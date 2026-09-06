//! A deliberately narrow Biscuit profile for proof-bound GNAP file access.
//!
//! The authority fixes the issuer, audience, complete PS256 public JWK and
//! rights. Holders may add only exact-resource and deadline checks. See the
//! crate README for the wire contract, resource bounds and deployment duties.

// Explicit internal visibility also satisfies the workspace's unreachable_pub lint.
#[allow(clippy::redundant_pub_crate)]
mod format;
#[allow(clippy::redundant_pub_crate)]
mod rights;

use biscuit_auth::{
    builder::{fact, int, string},
    AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair, PublicKey,
};
pub use format::{inspect, Inspection};
pub use gnap_crypto::ReceivedParams;
use gnap_crypto::{
    verify_request_with_policy, Expectations, NonceMemory, Ps256Verifier, SignedRequest,
};
use gnap_types::token::TokenValue;
pub use rights::{FileAction, FileRight};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, time::Duration};

/// The exact access type and authority profile identifier.
pub const PROFILE: &str = "gnap-biscuit-file-v1";

/// Failure classes intentionally do not include secret or untrusted token text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Malformed, oversized or unsupported profile structure.
    Profile,
    /// Unknown root, invalid chain or invalid public client key.
    Crypto,
    /// Proof, rights, time, attenuation or the live decision denied access.
    Denied,
    /// The required clock or live decision source is unavailable.
    Unavailable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Profile => "unsupported or malformed Biscuit file profile",
            Self::Crypto => "Biscuit or client key verification failed",
            Self::Denied => "file request was not authorized",
            Self::Unavailable => "live authorization context unavailable",
        })
    }
}
impl std::error::Error for Error {}

/// Root-signed file-token issuer. Keys are configured locally, never fetched.
pub struct Issuer {
    root: KeyPair,
    root_key_id: u32,
    grant_uri: String,
    audience: String,
}

impl Issuer {
    /// Configures the issuer and intended RS independently of client requests.
    ///
    /// # Errors
    /// Rejects invalid or oversized issuer/audience HTTP(S) URIs.
    pub fn new(
        root: KeyPair,
        root_key_id: u32,
        issuer: String,
        audience: String,
    ) -> Result<Self, Error> {
        rights::validate_uri(&issuer)?;
        rights::validate_uri(&audience)?;
        Ok(Self {
            root,
            root_key_id,
            grant_uri: issuer,
            audience,
        })
    }

    /// Issues 1–32 distinct exact rights bound to a complete public PS256 JWK.
    /// Times are Unix seconds, with `issued_at < expires_at <= i64::MAX`.
    ///
    /// # Errors
    /// Rejects invalid keys, times, duplicate rights or an oversized result.
    pub fn mint(
        &self,
        rights: &[FileRight],
        client_jwk: &Map<String, Value>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<TokenValue, Error> {
        Ps256Verifier::from_public_jwk(client_jwk).map_err(|_| Error::Crypto)?;
        if rights.is_empty()
            || rights.len() > 32
            || rights
                .iter()
                .enumerate()
                .any(|(i, right)| rights[..i].contains(right))
            || issued_at >= expires_at
        {
            return Err(Error::Profile);
        }
        let jwk = serde_json::to_string(client_jwk).map_err(|_| Error::Profile)?;
        let mut builder = Biscuit::builder().root_key_id(self.root_key_id);
        for (name, value) in [
            ("gnap_profile", PROFILE),
            ("gnap_issuer", self.grant_uri.as_str()),
            ("gnap_audience", self.audience.as_str()),
            ("gnap_jwk", jwk.as_str()),
            ("gnap_proof", "httpsig"),
        ] {
            builder = builder
                .fact(fact(name, &[string(value)]))
                .map_err(|_| Error::Profile)?;
        }
        for (name, value) in [("gnap_iat", issued_at), ("gnap_exp", expires_at)] {
            builder = builder
                .fact(fact(name, &[int(seconds(value)?)]))
                .map_err(|_| Error::Profile)?;
        }
        for right in rights {
            builder = builder
                .fact(fact(
                    "right",
                    &[string(right.resource()), string(right.action().as_str())],
                ))
                .map_err(|_| Error::Profile)?;
        }
        encode(&builder.build(&self.root).map_err(|_| Error::Crypto)?)
    }
}

/// A live per-request decision, including revocation and central replay checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveDecision {
    /// Live state and any required one-use reservation allow this request.
    Allowed,
    /// Access is denied, for example by revocation or a refused nonce reservation.
    Denied,
    /// The live decision could not be established; access must fail closed.
    Unavailable,
}

/// Locally configured expected context, not values inferred from a token.
pub struct RequestContext<'a> {
    /// Expected issuer grant endpoint.
    pub issuer: &'a str,
    /// Expected resource-server audience.
    pub audience: &'a str,
    /// Accepted HTTP signature timestamp skew in seconds.
    pub max_clock_skew: u64,
}

/// A structurally checked, cryptographically verified token; not an authorization.
pub struct VerifiedToken {
    token: Biscuit,
    value: TokenValue,
    claims: format::Claims,
    verifier: Ps256Verifier,
}

impl VerifiedToken {
    /// Checks bounded structure before verifying the complete signature chain.
    ///
    /// # Errors
    /// Rejects unsupported profiles, invalid chains/JWKs and unknown root IDs.
    pub fn from_token(value: &TokenValue, roots: &BTreeMap<u32, PublicKey>) -> Result<Self, Error> {
        let parsed = format::parse(value)?;
        let root = roots.get(&parsed.info.root_key_id).ok_or(Error::Crypto)?;
        let token = Biscuit::from(parsed.bytes, *root).map_err(|_| Error::Crypto)?;
        let verifier =
            Ps256Verifier::from_public_jwk(&parsed.claims.jwk).map_err(|_| Error::Crypto)?;
        Ok(Self {
            token,
            value: value.clone(),
            claims: parsed.claims,
            verifier,
        })
    }

    /// The exact encoded token whose value must be covered by the request proof.
    #[must_use]
    pub const fn value(&self) -> &TokenValue {
        &self.value
    }

    /// Native authority and block signatures, in ancestry order, for revocation.
    #[must_use]
    pub fn revocation_identifiers(&self) -> Vec<Vec<u8>> {
        self.token.revocation_identifiers()
    }

    /// Adds only restrictive checks, preserving the authority and client key.
    /// This is local attenuation, not RFC 9767 downstream token derivation.
    ///
    /// # Errors
    /// Rejects empty restrictions, malformed URIs, invalid times or size limits.
    pub fn attenuate(
        &self,
        resource: Option<&str>,
        deadline: Option<u64>,
    ) -> Result<TokenValue, Error> {
        if resource.is_none() && deadline.is_none() {
            return Err(Error::Profile);
        }
        let mut block = BlockBuilder::new();
        if let Some(resource) = resource {
            rights::validate_uri(resource)?;
            block = block
                .check(biscuit_auth::macros::check!(
                    "check if resource({resource})"
                ))
                .map_err(|_| Error::Profile)?;
        }
        if let Some(deadline) = deadline {
            let deadline = seconds(deadline)?;
            block = block
                .check(biscuit_auth::macros::check!(
                    "check if time($now), $now < {deadline}"
                ))
                .map_err(|_| Error::Profile)?;
        }
        encode(&self.token.append(block).map_err(|_| Error::Crypto)?)
    }

    /// Verifies the actual request, evaluates its rights and all carried checks,
    /// then requests a live decision. No positive decision is cached.
    ///
    /// The callback receives native block identifiers and the authenticated
    /// parameters of the signature actually accepted by the verifier. It can
    /// consult revocation state and atomically reserve that signature's nonce
    /// centrally, without receiving the access token. It runs only after proof
    /// and Datalog checks succeed. Do not reconstruct its parameters from the
    /// first signature header: another candidate may have been accepted.
    ///
    /// The clock is read before proof verification and again after evaluation
    /// and the live callback. Failure or backwards movement denies access. The
    /// final time is checked against the earliest carried deadline and the
    /// signature timestamp, without running Datalog again. The nonce memory
    /// must be atomic and retained/scoped as documented by `gnap_crypto`.
    /// This profile requires a nonce, even though GNAP allows omitting it. The
    /// local nonce memory remains an initial filter; restart-safe replay
    /// protection requires persistent/shared state or the live callback's
    /// central one-use decision. Unknown live state must not return `Allowed`.
    ///
    /// # Errors
    /// Fails closed for every malformed, unproven, expired, revoked or unavailable
    /// request. A valid proof's nonce may be consumed even if authorization fails.
    pub fn authorize(
        &self,
        request: &SignedRequest<'_>,
        context: &RequestContext<'_>,
        nonces: &dyn NonceMemory,
        clock: &mut impl FnMut() -> Option<u64>,
        live: &mut impl FnMut(&[Vec<u8>], &ReceivedParams) -> LiveDecision,
    ) -> Result<(), Error> {
        let mut authorization = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
        let (_, credentials) = authorization.next().ok_or(Error::Denied)?;
        let (scheme, value) = credentials
            .trim_matches([' ', '\t'])
            .split_once(' ')
            .ok_or(Error::Denied)?;
        if !scheme.eq_ignore_ascii_case("GNAP")
            || value.trim_start_matches(' ') != self.value.as_str()
            || authorization.next().is_some()
            || context.issuer != self.claims.issuer
            || context.audience != self.claims.audience
        {
            return Err(Error::Denied);
        }
        let now = clock().ok_or(Error::Unavailable)?;
        self.check_time(now)?;
        let accepted = verify_request_with_policy(
            request,
            &self.verifier,
            &Expectations {
                now,
                max_clock_skew: context.max_clock_skew,
                key_id: None,
            },
            nonces,
            &|params| params.nonce.is_some(),
        )
        .map_err(|_| Error::Denied)?;
        self.evaluate(request, now)?;
        match live(&self.revocation_identifiers(), &accepted.params) {
            LiveDecision::Allowed => {}
            LiveDecision::Denied => return Err(Error::Denied),
            LiveDecision::Unavailable => return Err(Error::Unavailable),
        }
        let final_now = clock().ok_or(Error::Unavailable)?;
        let created = accepted.params.created.ok_or(Error::Denied)?;
        if final_now < now || final_now.abs_diff(created) > context.max_clock_skew {
            return Err(Error::Denied);
        }
        self.check_time(final_now)
    }

    const fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.claims.issued_at
            || now >= self.claims.expires_at
            || now >= self.claims.deadline
        {
            return Err(Error::Denied);
        }
        Ok(())
    }

    fn evaluate(&self, request: &SignedRequest<'_>, now: u64) -> Result<(), Error> {
        let action = match request.method {
            "GET" => "read",
            "PUT" => "write",
            _ => return Err(Error::Denied),
        };
        let mut authorizer = AuthorizerBuilder::new()
            .set_limits(biscuit_auth::AuthorizerLimits {
                max_facts: 128,
                max_iterations: 10,
                max_time: Duration::from_millis(20),
            })
            .fact(fact("resource", &[string(request.target_uri)]))
            .map_err(|_| Error::Denied)?
            .fact(fact("operation", &[string(action)]))
            .map_err(|_| Error::Denied)?
            .fact(fact("time", &[int(seconds(now)?)]))
            .map_err(|_| Error::Denied)?
            .policy("allow if resource($r), operation($o), right($r, $o) trusting authority")
            .map_err(|_| Error::Denied)?
            .build(&self.token)
            .map_err(|_| Error::Denied)?;
        authorizer.authorize().map_err(|_| Error::Denied)?;
        Ok(())
    }
}

fn seconds(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::Profile)
}

fn encode(token: &Biscuit) -> Result<TokenValue, Error> {
    let value = TokenValue::new(token.to_base64().map_err(|_| Error::Crypto)?)
        .map_err(|_| Error::Profile)?;
    inspect(&value)?;
    Ok(value)
}
