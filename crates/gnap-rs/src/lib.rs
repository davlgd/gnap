//! Resource-request authorization for an explicit opaque-token GNAP profile.
//!
//! [`Authorizer`] discovers a pinned AS, introspects with the RS's own key,
//! then verifies the actual resource request with the returned client key.
//! It needs no AS store or HTTP runtime. Supply a [`HttpTransport`], replay
//! memory, trusted endpoints and an application [`AccessPolicy`].
//!
//! A successful call makes two HTTP exchanges and retains no positive cache.
//! Transport adapters must authenticate HTTPS, preserve signed bytes, refuse
//! redirects and unapproved destinations, and bound response buffering and time.
//! The SDK additionally checks an 8,192-byte JSON response limit after receipt.
//! Blocking adapters belong in a bounded worker when used from async servers.
//!
//! This is not a generic token-format validator. Biscuit's local validation and
//! attenuation remain in `gnap-biscuit`; they do not require introspection.
//! There is no bearer support, dynamic AS trust, RS registration or derivation
//! client here. Limits and strict extensions are SDK choices, not extra RFC MUSTs.
//!
//! # Protecting a resource
//!
//! This function takes a deployment's transport, RS key and replay memory; it
//! does not construct an AS or copy a token store. The application performs its
//! protected operation only after this function returns an [`Authorized`], on
//! the content it carries: for a `jws` proof, the JWS payload, not the body.
//!
//! ```
//! use gnap_client::HttpTransport;
//! use gnap_crypto::{proof::Signer, verify::NonceMemory};
//! use gnap_rs::{Authorizer, AuthorizationError, AudiencePolicy, TokenInfo, TrustedAs};
//! use gnap_types::{access::AccessItem, http::HttpRequest, rs::ResourceServer};
//!
//! fn authorize_read<T: HttpTransport>(
//!     request: &HttpRequest,
//!     transport: &T,
//!     rs_signer: &dyn Signer,
//!     replay: &dyn NonceMemory,
//!     now: impl Fn() -> u64,
//! ) -> Result<Vec<u8>, AuthorizationError> {
//!     let trusted = TrustedAs::new(
//!         "https://as.example/gnap", "https://as.example/introspect",
//!     ).map_err(|_| AuthorizationError::Unavailable)?;
//!     let identity = ResourceServer::ByReference("registered-files-rs".into());
//!     let required = [AccessItem::Reference("files:read".into())];
//!     let policy = |token: &TokenInfo<'_>| {
//!         if token.subject == Some("approved-owner") { Ok(()) }
//!         else { Err(AuthorizationError::Denied) }
//!     };
//!     Authorizer::new(&trusted, &identity, transport, rs_signer, replay,
//!         &AudiencePolicy::IntrospectionContext)
//!         .authorize(request, &required, &policy, now)
//!         .map(gnap_rs::Authorized::into_content)
//! }
//! ```

mod token;
mod trust;

pub use token::{AccessPolicy, Audience, AudiencePolicy, TokenInfo};
pub use trust::TrustedAs;

use gnap_client::{HttpTransport, sign_request};
use gnap_crypto::{
    PublicKey,
    jws::{DETACHED_JWS_HEADER, JwsKey, JwsMethod, JwsReplayMemory, verify_jws_request},
    proof::Signer,
    verify::{Expectations, NonceMemory, SignedRequest, verify_request_with_policy},
};
use gnap_registry::KeyProofingMethod;
use gnap_types::{
    access::AccessItem,
    http::{HttpRequest, HttpResponse},
    rs::{IntrospectionRequest, IntrospectionResponse, ResourceServer, RsDiscovery},
    token::TokenValue,
};
use std::fmt;

/// Largest discovery or introspection response, in bytes, checked after receipt.
pub const MAX_RESPONSE_BYTES: usize = 8192;

/// Clock difference, in seconds, that the client's request signature may show.
pub const MAX_CLOCK_SKEW: u64 = 300;

/// Redacted authorization outcomes; neither variant exposes request credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    /// The request, token, proof or application policy did not authorize access.
    /// An inactive introspection can also mean the AS could not decide validity.
    Denied,
    /// Transport, configuration or an unusable AS response prevented a decision.
    Unavailable,
}
impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "resource request denied",
            Self::Unavailable => "resource authorization unavailable",
        })
    }
}
impl std::error::Error for AuthorizationError {}

/// Borrows the trust, transport, RS identity and proof-replay boundary.
///
/// The RS signer must correspond to its preregistered [`ResourceServer`]. The
/// client key returned by introspection is a different role, never inferred
/// from that signer or from an RS reference. Replay memory must reserve nonces
/// atomically for the full signature window, including across replicas/restarts
/// when those deployment guarantees are required. Keep the RS-to-AS proof
/// channel's replay memory separate from this incoming-resource channel.
pub struct Authorizer<'a, T: HttpTransport + ?Sized> {
    trusted: &'a TrustedAs,
    identity: &'a ResourceServer,
    transport: &'a T,
    signer: &'a dyn Signer,
    nonces: &'a dyn NonceMemory,
    audience: &'a AudiencePolicy,
    jose: Option<&'a dyn JwsReplayMemory>,
}

/// An authorized resource request, and the content the application processes.
///
/// The content is the one the proof authenticates: the request body for
/// `httpsig` and `jwsd`, and the JWS payload for `jws`, whose body is the
/// compact JWS. It is empty when the request has none.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Authorized {
    content: Vec<u8>,
}

impl Authorized {
    /// The authenticated request content.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// The authenticated request content, owned.
    #[must_use]
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }
}

impl<'a, T: HttpTransport + ?Sized> Authorizer<'a, T> {
    /// Assembles a verifier without performing network calls or changing state.
    #[must_use]
    pub const fn new(
        trusted: &'a TrustedAs,
        identity: &'a ResourceServer,
        transport: &'a T,
        signer: &'a dyn Signer,
        nonces: &'a dyn NonceMemory,
        audience: &'a AudiencePolicy,
    ) -> Self {
        Self {
            trusted,
            identity,
            transport,
            signer,
            nonces,
            audience,
            jose: None,
        }
    }

    /// Accepts tokens bound to a `jws` or `jwsd` key (RFC 9635 §7.3.3,
    /// §7.3.4), whose proofs `replay` reserves. Without it, such a token is
    /// refused as unavailable. `replay` is the JOSE counterpart of the nonce
    /// memory, and like it shared by the replicas that serve one resource.
    #[must_use]
    pub const fn with_jose_proofs(mut self, replay: &'a dyn JwsReplayMemory) -> Self {
        self.jose = Some(replay);
        self
    }

    /// Authorizes the exact presented request using freshly introspected state.
    ///
    /// Required rights must be nonempty and each must occur exactly in the AS's
    /// response; this is not a generic semantic comparison of rights objects.
    /// The policy can only add a refusal and runs before the proof is spent.
    /// All successful calls read `clock` three times: before network work,
    /// before proof verification and after it. Unix seconds must not decrease.
    /// `iat` and exclusive `exp` are mandatory here; token time has no skew.
    /// Proofs allow 300 seconds of clock skew, and `httpsig` signatures require
    /// a nonempty nonce. The proof method is the one of the key introspection
    /// returns, never one the request suggests, and a request carrying the
    /// envelope of another method is refused.
    ///
    /// There is no automatic retry. A nonce may already be consumed when a late
    /// clock check refuses the request. A revocation can occur after the AS's
    /// introspection decision; this method cannot make network delivery atomic
    /// with remote revocation and never caches an authorization for another call.
    /// # Errors
    /// Returns a redacted refusal or unavailability; callers choose HTTP mapping.
    pub fn authorize(
        &self,
        request: &HttpRequest,
        required_access: &[AccessItem],
        policy: &(impl AccessPolicy + ?Sized),
        clock: impl Fn() -> u64,
    ) -> Result<Authorized, AuthorizationError> {
        if required_access.is_empty() {
            return Err(AuthorizationError::Denied);
        }
        let value = presented_token(request)?;
        let before = clock();
        let metadata: RsDiscovery =
            self.send(HttpRequest::new("GET", self.trusted.discovery_endpoint()))?;
        self.trusted.accepts(&metadata)?;
        // RFC 9767 §3.3 RECOMMENDS naming the proof method. `httpsig` is told
        // from its fields; `jws` and `jwsd` aren't told apart without reading
        // an unverified header, so the method is left to the introspected key.
        let signed_with_httpsig = request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("signature-input"));
        let context = IntrospectionRequest {
            access_token: value,
            resource_server: self.identity.clone(),
            proof: signed_with_httpsig.then_some(KeyProofingMethod::Httpsig),
            access: Some(required_access.to_vec()),
            extra: serde_json::Map::new(),
        };
        let body = serde_json::to_vec(&context).map_err(|_| AuthorizationError::Unavailable)?;
        let outgoing = sign_request(
            HttpRequest::new("POST", self.trusted.introspection_endpoint()).json_body(body),
            self.signer,
            None,
            before,
        )
        .map_err(|_| AuthorizationError::Unavailable)?;
        let response: IntrospectionResponse = self.send(outgoing)?;
        let IntrospectionResponse::Active(active) = response else {
            return Err(AuthorizationError::Denied);
        };
        let info = TokenInfo::from_active(&active)?;
        self.audience.check(info.audience.as_ref())?;
        if active.iss != self.trusted.grant_endpoint()
            || active.flags.as_ref().is_some_and(|flags| !flags.is_empty())
        {
            return Err(AuthorizationError::Unavailable);
        }
        let key = active
            .key
            .as_ref()
            .and_then(gnap_types::key::Key::as_value)
            .ok_or(AuthorizationError::Unavailable)?;
        if key.validate().is_err()
            || matches!(&key.proof, gnap_types::key::Proof::Detailed { params, .. } if !params.is_empty())
        {
            return Err(AuthorizationError::Unavailable);
        }
        let jwk = key.jwk.as_ref().ok_or(AuthorizationError::Unavailable)?;
        let proof = match key.proof.method() {
            KeyProofingMethod::Httpsig => Proof::Httpsig,
            KeyProofingMethod::Jws => Proof::Jose(JwsMethod::Jws),
            KeyProofingMethod::Jwsd => Proof::Jose(JwsMethod::Jwsd),
            _ => return Err(AuthorizationError::Unavailable),
        };
        let verifier = match proof {
            Proof::Httpsig => PublicKey::for_httpsig(jwk),
            Proof::Jose(_) if self.jose.is_some() => PublicKey::for_jws(jwk),
            Proof::Jose(_) => return Err(AuthorizationError::Unavailable),
        }
        .map_err(|_| AuthorizationError::Unavailable)?;
        policy.validate(&info)?;
        if !required_access
            .iter()
            .all(|right| info.access.contains(right))
        {
            return Err(AuthorizationError::Denied);
        }
        let verification_time = clock();
        info.check_time(before, verification_time)?;
        let authenticated = self.verify_proof(proof, &verifier, request, verification_time)?;
        info.check_time(verification_time, clock())?;
        Ok(Authorized {
            content: authenticated,
        })
    }

    /// Verifies the request's proof with the introspected key, by its method,
    /// and returns the content it authenticates.
    fn verify_proof(
        &self,
        proof: Proof,
        verifier: &PublicKey,
        request: &HttpRequest,
        now: u64,
    ) -> Result<Vec<u8>, AuthorizationError> {
        let signed = SignedRequest {
            method: &request.method,
            target_uri: &request.url,
            headers: &request.headers,
            body: request.body.as_deref(),
        };
        match (proof, self.jose) {
            (Proof::Httpsig, _) => {
                // The JOSE verifier refuses an HTTP signature next to its
                // proof; this is the other direction.
                if request
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(DETACHED_JWS_HEADER))
                {
                    return Err(AuthorizationError::Denied);
                }
                verify_request_with_policy(
                    &signed,
                    verifier,
                    &Expectations {
                        now,
                        max_clock_skew: MAX_CLOCK_SKEW,
                        key_id: None,
                    },
                    self.nonces,
                    &|params| params.nonce.as_ref().is_some_and(|nonce| !nonce.is_empty()),
                )
                .map_err(|_| AuthorizationError::Denied)?;
                Ok(request.body.clone().unwrap_or_default())
            }
            (Proof::Jose(method), Some(replay)) => verify_jws_request(
                method,
                &signed,
                &JwsKey::for_public_key(verifier, now, MAX_CLOCK_SKEW),
                replay,
            )
            .map(|accepted| accepted.content)
            .map_err(|_| AuthorizationError::Denied),
            (Proof::Jose(_), None) => Err(AuthorizationError::Unavailable),
        }
    }

    fn send<D: serde::de::DeserializeOwned>(
        &self,
        request: HttpRequest,
    ) -> Result<D, AuthorizationError> {
        let response = self
            .transport
            .send(request)
            .map_err(|_| AuthorizationError::Unavailable)?;
        decode(&response)
    }
}

/// The proof method of the introspected key.
#[derive(Clone, Copy)]
enum Proof {
    Httpsig,
    Jose(JwsMethod),
}

fn presented_token(request: &HttpRequest) -> Result<TokenValue, AuthorizationError> {
    let mut headers = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    let (_, value) = headers.next().ok_or(AuthorizationError::Denied)?;
    if headers.next().is_some() {
        return Err(AuthorizationError::Denied);
    }
    let (scheme, value) = value.split_once(' ').ok_or(AuthorizationError::Denied)?;
    if !scheme.eq_ignore_ascii_case("GNAP") {
        return Err(AuthorizationError::Denied);
    }
    TokenValue::new(value.trim_start_matches(' ')).map_err(|_| AuthorizationError::Denied)
}

fn decode<D: serde::de::DeserializeOwned>(
    response: &HttpResponse,
) -> Result<D, AuthorizationError> {
    if response.status != 200
        || response.body.len() > MAX_RESPONSE_BYTES
        || !response.has_json_content_type()
    {
        return Err(AuthorizationError::Unavailable);
    }
    serde_json::from_slice(&response.body).map_err(|_| AuthorizationError::Unavailable)
}
