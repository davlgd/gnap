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
//! protected operation only after this function returns `Ok(())`.
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
//! ) -> Result<(), AuthorizationError> {
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
//! }
//! ```

mod token;
mod trust;

pub use token::{AccessPolicy, Audience, AudiencePolicy, TokenInfo};
pub use trust::TrustedAs;

use gnap_client::{sign_request, HttpTransport};
use gnap_crypto::{
    proof::Signer,
    verify::{verify_request_with_policy, Expectations, NonceMemory, SignedRequest},
    Ps256Verifier,
};
use gnap_registry::KeyProofingMethod;
use gnap_types::{
    access::AccessItem,
    http::{HttpRequest, HttpResponse},
    rs::{IntrospectionRequest, IntrospectionResponse, ResourceServer, RsDiscovery},
    token::TokenValue,
};
use std::fmt;

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
        }
    }

    /// Authorizes the exact presented request using freshly introspected state.
    ///
    /// Required rights must be nonempty and each must occur exactly in the AS's
    /// response; this is not a generic semantic comparison of rights objects.
    /// The policy can only add a refusal and runs before nonce consumption.
    /// All successful calls read `clock` three times: before network work,
    /// before proof verification and after it. Unix seconds must not decrease.
    /// `iat` and exclusive `exp` are mandatory here; token time has no skew.
    /// Signatures allow 300 seconds of clock skew and require a nonempty nonce.
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
    ) -> Result<(), AuthorizationError> {
        if required_access.is_empty() {
            return Err(AuthorizationError::Denied);
        }
        let value = presented_token(request)?;
        let before = clock();
        let metadata: RsDiscovery =
            self.send(HttpRequest::new("GET", self.trusted.discovery_endpoint()))?;
        self.trusted.accepts(&metadata)?;
        let context = IntrospectionRequest {
            access_token: value,
            resource_server: self.identity.clone(),
            proof: Some(KeyProofingMethod::Httpsig),
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
            || key.proof.method() != &KeyProofingMethod::Httpsig
            || matches!(&key.proof, gnap_types::key::Proof::Detailed { params, .. } if !params.is_empty())
        {
            return Err(AuthorizationError::Unavailable);
        }
        let verifier = Ps256Verifier::from_public_jwk(
            key.jwk.as_ref().ok_or(AuthorizationError::Unavailable)?,
        )
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
        verify_request_with_policy(
            &SignedRequest {
                method: &request.method,
                target_uri: &request.url,
                headers: &request.headers,
                body: request.body.as_deref(),
            },
            &verifier,
            &Expectations {
                now: verification_time,
                max_clock_skew: 300,
                key_id: None,
            },
            self.nonces,
            &|params| params.nonce.as_ref().is_some_and(|nonce| !nonce.is_empty()),
        )
        .map_err(|_| AuthorizationError::Denied)?;
        info.check_time(verification_time, clock())
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
    let mut types = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    let mime = types.next().map(|(_, value)| value);
    if response.status != 200
        || response.body.len() > 8192
        || types.next().is_some()
        || !mime.is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(AuthorizationError::Unavailable);
    }
    serde_json::from_slice(&response.body).map_err(|_| AuthorizationError::Unavailable)
}
