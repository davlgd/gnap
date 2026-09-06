//! The opaque-token RS-facing API — RFC 9767 §§3.1–3.3 and §3.5.
//!
//! Authentication uses a pre-registered RS key and a separate nonce store.
//! The client's resource request is not forwarded here: its proof is verified
//! by the RS using the client key returned in the introspection response.
//! This module does not introspect Biscuit, register resources, derive tokens,
//! issue RS management credentials, or implement trust-on-first-use.

use crate::{GrantSelector, NonceStore, Storage, TokenRecord, MAX_CLOCK_SKEW};
use gnap_crypto::{
    ps256::Ps256Verifier,
    verify::{verify_request_with_policy, Expectations, SignedRequest},
};
use gnap_registry::{AccessTokenFlag, KeyProofingMethod, RsErrorCode};
use gnap_types::{
    access::AccessItem,
    http::{HttpRequest, HttpResponse},
    key::{Key, KeyObject},
    message::DiscoveryError,
    polymorphic::MethodOrObject,
    rs::{
        ActiveIntrospection, IntrospectionRequest, IntrospectionResponse, ResourceServer,
        RsDiscovery, RsError, RsErrorResponse,
    },
};

/// Maximum introspection JSON content accepted before decoding or cryptography.
pub const MAX_INTROSPECTION_BYTES: usize = 64 * 1024;

/// Resolves only pre-registered resource servers, independently of client keys.
pub trait ResourceServerResolver {
    /// Returns the registered RS public key, or refuses an unknown identity.
    ///
    /// The SDK verifies a PS256 JWK and any key supplied by value against this
    /// result. Accepting arbitrary presented keys here would bypass registration.
    fn resolve(&self, resource_server: &ResourceServer) -> Option<KeyObject>;
}

/// The deployment's contextual decision about an authenticated RS and token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntrospectionDecision {
    /// Unknown, inappropriate, or impossible to determine in this context.
    Inactive,
    /// This RS is not permitted to introspect for the requested access (§3.5).
    InvalidAccess,
    /// Valid for this RS and every understood minimum access requirement.
    Active {
        /// Disclosable rights, each an exact description from the stored token.
        access: Vec<AccessItem>,
        /// The client's public key, not the RS authentication key.
        ///
        /// Required for bound tokens. Resolving a client/key reference is a
        /// trusted deployment decision; known by-value bindings cannot change.
        key: Option<KeyObject>,
    },
}

/// Evaluates audience, resource rights and any application-specific conditions.
pub trait IntrospectionPolicy {
    /// Called only after authenticating the RS and checking token liveness.
    ///
    /// Must understand every supplied minimum access description, refuse
    /// unknown dimensions, and establish suitability for this RS. `Active`
    /// with empty disclosed access is permitted, but is not an exemption from
    /// checking requested minimum access. Exact output-description membership
    /// is a conservative SDK profile, not a generic GNAP rights comparison.
    /// The key in `Active` resolves the stored token/client binding, never the
    /// requesting RS's identity. For a client/key reference, use the same trusted
    /// resolution that the AS uses to verify that client's proof; an arbitrary
    /// key selected by the RS or merely sharing a key identifier is not a binding.
    /// Do not mutate grants or cache positive results.
    fn evaluate(
        &self,
        resource_server: &ResourceServer,
        token: &TokenRecord,
        access: Option<&[AccessItem]>,
    ) -> IntrospectionDecision;
}

/// Borrowed discovery/introspection handler for an opaque-encoder AS.
///
/// Construct with [`crate::AuthorizationServer::resource_server_api`]. No
/// positive result is cached. Storage is reread after policy/key processing;
/// the same grant revision must still exist at that decision point. This cannot
/// guarantee delivery before a subsequent concurrent revocation. The caller's
/// `now` is one trusted Unix-seconds sample for this synchronous operation;
/// the RS must check expiration again after network and proof verification.
pub struct ResourceServerApi<'a, R, P, S> {
    keys: &'a R,
    policy: &'a P,
    storage: &'a S,
    nonces: &'a dyn NonceStore,
    discovery: RsDiscovery,
    discovery_url: String,
    endpoint: &'a str,
    development: bool,
}

impl<'a, R: ResourceServerResolver, P: IntrospectionPolicy, S: Storage>
    ResourceServerApi<'a, R, P, S>
{
    pub(crate) fn new(
        keys: &'a R,
        policy: &'a P,
        storage: &'a S,
        nonces: &'a dyn NonceStore,
        grant: &str,
        endpoint: &'a str,
        development: bool,
    ) -> Result<Self, DiscoveryError> {
        let discovery = RsDiscovery {
            grant_request_endpoint: grant.into(),
            introspection_endpoint: Some(endpoint.into()),
            token_formats_supported: None,
            resource_registration_endpoint: None,
            key_proofs_supported: Some(vec![KeyProofingMethod::Httpsig]),
            extra: serde_json::Map::new(),
        };
        let discovery_url = if development {
            discovery.discovery_url_for_local_development()?
        } else {
            discovery.discovery_url()?
        };
        Ok(Self {
            keys,
            policy,
            storage,
            nonces,
            discovery,
            discovery_url,
            endpoint,
            development,
        })
    }

    /// Routes exact discovery GET and introspection POST URLs.
    ///
    /// Every RS API error has status 400 and only an `error` field (§3.5).
    /// Unknown URLs are outside this API and receive 404. An unknown token
    /// value, unavailable store or changed revision returns only `active: false`;
    /// that is not a claim of intrinsic invalidity of the presented value.
    #[must_use]
    pub fn handle(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        if request.url == self.discovery_url {
            if !request.method.eq_ignore_ascii_case("GET") {
                return rs_error(RsErrorCode::InvalidRequest);
            }
            let mut response = json_response(200, &self.discovery);
            if self.development {
                response.headers.push((
                    "GNAP-Development-Only".into(),
                    "insecure-loopback-discovery".into(),
                ));
            }
            return response;
        }
        if request.url != self.endpoint {
            return HttpResponse {
                status: 404,
                headers: vec![("Cache-Control".into(), "no-store".into())],
                body: Vec::new(),
            };
        }
        self.introspect(request, now)
    }

    fn introspect(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        if !request.method.eq_ignore_ascii_case("POST")
            || request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            return rs_error(RsErrorCode::InvalidRequest);
        }
        let content_types: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .collect();
        if content_types.len() != 1
            || !content_types[0]
                .1
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
        {
            return rs_error(RsErrorCode::InvalidRequest);
        }
        let Some(bytes) = request
            .body
            .as_deref()
            .filter(|body| body.len() <= MAX_INTROSPECTION_BYTES)
        else {
            return rs_error(RsErrorCode::InvalidRequest);
        };
        let Ok(body) = serde_json::from_slice::<IntrospectionRequest>(bytes) else {
            return rs_error(RsErrorCode::InvalidRequest);
        };
        if !self.authenticate(request, &body.resource_server, now) {
            return rs_error(RsErrorCode::InvalidResourceServer);
        }
        // RFC 9767 §3.3: "the AS MUST take all provided parameters into account
        // when evaluating if the token is active."
        if !body.extra.is_empty()
            || body
                .resource_server
                .as_value()
                .is_some_and(|rs| !rs.extra.is_empty())
        {
            return inactive();
        }
        // RFC 9767 §3.3: "if the AS is unable to make a determination (such as
        // the token is not found), the value is set to false and other fields
        // are omitted." A storage failure is indeterminate, not intrinsic
        // token invalidity. Deployment storage adapters should record failures
        // without logging credentials; they are not revealed to the RS here.
        self.inspect_token(&body, now)
    }

    fn inspect_token(&self, body: &IntrospectionRequest, now: u64) -> HttpResponse {
        let Ok(Some(snapshot)) = self
            .storage
            .lookup(GrantSelector::AccessToken(body.access_token.as_str()))
        else {
            return inactive();
        };
        if snapshot.aggregate.revoked {
            return inactive();
        }
        let Some(token) = snapshot
            .aggregate
            .tokens
            .values()
            .find(|token| token.token.value == body.access_token)
        else {
            return inactive();
        };
        if !token.is_valid_at(now) || token.identifier.is_some() || !token.token.extra.is_empty() {
            return inactive();
        }
        let (access, key) =
            match self
                .policy
                .evaluate(&body.resource_server, token, body.access.as_deref())
            {
                IntrospectionDecision::Inactive => return inactive(),
                IntrospectionDecision::InvalidAccess => {
                    return rs_error(RsErrorCode::InvalidAccess)
                }
                IntrospectionDecision::Active { access, key } => (access, key),
            };
        if !access.iter().all(|right| {
            token
                .token
                .access
                .as_ref()
                .is_some_and(|rights| rights.contains(right))
        }) || !binding_matches(token, key.as_ref(), body.proof.as_ref())
        {
            return inactive();
        }
        let response = IntrospectionResponse::Active(ActiveIntrospection {
            access,
            iss: self.discovery.grant_request_endpoint.clone(),
            key: key.map(|key| Key::ByValue(Box::new(key))),
            flags: (!token.token.flags.is_empty()).then(|| token.token.flags.clone()),
            exp: token.expires_at(),
            iat: Some(token.issued_at),
            extra: serde_json::Map::new(),
        });
        let Ok(Some(current)) = self.storage.lookup(GrantSelector::Id(snapshot.id)) else {
            return inactive();
        };
        if current.revision != snapshot.revision || current.aggregate.revoked {
            return inactive();
        }
        json_response(200, &response)
    }

    fn authenticate(&self, request: &HttpRequest, identity: &ResourceServer, now: u64) -> bool {
        let Some(key) = self.keys.resolve(identity) else {
            return false;
        };
        let Some(verifier) = public_verifier(&key) else {
            return false;
        };
        if let Some(presented) = identity.as_value().and_then(|rs| rs.key.as_value()) {
            if presented != &key {
                return false;
            }
        }
        let signed = SignedRequest {
            method: &request.method,
            target_uri: &request.url,
            headers: &request.headers,
            body: request.body.as_deref(),
        };
        let remember = |nonce: &str, at: u64| self.nonces.remember_nonce(nonce, at);
        verify_request_with_policy(
            &signed,
            &verifier,
            &Expectations {
                now,
                max_clock_skew: MAX_CLOCK_SKEW,
                key_id: key.jwk_key_id(),
            },
            &remember,
            &|params| params.nonce.as_ref().is_some_and(|nonce| !nonce.is_empty()),
        )
        .is_ok()
    }
}

fn public_verifier(key: &KeyObject) -> Option<Ps256Verifier> {
    key.validate().ok()?;
    if key.proof.method() != &KeyProofingMethod::Httpsig {
        return None;
    }
    if matches!(&key.proof, MethodOrObject::Detailed { params, .. } if !params.is_empty()) {
        return None;
    }
    Ps256Verifier::from_public_jwk(key.jwk.as_ref()?).ok()
}

fn binding_matches(
    token: &TokenRecord,
    key: Option<&KeyObject>,
    proof: Option<&KeyProofingMethod>,
) -> bool {
    if token.token.flags.contains(&AccessTokenFlag::Bearer) {
        return key.is_none() && proof.is_none() && token.token.key.is_none();
    }
    let Some(key) = key else {
        return false;
    };
    if public_verifier(key).is_none() || proof.is_some_and(|proof| proof != key.proof.method()) {
        return false;
    }
    let known = token.token.key.as_ref().map_or_else(
        || {
            token
                .client
                .as_value()
                .and_then(|client| client.key.as_value())
        },
        Key::as_value,
    );
    known.is_none_or(|known| known == key)
}

fn inactive() -> HttpResponse {
    json_response(200, &IntrospectionResponse::Inactive)
}

fn rs_error(code: RsErrorCode) -> HttpResponse {
    // RFC 9767 §3.5: "the AS responds to the RS with HTTP status code 400
    // (Bad Request) and a JSON object consisting of a single error field".
    json_response(
        400,
        &RsErrorResponse {
            error: RsError {
                code,
                description: None,
            },
        },
    )
}

fn json_response(status: u16, value: &impl serde::Serialize) -> HttpResponse {
    let (status, body) = serde_json::to_vec(value).map_or_else(
        |_| (400, br#"{"error":"invalid_request"}"#.to_vec()),
        |body| (status, body),
    );
    HttpResponse {
        status,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body,
    }
}
