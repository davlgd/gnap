//! The authorization server, free of any HTTP framework.
//!
//! Takes a described HTTP request and returns a described HTTP response. What
//! carries those bytes — hyper, axum, a test harness, a Unix socket — is the
//! caller's business. The same seam that lets `gnap-client` be tested without a
//! network lets a client and a server be wired straight together.

mod continuation;
mod derivation;
mod grant;
mod interaction;
mod issuance;
mod key_rotation;
mod management;
mod responses;
mod tokens;

use continuation::modifies;

use grant::{check_presented_key, classify, presented_key, supported_finish};

use management::gnap_token;
use responses::{
    error, method_not_allowed, misconfigured, no_content, not_found, ok, require_json_content,
    storage_failure,
};

use crate::encoding::{EncodedToken, OpaqueTokenEncoder, TokenEncoder};
use crate::nonce::Nonces;
use crate::policy::{KeyResolver, Policy, ReleasedSubject, SubjectGround};
use crate::storage::{
    GrantAggregate, GrantSnapshot, RotationNonceStore, Storage, StoreError, TokenRecord,
    UserCodeStore,
};
use gnap_core::State;
use gnap_crypto::verify::{verify_request, Expectations, SignedRequest};
use gnap_registry::ErrorCode;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::message::{AsDiscovery, Continue, GrantRequest, GrantResponse};
use gnap_types::token::{AccessToken, AccessTokenResponse, BoundToken, TokenManage, TokenValue};
use std::fmt;

/// How far a signature's `created` timestamp may sit from the current time.
///
/// §7.3.1 asks the verifier to ensure it is "sufficiently close to the current
/// time given expected network delay and clock skew", without naming a figure.
/// Five minutes is the usual choice, and it matches the window §7.3.1 suggests
/// for nonce uniqueness.
pub const MAX_CLOCK_SKEW: u64 = 300;

/// How long an interaction the AS starts stays usable, in seconds.
///
/// §4-M04: the AS "MUST handle any interact request as a one-time-use mechanism
/// and SHOULD apply suitable timeouts to any interaction start methods
/// provided". §4.1-M02 turns the timeout into a MUST once it has passed: the AS
/// "MUST reject attempts to use the interaction start modes".
///
/// Ten minutes is long enough for someone to read a consent screen and short
/// enough that an interaction URI left in a browser history is not a standing
/// invitation. The value travels to the client as `interact.expires_in` (§3.3),
/// so nobody has to guess it.
pub const INTERACTION_LIFETIME: u64 = 600;

/// Largest body, in bytes, that the derivation and key-rotation handlers parse.
///
/// An implementation bound, not a GNAP message limit. The ordinary grant
/// handler leaves the body size to the HTTP adapter, which must bound it.
pub const MAX_GRANT_BODY_BYTES: usize = 64 * 1024;

/// Where the AS answers.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The grant endpoint, which identifies the AS (§1.2).
    pub grant: String,
    /// The continuation endpoint (§3.1).
    pub continuation: String,
    /// The base the AS builds interaction URIs from (§3.3.1).
    pub interaction: String,
    /// The base the AS builds token management URIs from (§3.2.1, §6).
    pub token_management: String,
}

/// What the AS has to do to signal that interaction is complete (§4.2).
///
/// Returned by [`AuthorizationServer::complete_interaction`]. Carrying it out
/// belongs to the deployment: the AS core describes the call, the HTTP adapter
/// makes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    /// §4.2.1 — direct the RO's browser to this URI.
    ///
    /// The hash and the interaction reference are already in its query. See
    /// §11.19 on which redirect status code to use for a URI that carries
    /// credentials.
    Redirect {
        /// The client's redirect URI, with the callback parameters added.
        uri: String,
    },

    /// §4.2.2 — POST this JSON body to the client's callback URI.
    ///
    /// The URI comes from the client, so whoever performs this call MUST guard
    /// against SSRF as §11.34 describes.
    Push {
        /// The client's callback URI.
        uri: String,
        /// The JSON body: the hash and the interaction reference.
        body: Vec<u8>,
    },

    /// §4.2 — no finish method was requested, so the AS "SHOULD instruct the
    /// RO to return to the client instance", which is polling (§5.2).
    SendTheUserBack,
}

/// Why the AS cannot signal the end of an interaction (§4.2).
///
/// The first two are the circumstances in which §4.2 says the AS MUST NOT
/// follow the finish method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionError {
    /// No pending grant is waiting on this interaction.
    UnknownInteraction,
    /// The grant is no longer pending: canceled, finished, or already answered.
    NotPending(State),
    /// The interaction outlived the timeout the AS set on it (§4.1).
    Expired,
    /// The client asked for a finish method this server does not implement.
    UnsupportedFinish(String),
    /// The grant on file cannot produce a callback; the server built it wrong.
    Misconfigured(&'static str),
    /// The interaction hash could not be computed (§4.2.3).
    Hash(String),
    /// The callback body could not be built.
    Serialization(String),
    /// Storage could not atomically publish this completion.
    Storage(StoreError),
}

impl fmt::Display for InteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownInteraction => write!(
                f,
                "no pending grant request is waiting on this interaction; the AS MUST NOT \
                 follow the finish method when it cannot determine which request is \
                 referenced (RFC 9635 §4.2)"
            ),
            Self::NotPending(state) => write!(
                f,
                "the grant request is `{state}`, not `pending`; the AS MUST NOT follow the \
                 finish method for a request that has been canceled or blocked \
                 (RFC 9635 §4.2)"
            ),
            Self::Expired => write!(
                f,
                "the interaction has expired; past the timeout the AS sets on it, the AS \
                 MUST reject attempts to use the interaction start modes (RFC 9635 §4.1)"
            ),
            Self::UnsupportedFinish(name) => {
                write!(f, "`{name}` is not a finish method this server implements")
            }
            Self::Misconfigured(what) => write!(f, "{what}"),
            Self::Hash(e) => write!(f, "the interaction hash could not be computed: {e}"),
            Self::Serialization(e) => write!(f, "the callback body could not be built: {e}"),
            Self::Storage(e) => write!(f, "interaction completion was not published: {e}"),
        }
    }
}

impl std::error::Error for InteractionError {}

/// A GNAP authorization server.
pub struct AuthorizationServer<P, K, S, N, E = OpaqueTokenEncoder> {
    policy: P,
    keys: K,
    storage: S,
    nonces: N,
    endpoints: Endpoints,
    development_http_discovery: bool,
    /// The store's atomic nonce-pair reservation, captured by
    /// [`Self::with_key_rotation`]; `None` means key rotation is disabled.
    key_rotation: Option<NoncePairReservation<S>>,
    user_codes: Option<crate::user_code::Configuration<S>>,
    encoder: E,
}

/// The [`RotationNonceStore::remember_nonce_pair`] of the server's own store.
type NoncePairReservation<S> = fn(&S, Option<&str>, Option<&str>, u64) -> bool;

/// All newly generated credentials are chosen before invoking the encoder.
struct PreparedToken {
    encoded: EncodedToken,
    expires_in: Option<u64>,
    management: String,
    management_token: TokenValue,
    continuation: Option<TokenValue>,
}

struct ApprovedDerivation {
    request: GrantRequest,
    access: crate::DerivedAccess,
    requester: crate::ResolvedResourceServer,
    parent: GrantSnapshot,
    issued_at: u64,
    ttl: u64,
}

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces> AuthorizationServer<P, K, S, N> {
    /// Offers discovery and introspection for this AS's opaque reference tokens.
    ///
    /// The RS resolver and replay memory are separate from client authentication.
    /// This API is deliberately unavailable with a custom token encoder: in
    /// particular, a Biscuit's parent identifier is not token introspection.
    /// The explicit loopback-discovery development setting is inherited.
    /// # Errors
    /// Rejects invalid or non-HTTPS endpoint configuration, except explicit
    /// HTTP-loopback development configuration.
    pub fn resource_server_api<
        'a,
        R: crate::ResourceServerResolver,
        Q: crate::IntrospectionPolicy,
    >(
        &'a self,
        keys: &'a R,
        policy: &'a Q,
        nonces: &'a dyn crate::NonceStore,
        endpoint: &'a str,
    ) -> Result<crate::ResourceServerApi<'a, R, Q, S>, gnap_types::message::DiscoveryError> {
        crate::ResourceServerApi::new(
            keys,
            policy,
            &self.storage,
            nonces,
            &self.endpoints.grant,
            endpoint,
            self.development_http_discovery,
        )
    }

    /// Assembles a server from its parts.
    pub const fn new(policy: P, keys: K, storage: S, nonces: N, endpoints: Endpoints) -> Self {
        Self {
            policy,
            keys,
            storage,
            nonces,
            endpoints,
            development_http_discovery: false,
            key_rotation: None,
            user_codes: None,
            encoder: OpaqueTokenEncoder,
        }
    }
}

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    /// Replaces the access-token representation without changing authorization.
    ///
    /// The encoder is used for both issuance and rotation. The default is an
    /// opaque reference; this builder alone does not implement a token format.
    pub fn with_token_encoder<T: TokenEncoder>(
        self,
        encoder: T,
    ) -> AuthorizationServer<P, K, S, N, T> {
        AuthorizationServer {
            policy: self.policy,
            keys: self.keys,
            storage: self.storage,
            nonces: self.nonces,
            endpoints: self.endpoints,
            development_http_discovery: self.development_http_discovery,
            key_rotation: self.key_rotation,
            user_codes: self.user_codes,
            encoder,
        }
    }

    /// Enables both human-code start modes at a stable web-entry URI.
    ///
    /// The adapter must serve that URI, obtain consent and limit guessing. Codes
    /// identify requests; they do not authenticate the resource owner. This
    /// profile uses eight Crockford base32 symbols and the interaction lifetime.
    /// A dedicated draw from the trusted [`Nonces`] source feeds each code.
    ///
    /// The URI is fixed, at most 256 bytes, HTTPS or HTTP loopback, without
    /// userinfo, query, fragment or percent encoding. These are profile bounds,
    /// not all URI forms allowed by GNAP. Prefer a manually typable URI; RFC
    /// 9635 §4.1.3 recommends 20 characters or fewer. Code-only clients know it
    /// out of band; `user_code_uri` clients receive it unchanged.
    ///
    /// [`UserCodeStore`] keeps this capability optional for ordinary adapters.
    /// Discovery announces the start modes after this opt-in, not completion
    /// of the Secondary Device interoperability profile.
    ///
    /// A store with the optional capability can enable the modes:
    ///
    /// ```
    /// use gnap_as::{AuthorizationServer, InteractionError, KeyResolver, Nonces, Policy, Storage, UserCodeStore};
    /// # #[allow(dead_code)]
    /// fn enable<P: Policy, K: KeyResolver, S: Storage + UserCodeStore, N: Nonces>(
    ///     server: AuthorizationServer<P, K, S, N>,
    /// ) -> Result<AuthorizationServer<P, K, S, N>, InteractionError> {
    ///     server.with_user_code_uri("https://as.example/code")
    /// }
    /// ```
    ///
    /// A plain storage bound is insufficient for that opt-in:
    ///
    /// ```compile_fail,E0277
    /// use gnap_as::{AuthorizationServer, InteractionError, KeyResolver, Nonces, Policy, Storage};
    /// # #[allow(dead_code)]
    /// fn enable<P: Policy, K: KeyResolver, S: Storage, N: Nonces>(
    ///     server: AuthorizationServer<P, K, S, N>,
    /// ) -> Result<AuthorizationServer<P, K, S, N>, InteractionError> {
    ///     server.with_user_code_uri("https://as.example/code")
    /// }
    /// ```
    ///
    /// # Errors
    /// Refuses an invalid URI without reflecting configuration values.
    pub fn with_user_code_uri(mut self, uri: impl Into<String>) -> Result<Self, InteractionError>
    where
        S: UserCodeStore,
    {
        let uri = uri.into();
        if !crate::user_code::valid_uri(&uri) {
            return Err(InteractionError::Misconfigured(
                "invalid user-code entry URI",
            ));
        }
        self.user_codes = Some(crate::user_code::Configuration {
            uri,
            lookup: S::lookup_user_code,
        });
        Ok(self)
    }

    /// Explicitly permits HTTP-loopback discovery for local development only.
    ///
    /// RFC 9635 §9 requires HTTPS. This opt-in does not claim an RFC exception:
    /// HTTP discovery is allowed only for `localhost`, IPv4 loopback or `::1`,
    /// and responses carry `GNAP-Development-Only: insecure-loopback-discovery`.
    /// Non-loopback HTTP remains rejected. Leave this disabled in production.
    /// It affects discovery only; it does not change grant or proof validation.
    #[must_use]
    pub const fn with_development_http_discovery(mut self) -> Self {
        self.development_http_discovery = true;
        self
    }

    /// Opts the token-management endpoint into linked HTTP-signature key rotation.
    ///
    /// Disabled by default. Enabling it also advertises the capability through
    /// discovery, but [`Policy::may_rotate_key`] still decides for each token.
    /// The key resolver must resolve both bindings, and the encoder and RS must
    /// honor explicit token keys. Turning the capability off does not erase
    /// already stored token bindings.
    /// Both proofs must carry nonempty nonces under this SDK's replay policy.
    ///
    /// The store must implement [`RotationNonceStore`]: the two proof nonces of
    /// a rotation are reserved together or not at all, and that reservation is
    /// captured here. A store without the capability cannot enable rotation:
    ///
    /// ```
    /// use gnap_as::{AuthorizationServer, KeyResolver, Nonces, Policy, RotationNonceStore, Storage};
    /// # #[allow(dead_code)]
    /// fn enable<P: Policy, K: KeyResolver, S: Storage + RotationNonceStore, N: Nonces>(
    ///     server: AuthorizationServer<P, K, S, N>,
    /// ) -> AuthorizationServer<P, K, S, N> {
    ///     server.with_key_rotation(true)
    /// }
    /// ```
    ///
    /// The same code with a plain [`Storage`] bound does not compile:
    ///
    /// ```compile_fail,E0277
    /// use gnap_as::{AuthorizationServer, KeyResolver, Nonces, Policy, Storage};
    /// # #[allow(dead_code)]
    /// fn enable<P: Policy, K: KeyResolver, S: Storage, N: Nonces>(
    ///     server: AuthorizationServer<P, K, S, N>,
    /// ) -> AuthorizationServer<P, K, S, N> {
    ///     server.with_key_rotation(true)
    /// }
    /// ```
    #[must_use]
    pub const fn with_key_rotation(mut self, enabled: bool) -> Self
    where
        S: RotationNonceStore,
    {
        let reserve: NoncePairReservation<S> = <S as RotationNonceStore>::remember_nonce_pair;
        self.key_rotation = if enabled { Some(reserve) } else { None };
        self
    }

    /// A fresh unguessable value, or the 500 response to send without one.
    fn nonce(&self) -> Result<String, HttpResponse> {
        self.nonces
            .next()
            .map_err(|_| misconfigured("the nonce source is unavailable"))
    }

    /// The store, for inspection.
    pub const fn storage(&self) -> &S {
        &self.storage
    }

    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    /// Handles a request, routing on its URI.
    pub fn handle(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        if request.url == self.endpoints.grant {
            if request.method.eq_ignore_ascii_case("OPTIONS") {
                self.handle_discovery(request)
            } else {
                self.handle_grant_request(request, now)
            }
        } else if request.url.starts_with(&self.endpoints.continuation) {
            self.handle_continuation(request, now)
        } else if request.url.starts_with(&self.endpoints.token_management) {
            self.handle_token_management(request, now)
        } else {
            not_found()
        }
    }

    /// Answers OPTIONS discovery at the exact configured grant endpoint (§9).
    ///
    /// No grant, key resolution, signature check or nonce consumption occurs.
    /// Engine capabilities include `httpsig`, the key-rotation setting,
    /// redirect start and, after explicit configuration, both user-code starts.
    /// Other interaction/subject fields are omitted because their availability
    /// depends on policy and HTTP adapter behavior;
    /// a registry enum is not a deployment's capability catalogue.
    /// This is discovery, not a CORS preflight policy: it adds no cross-origin
    /// permission headers. An HTTP adapter must define any such policy separately.
    ///
    /// Invalid public endpoint configuration returns an explicit server error,
    /// rather than publishing a nonconformant successful discovery document.
    /// Local HTTP requires [`Self::with_development_http_discovery`].
    pub fn handle_discovery(&self, request: &HttpRequest) -> HttpResponse {
        if request.url != self.endpoints.grant {
            return not_found();
        }
        if !request.method.eq_ignore_ascii_case("OPTIONS") {
            return method_not_allowed("POST, OPTIONS");
        }
        let mut starts = vec![gnap_registry::InteractionStartMode::Redirect];
        if self.user_codes.is_some() {
            starts.extend([
                gnap_registry::InteractionStartMode::UserCode,
                gnap_registry::InteractionStartMode::UserCodeUri,
            ]);
        }
        let discovery = AsDiscovery {
            grant_request_endpoint: self.endpoints.grant.clone(),
            interaction_start_modes_supported: Some(starts),
            interaction_finish_methods_supported: None,
            key_proofs_supported: Some(vec![gnap_registry::KeyProofingMethod::Httpsig]),
            sub_id_formats_supported: None,
            assertion_formats_supported: None,
            key_rotation_supported: Some(self.key_rotation.is_some()),
            extra: serde_json::Map::new(),
        };
        let validity = if self.development_http_discovery {
            discovery.validate_for_local_development(&request.url)
        } else {
            discovery.validate_for(&request.url)
        };
        if let Err(reason) = validity {
            return misconfigured(&reason.to_string());
        }
        let body = match serde_json::to_vec(&discovery) {
            Ok(body) => body,
            Err(reason) => return misconfigured(&reason.to_string()),
        };
        let mut headers = vec![
            ("Content-Type".into(), "application/json".into()),
            ("Cache-Control".into(), "no-store".into()),
            ("Allow".into(), "POST, OPTIONS".into()),
        ];
        if discovery.validate_for(&request.url).is_err() {
            headers.push((
                "GNAP-Development-Only".into(),
                "insecure-loopback-discovery".into(),
            ));
        }
        HttpResponse {
            status: 200,
            headers,
            body,
        }
    }

    /// Verifies the request's signature (§7.3.1), with this server's policy.
    ///
    /// The checks themselves live in `gnap_crypto::verify`, once for every
    /// role; what the AS brings is the clock, its tolerance, the `kid` of the
    /// key the client presented, and its nonce store.
    fn verify_signature(
        &self,
        request: &HttpRequest,
        verifier: &dyn gnap_crypto::proof::Verifier,
        presented_kid: Option<&str>,
        now: u64,
    ) -> Result<(), HttpResponse> {
        let signed = SignedRequest {
            method: &request.method,
            target_uri: &request.url,
            headers: &request.headers,
            body: request.body.as_deref(),
        };
        let expectations = Expectations {
            now,
            max_clock_skew: MAX_CLOCK_SKEW,
            key_id: presented_kid,
        };
        let remember = |nonce: &str, at: u64| self.storage.remember_nonce(nonce, at);
        verify_request(&signed, verifier, &expectations, &remember)
            .map(|_| ())
            .map_err(|e| error(ErrorCode::InvalidClient, &e.to_string()))
    }

    fn parse<D: serde::de::DeserializeOwned>(request: &HttpRequest) -> Result<D, HttpResponse> {
        let body = request.body.as_deref().unwrap_or_default();
        serde_json::from_slice(body).map_err(|e| error(ErrorCode::InvalidRequest, &e.to_string()))
    }
}

/// Includes retired-on-commit credentials from the authenticated snapshot.
fn credential_used(aggregate: &GrantAggregate, value: &str) -> bool {
    aggregate.record.continuation_token.as_deref() == Some(value)
        || aggregate
            .tokens
            .values()
            .any(|token| token.token.value.as_str() == value || token.management_token == value)
}
