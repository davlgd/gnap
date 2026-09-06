//! The authorization server, free of any HTTP framework.
//!
//! Takes a described HTTP request and returns a described HTTP response. What
//! carries those bytes — hyper, axum, a test harness, a Unix socket — is the
//! caller's business. The same seam that lets `gnap-client` be tested without a
//! network lets a client and a server be wired straight together.

use crate::encoding::{
    EncodedToken, OpaqueTokenEncoder, TokenEncoder, TokenEncodingContext, TokenEncodingError,
};
use crate::nonce::Nonces;
use crate::policy::{
    Decision, EvaluationContext, KeyResolver, Policy, ReleasedSubject, SubjectGround,
};
use crate::storage::{
    GrantAggregate, GrantRecord, GrantSelector, GrantSnapshot, Storage, StoreError, TokenRecord,
};
use gnap_core::{Event, Grant, State};
use gnap_crypto::hash::{interaction_hash_named, InteractionHashInput};
use gnap_crypto::verify::{verify_request, Expectations, SignedRequest};
use gnap_registry::{ErrorCode, InteractionFinishMethod};
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::interact::{InteractCallback, InteractFinish, InteractResponse};
use gnap_types::message::{AsDiscovery, Continue, ContinueRequest, GrantRequest, GrantResponse};
use gnap_types::token::{AccessToken, AccessTokenResponse, BoundToken, TokenManage, TokenValue};
use gnap_types::GnapError;
use gnap_types::{access::AccessItem, client::Client};
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
    encoder: E,
}

/// All newly generated credentials are chosen before invoking the encoder.
struct PreparedToken {
    encoded: EncodedToken,
    expires_in: Option<u64>,
    management: String,
    management_token: TokenValue,
    continuation: Option<TokenValue>,
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
            encoder,
        }
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
    /// Only fixed engine capabilities are announced: `httpsig` and lack of
    /// token-bound key rotation. Optional interaction/subject fields are omitted
    /// because their availability depends on policy and HTTP adapter behavior;
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
        let discovery = AsDiscovery {
            grant_request_endpoint: self.endpoints.grant.clone(),
            interaction_start_modes_supported: None,
            interaction_finish_methods_supported: None,
            key_proofs_supported: Some(vec![gnap_registry::KeyProofingMethod::Httpsig]),
            sub_id_formats_supported: None,
            assertion_formats_supported: None,
            key_rotation_supported: Some(false),
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

    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    /// A new grant request (§2).
    pub fn handle_grant_request(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        // §2 — "The request MUST be sent as a JSON object in the content of the
        // HTTP POST request with Content-Type application/json."
        if !request.method.eq_ignore_ascii_case("POST") {
            return method_not_allowed("POST, OPTIONS");
        }
        // §4.2.3 hashes "the grant endpoint URI the client instance used to
        // make its initial request", and this server hashes the endpoint it was
        // configured with. Serving a grant request at any other URL would make
        // the two differ, and every interaction hash wrong.
        if request.url != self.endpoints.grant {
            return not_found();
        }
        if let Err(r) = require_json_content(request) {
            return r;
        }

        let body = match Self::parse::<GrantRequest>(request) {
            Ok(b) => b,
            Err(r) => return r,
        };

        // §7.1 — a key sent by value is presented in exactly one format, and a
        // JWK carries `alg` and `kid`. The AS checks that before trying to use
        // it: a key it cannot read is a request it cannot verify.
        if let Some(key) = presented_key(&body.client) {
            if let Err(e) = key.validate() {
                return error(ErrorCode::InvalidClient, &e.to_string());
            }
        }

        // §2.4.1 — a user reference is one the AS itself handed out. One it
        // does not know is not a hint to ignore; the RFC names the answer.
        if let Some(reference) = body
            .user
            .as_ref()
            .and_then(gnap_types::user::User::as_reference)
        {
            if !self.policy.recognises_user(reference) {
                return error(
                    ErrorCode::UnknownUser,
                    "the user reference is not one this AS recognises (RFC 9635 §2.4.1)",
                );
            }
        }

        // §2.3.2 — the display information is shown to the RO on a page the AS
        // serves, so its URIs have to stand on their own.
        if let Some(display) = body.client.as_value().and_then(|c| c.display.as_ref()) {
            if let Err(e) = display.validate() {
                return error(ErrorCode::InvalidClient, &e.to_string());
            }
        }

        // §2.5.2 — a callback the AS cannot use is refused now, not at the end
        // of an interaction the RO has already been through.
        if let Some(finish) = body.interact.as_ref().and_then(|i| i.finish.as_ref()) {
            if let Err(reason) = supported_finish(finish) {
                return error(ErrorCode::InvalidRequest, &reason);
            }
        }

        // §2.3 — the client identifies itself, and the AS resolves its key.
        let Some(verifier) = self.keys.resolve(&body.client) else {
            return error(
                ErrorCode::InvalidClient,
                "the client instance is not recognised",
            );
        };

        // §7.3.1-M15 — when the key is a JWK, the signature names it by its
        // `kid` and uses the algorithm its `alg` declares.
        let presented_kid = match presented_key(&body.client) {
            None => None,
            Some(key) => match check_presented_key(key, verifier.as_ref()) {
                Ok(kid) => kid,
                Err(r) => return r,
            },
        };

        if let Err(r) = self.verify_signature(request, verifier.as_ref(), presented_kid, now) {
            return r;
        }

        let decision = self
            .policy
            .evaluate_context(&body, EvaluationContext::Initial);
        let mut aggregate = GrantAggregate::new(GrantRecord {
            grant: Grant::new(),
            request: body,
            continuation_token: None,
            as_nonce: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        });
        let response = self.settle(&mut aggregate, decision, now, None);
        if aggregate.record.continuation_token.is_some() || !aggregate.tokens.is_empty() {
            if let Err(failure) = self.storage.create(aggregate) {
                return storage_failure(failure);
            }
        }
        response
    }

    /// A call to the token management API (§6).
    ///
    /// §6 defines two actions and nothing else: POST rotates the token's value
    /// (§6.1), DELETE revokes it (§6.2). "Other actions are undefined by this
    /// specification", so nothing else is answered.
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    pub fn handle_token_management(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        let rotating = request.method.eq_ignore_ascii_case("POST");
        if !rotating && !request.method.eq_ignore_ascii_case("DELETE") {
            return method_not_allowed("POST, DELETE");
        }

        let handle = request
            .url
            .strip_prefix(&self.endpoints.token_management)
            .map(|rest| rest.trim_start_matches('/'))
            .unwrap_or_default();

        let Some(presented) = gnap_token(request) else {
            return error(
                ErrorCode::InvalidClient,
                "no token management access token was presented (RFC 9635 §6, §7.2)",
            );
        };

        let snapshot = match self.storage.lookup(GrantSelector::Management(handle)) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return invalid_management_credentials(),
            Err(failure) => return storage_failure(failure),
        };
        let Some(record) = snapshot.aggregate.tokens.get(handle) else {
            // §6 requires validation of the proof and its binding to the token.
            // This store retains no revoked-token key metadata, so it cannot
            // authenticate a request for a deleted handle. That prevents the
            // idempotent success recommended by §6.2-S04. Report the same error
            // as bad credentials for a live handle, without exposing existence.
            return invalid_management_credentials();
        };

        // §6-M04 — "The AS MUST uniquely identify the token being managed from
        // the token management URI, the token management access token, or a
        // combination of both." This server uses both: the handle finds the
        // record, and the token still has to be the one that record names.
        if record.management_token != presented {
            return invalid_management_credentials();
        }

        // §6-M03 — "The AS MUST validate the proof and ensure that it is
        // associated with the token management access token." The key is the
        // client's, and the record is what identifies the client.
        let Some(verifier) = self.keys.resolve(&record.client) else {
            return error(
                ErrorCode::InvalidClient,
                "the client instance is not recognised",
            );
        };
        let presented_kid = match presented_key(&record.client) {
            None => None,
            Some(key) => match check_presented_key(key, verifier.as_ref()) {
                Ok(kid) => kid,
                Err(r) => return r,
            },
        };
        if let Err(r) = self.verify_signature(request, verifier.as_ref(), presented_kid, now) {
            return r;
        }

        if rotating {
            self.rotate_token(snapshot, handle, request, now)
        } else {
            // §6.2-M02 — "the AS MUST invalidate the access token, if possible,
            // and return an HTTP response code 204."
            let mut replacement = snapshot.aggregate.clone();
            replacement.tokens.remove(handle);
            if let Err(failure) =
                self.storage
                    .compare_exchange(snapshot.id, snapshot.revision, replacement)
            {
                return storage_failure(failure);
            }
            no_content()
        }
    }

    /// Value rotation is bodyless; key rotation is explicitly unsupported.
    fn validate_rotation_content(request: &HttpRequest) -> Result<(), HttpResponse> {
        if request.body.as_ref().is_none_or(Vec::is_empty) {
            return Ok(());
        }
        require_json_content(request)?;
        let body = Self::parse::<serde_json::Map<String, serde_json::Value>>(request)?;
        if body.contains_key("key") {
            return Err(error(
                ErrorCode::KeyRotationNotSupported,
                "this server does not rotate the key bound to an access token (RFC 9635 §6.1.1)",
            ));
        }
        Err(error(
            ErrorCode::InvalidRequest,
            "value rotation has no message content; binding a new key requires a key field (RFC 9635 §6.1, §6.1.1)",
        ))
    }

    /// Rotates the value of a managed access token (§6.1).
    fn rotate_token(
        &self,
        mut snapshot: GrantSnapshot,
        handle: &str,
        request: &HttpRequest,
        now: u64,
    ) -> HttpResponse {
        if let Err(response) = Self::validate_rotation_content(request) {
            return response;
        }

        // Work on the authenticated snapshot. Publication is a single CAS;
        // the original stays visible while policy and encoding run.
        let Some(record) = snapshot.aggregate.tokens.get(handle).cloned() else {
            return error(
                ErrorCode::InvalidRotation,
                "no access token is managed at this URI (RFC 9635 §6)",
            );
        };

        // §6.1 — "If the AS is unable or unwilling to rotate the value of the
        // access token, the AS responds with an invalid_rotation error." The
        // client then "MUST consider the access token to not have changed its
        // state", so a refusal performs no storage write.
        // SDK policy, not an RFC requirement: an expired or not-yet-issued
        // value cannot be renewed. A clock rollback or an unrepresentable new
        // deadline must not extend it either. Keep all original metadata.
        if !record.is_valid_at(now)
            || record
                .token
                .expires_in
                .is_some_and(|seconds| now.checked_add(seconds).is_none())
            || !self.policy.may_rotate(&record.token)
        {
            return error(
                ErrorCode::InvalidRotation,
                "token lifetime or server policy prevents rotation (RFC 9635 §6.1)",
            );
        }

        let (Ok(candidate), Ok(management_token)) = (
            TokenValue::new(self.nonces.next()),
            TokenValue::new(self.nonces.next()),
        ) else {
            return error(
                ErrorCode::InvalidRotation,
                "unable to generate valid token values",
            );
        };

        // §6.1 — "issuing a new access token in place of an existing access
        // token, with the same rights and properties as the original token,
        // apart from an updated token value and expiration time." §6.1-M05
        // makes the rights explicit: they "MUST be included in the response and
        // MUST be the same as the token before rotation", which is why only the
        // value and the management API are replaced here.
        let rotated_handle = self.nonces.next();
        let Ok(encoded) = self.encode_rotated_token(
            &record,
            &snapshot.aggregate,
            now,
            &candidate,
            &management_token,
        ) else {
            return error(
                ErrorCode::InvalidRotation,
                "unable to encode a replacement access token",
            );
        };
        // Keep the original until the replacement is fully validated. A failed
        // rotation leaves the existing token unchanged (§6.1).
        let mut rotated = record.clone();
        rotated.issued_at = now;
        rotated.token.value = encoded.value;
        rotated.identifier = encoded.identifier;
        // §6.1-M03 — the response includes a management URI, and it may differ
        // from the one just called; §6.1-M04 has the client use the new one.
        rotated.token.manage = Some(TokenManage {
            uri: format!(
                "{}/{}",
                self.endpoints.token_management.trim_end_matches('/'),
                rotated_handle
            ),
            access_token: BoundToken::new(management_token.clone()),
        });
        management_token
            .as_str()
            .clone_into(&mut rotated.management_token);

        // §6.1-MN02 refers to the CURRENT management token. Validating the new
        // token alone only compares with the replacement management token.
        let invalid = if record.identifier.is_some() && rotated.identifier == record.identifier {
            Some("the rotated token repeats its previous format identifier".into())
        } else if credential_used(&snapshot.aggregate, rotated.token.value.as_str()) {
            Some("the rotated value repeats an existing access or management token".into())
        } else {
            rotated.token.validate().err().map(|e| e.to_string())
        };
        if let Some(reason) = invalid {
            return error(ErrorCode::InvalidRotation, &reason);
        }

        let response = GrantResponse {
            access_token: Some(AccessTokenResponse {
                cardinality: gnap_types::Cardinality::Single,
                tokens: vec![rotated.token.clone()],
            }),
            ..GrantResponse::default()
        };
        // §6.1-M01 — "the AS MUST invalidate the current access token value
        // associated with this URI, if possible". The replacement and removal of all
        // old indexes publish together; a stale candidate cannot restore them.
        if rotated_handle != handle && snapshot.aggregate.tokens.contains_key(&rotated_handle) {
            return error(
                ErrorCode::InvalidRotation,
                "token management handle collision",
            );
        }
        snapshot.aggregate.tokens.remove(handle);
        snapshot.aggregate.tokens.insert(rotated_handle, rotated);
        if let Err(failure) =
            self.storage
                .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        {
            return if matches!(
                failure,
                StoreError::Conflict | StoreError::Collision | StoreError::Invalid
            ) {
                error(
                    ErrorCode::InvalidRotation,
                    "the replacement token could not be committed",
                )
            } else {
                storage_failure(failure)
            };
        }
        ok(&response)
    }

    /// A call to the continuation API (§5).
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    pub fn handle_continuation(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        // §5 gives each operation its own method: POST continues, whether by
        // polling (§5.2) or by returning from interaction (§5.1), PATCH
        // modifies the request (§5.3), and DELETE revokes it (§5.4).
        let modifying = request.method.eq_ignore_ascii_case("PATCH");
        let revoking = request.method.eq_ignore_ascii_case("DELETE");
        if !revoking {
            if !modifying && !request.method.eq_ignore_ascii_case("POST") {
                return method_not_allowed("POST, PATCH, DELETE");
            }
            if let Err(r) = require_json_content(request) {
                return r;
            }
        }

        let snapshot = match self.authenticate_continuation(request, now) {
            Ok(snapshot) => snapshot,
            Err(r) => return r,
        };

        let mut aggregate = snapshot.aggregate.clone();
        let response = self.continue_authenticated(
            request,
            now,
            modifying,
            revoking,
            &mut aggregate,
            &snapshot,
        );
        // Preparation failed before publication. An internal 5xx is not a
        // GNAP decision to close or modify the grant. Keep the original; this
        // says nothing about a response lost after a successful CAS.
        if response.status >= 500 {
            return response;
        }
        if aggregate.record.continuation_token.is_some()
            && aggregate.record.continuation_token == snapshot.aggregate.record.continuation_token
        {
            return misconfigured(
                "the replacement continuation credential repeats its predecessor",
            );
        }
        if aggregate.record.continuation_token.is_none() {
            aggregate.record.interact_handle = None;
            aggregate.record.interact_ref = None;
            aggregate.record.interact_expires_at = None;
            aggregate.record.grant.withhold_continuation();
        }
        match self
            .storage
            .compare_exchange(snapshot.id, snapshot.revision, aggregate)
        {
            Ok(_) => response,
            Err(failure) => storage_failure(failure),
        }
    }

    // Only prepares a replacement. No intermediate state is externally visible.
    fn continue_authenticated(
        &self,
        request: &HttpRequest,
        now: u64,
        modifying: bool,
        revoking: bool,
        aggregate: &mut GrantAggregate,
        authenticated: &GrantSnapshot,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        record.continuation_token = None;
        let has_content = request.body.as_ref().is_some_and(|b| !b.is_empty());
        let continuation: ContinueRequest = if revoking || !has_content {
            ContinueRequest::default()
        } else {
            match Self::parse(request) {
                Ok(c) => c,
                Err(_) => {
                    return self.recover(
                        record,
                        ErrorCode::InvalidRequest,
                        "the continuation request is not a JSON object this server can \
                         read (RFC 9635 §5)",
                        now,
                    )
                }
            }
        };
        // §5.3-Y05 — a modification may bring new interaction capabilities, and
        // §2.5.2 applies to them exactly as it does to the initial request.
        if let Some(finish) = continuation
            .interact
            .as_ref()
            .and_then(|i| i.finish.as_ref())
        {
            if let Err(reason) = supported_finish(finish) {
                return self.recover(record, ErrorCode::InvalidRequest, &reason, now);
            }
        }
        if continuation
            .user
            .as_ref()
            .and_then(gnap_types::user::User::as_reference)
            .is_some_and(|reference| !self.policy.recognises_user(reference))
        {
            return self.recover(
                record,
                ErrorCode::UnknownUser,
                "the user reference is not one this AS recognises (RFC 9635 §2.4.1)",
                now,
            );
        }

        let event = if revoking {
            Event::Revoke
        } else {
            match classify(modifying, has_content, &continuation) {
                Ok(event) => event,
                Err(reason) => return self.recover(record, ErrorCode::InvalidRequest, reason, now),
            }
        };

        // §4.2 — the reference is one the AS issued for this grant, and it is
        // one-time-use. Without this check any string would do, and anyone able
        // to reach the continuation endpoint could claim the interaction had
        // finished.
        let returning = matches!(event, Event::ContinueWithInteractRef(_));
        if let Event::ContinueWithInteractRef(presented) = &event {
            if record.interact_ref.as_deref() != Some(presented.as_str()) {
                // The grant survives: presenting a wrong reference is not a
                // reason to lose a pending request. It survives with a new
                // continuation token, which is what lets the client try again.
                return self.recover(
                    record,
                    ErrorCode::InvalidInteraction,
                    "the interaction reference is not the one issued for this grant \
                     (RFC 9635 §4.2)",
                    now,
                );
            }
        }

        // gnap-core owns the guards: wait period, one-time references, the
        // states a modification is allowed from, and the absorbing finalized.
        if let Err(e) = record.grant.apply(event, now) {
            // A recoverable refusal keeps a continuation in the candidate:
            // being told `too_fast` must not cost the client its request.
            // The exception is a guard that finalizes, where §5.1 wants the
            // request invalidated and no way back offered.
            if e.finalizes {
                return error(e.code, &e.reason);
            }
            return self.recover(record, e.code, &e.reason, now);
        }

        // §4.2-M05 — the reference is one-time-use, and this is the call that
        // used it. Spending it any earlier would let a `too_fast` refusal
        // destroy a reference the client can never obtain again.
        if returning {
            record.interact_ref = None;
        }

        if revoking {
            aggregate.revoked = true;
            aggregate.tokens.clear();
            return no_content();
        }

        self.resume_grant(
            aggregate,
            continuation,
            modifying,
            returning,
            now,
            authenticated,
        )
    }

    /// Re-evaluates an authenticated continuation after its state guards pass.
    fn resume_grant(
        &self,
        aggregate: &mut GrantAggregate,
        continuation: ContinueRequest,
        modifying: bool,
        returning: bool,
        now: u64,
        authenticated: &GrantSnapshot,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        // Approved POST keeps the grant open but does not issue another token
        // or reuse old interaction consent to evaluate a new request (§3.1).
        if record.grant.state() == State::Approved && !modifying && !returning {
            return self.hand_back(record, None, now);
        }
        // §4 — coming back from interaction, the AS re-evaluates the whole
        // context, whether the RO approved or denied.
        //
        // How the client comes back is not free, though. §2.5.2-M13 makes every
        // finish method "require presentation of an interaction reference for
        // continuing this grant request", and §2.5.2-M14 says that reference
        // "MUST be presented by the client as described in Section 5.1". So a
        // grant that negotiated a finish is re-evaluated only when the client
        // actually presents the reference; polling does not stand in for it,
        // which would hand the grant to anyone holding the continuation token
        // the moment the RO answered. A grant with no finish method has nothing
        // to present, and polling is the whole of §5.2.
        let expects_reference = record
            .request
            .interact
            .as_ref()
            .is_some_and(|i| i.finish.is_some());

        // The reference is owed and this call is not the one that pays it. The
        // AS has nothing to decide yet — re-running the policy here would offer
        // a second interaction and, with it, throw away the reference the
        // client is about to present. So the grant is handed back untouched,
        // under a fresh token, still pending (§5.2).
        if expects_reference && !returning && !modifying {
            return self.hand_back(record, None, now);
        }

        if modifying {
            // A modification negotiates a new context (§5.3). The previous
            // interaction reference cannot stand for consent to that context.
            record.interaction_completed = false;
            record.interact_ref = None;
            record.as_nonce = None;
            record.interact_handle = None;
            record.interact_expires_at = None;
        }
        let after_interaction = record.interaction_completed && (returning || !expects_reference);
        let request_now = apply_modification(record.request.clone(), continuation);
        let decision = if modifying {
            self.policy
                .evaluate_context(&request_now, EvaluationContext::Modification(authenticated))
        } else if after_interaction {
            self.policy.evaluate_context(
                &request_now,
                EvaluationContext::AfterInteraction(authenticated),
            )
        } else {
            self.policy.evaluate(&request_now)
        };
        if !modifying && !returning && matches!(decision, Decision::RequireInteraction) {
            // A poll changes neither the request nor the interaction already
            // open in the RO's browser. Keep its handle and original timeout.
            return self.hand_back(record, None, now);
        }

        record.request = request_now;
        self.settle(aggregate, decision, now, Some(authenticated))
    }

    /// Signals that the RO is done interacting (§4.2).
    ///
    /// `handle` is the value the AS put in the interaction URI it handed the
    /// client; it names the grant the RO was working on. The AS creates the
    /// interaction reference here, binds it to that grant, computes the hash of
    /// §4.2.3, and returns what has to happen next.
    ///
    /// §4.2 associates the reference with "the current interaction and the
    /// underlying pending request". Spending the interaction handle and
    /// publishing that reference use one compare-and-exchange; only its winner
    /// receives a finish directive to carry out.
    ///
    /// Carrying the directive out is left to the caller, which is what keeps
    /// this crate free of an HTTP client. [`Finish::Push`] in particular is an
    /// outbound call to a URI the client supplied, so whoever performs it MUST
    /// apply the SSRF protection of §11.34 (§4.2.2).
    ///
    /// # Errors
    ///
    /// Returns the cases in which §4.2 says the AS MUST NOT follow the finish
    /// method: an unknown interaction, or a grant that is no longer pending.
    /// [`InteractionError::Storage`] also reports unavailable storage or a
    /// compare-and-exchange conflict. The caller must not carry out the finish
    /// method unless the state change committed and this call returned `Ok`.
    pub fn complete_interaction(&self, handle: &str, now: u64) -> Result<Finish, InteractionError> {
        let snapshot = self
            .storage
            .lookup(GrantSelector::Interaction(handle))
            .map_err(InteractionError::Storage)?
            .ok_or(InteractionError::UnknownInteraction)?;
        let mut aggregate = snapshot.aggregate.clone();
        let outcome = self.finish_interaction(&mut aggregate.record, now)?;
        self.storage
            .compare_exchange(snapshot.id, snapshot.revision, aggregate)
            .map_err(InteractionError::Storage)?;
        Ok(outcome)
    }

    /// Decides what a completed interaction owes the client, mutating `record`.
    ///
    /// The caller keeps the mutation only on `Ok`, so every refusal below
    /// leaves the grant untouched: an interaction the AS will not finish must
    /// not be marked as having happened.
    fn finish_interaction(
        &self,
        record: &mut GrantRecord,
        now: u64,
    ) -> Result<Finish, InteractionError> {
        // §4.2 — the AS MUST NOT follow the finish method when "The ongoing
        // grant request has been canceled or otherwise blocked".
        if record.grant.state() != State::Pending {
            return Err(InteractionError::NotPending(record.grant.state()));
        }

        // §4.1-M02 — past the timeout the AS "MUST reject attempts to use the
        // interaction start modes". An interaction URI outlives the tab it was
        // opened in; this is what stops one found later from still working.
        if record.interact_expires_at.is_some_and(|at| now >= at) {
            return Err(InteractionError::Expired);
        }

        let finish = record
            .request
            .interact
            .as_ref()
            .and_then(|i| i.finish.clone());

        // Everything that can refuse runs before anything is written.
        let directive = match &finish {
            None => None,
            Some(finish) => {
                let uri = finish
                    .uri
                    .as_deref()
                    .ok_or(InteractionError::Misconfigured(
                        "the finish method carries no URI to call back (RFC 9635 §2.5.2)",
                    ))?;
                // §2.5.2 — the URI is absolute and carries no fragment. A
                // fragment would swallow the query the callback travels in.
                if uri.contains('#') {
                    return Err(InteractionError::Misconfigured(
                        "the finish URI carries a fragment, so the callback parameters \
                         could not be read from its query (RFC 9635 §2.5.2)",
                    ));
                }
                match finish.method {
                    InteractionFinishMethod::Redirect | InteractionFinishMethod::Push => {}
                    InteractionFinishMethod::Unregistered(ref name) => {
                        return Err(InteractionError::UnsupportedFinish(name.clone()))
                    }
                }
                Some((finish, uri.to_owned()))
            }
        };

        // RFC 9635 §4.2 — "The interaction reference value MUST be
        // sufficiently random so as not to be guessable by an attacker", and
        // is an ASCII string of unreserved characters (RFC 3986 §2.3). Randomness is the nonce
        // source's contract; the character set is checked here because a
        // reference that has to survive a query parameter cannot hold anything
        // else.
        let interact_ref = self.nonces.next();
        if interact_ref.is_empty() || !interact_ref.bytes().all(is_unreserved) {
            return Err(InteractionError::Misconfigured(
                "the interaction reference must be a non-empty ASCII string of unreserved \
                 characters (RFC 9635 §4.2)",
            ));
        }

        let Some((finish, uri)) = directive else {
            // §4.2 — with no finish method the AS should send the RO back to
            // the client instance, which is polling the continuation endpoint.
            record.interaction_completed = true;
            record.interact_handle = None;
            return Ok(Finish::SendTheUserBack);
        };

        let as_nonce = record
            .as_nonce
            .as_deref()
            .ok_or(InteractionError::Misconfigured(
                "the grant carries no AS nonce, so the interaction hash cannot be computed \
                 (RFC 9635 §3.3.5)",
            ))?;
        let hash = interaction_hash_named(
            &InteractionHashInput {
                client_nonce: &finish.nonce,
                as_nonce,
                interact_ref: &interact_ref,
                grant_endpoint: &self.endpoints.grant,
            },
            finish.hash_method.as_deref(),
        )
        .map_err(|e| InteractionError::Hash(e.to_string()))?;

        let callback = InteractCallback {
            hash,
            interact_ref: interact_ref.clone(),
        };
        let directive = match finish.method {
            // §4.2.1 — the AS secures the redirect by adding the hash and the
            // reference as query parameters to the client's redirect URI.
            InteractionFinishMethod::Redirect => Finish::Redirect {
                uri: with_callback_query(&uri, &callback),
            },
            _ => Finish::Push {
                uri,
                body: serde_json::to_vec(&callback)
                    .map_err(|e| InteractionError::Serialization(e.to_string()))?,
            },
        };

        // Nothing can fail past here, so the writes land together.
        record.interaction_completed = true;
        record.interact_ref = Some(interact_ref);
        // §4.2 — the interaction is spent; a second completion finds nothing.
        record.interact_handle = None;
        Ok(directive)
    }

    /// Names the grant a continuation call is for, once the caller has proved
    /// it may make it (§5-M01, §5-M02).
    ///
    /// The grant is read without being consumed. The client's key is only known
    /// through the grant on file, so it has to be read before the signature can
    /// be verified — and a request that fails verification must leave the grant
    /// exactly as it was. Consuming here would let anyone holding a leaked
    /// continuation token destroy the grant with a signature that does not
    /// verify, and the legitimate client would never learn why.
    fn authenticate_continuation(
        &self,
        request: &HttpRequest,
        now: u64,
    ) -> Result<GrantSnapshot, HttpResponse> {
        let token = Self::continuation_token(request)?;
        let snapshot = self
            .storage
            .lookup(GrantSelector::Continuation(&token))
            .map_err(storage_failure)?
            .ok_or_else(unknown_continuation)?;
        let record = &snapshot.aggregate.record;

        let verifier = self.keys.resolve(&record.request.client).ok_or_else(|| {
            error(
                ErrorCode::InvalidClient,
                "the client instance is not recognised",
            )
        })?;
        let presented_kid = match presented_key(&record.request.client) {
            None => None,
            Some(key) => check_presented_key(key, verifier.as_ref())?,
        };
        self.verify_signature(request, verifier.as_ref(), presented_kid, now)?;
        Ok(snapshot)
    }

    /// Answers an error the grant can survive, and hands the client the way
    /// back (§5-M11, §5-M12).
    ///
    /// "If the AS determines that the client instance can make further requests
    /// to the continuation API, the AS MUST include a new continuation
    /// response", and that response "MUST include a continuation access token
    /// as well, and this token SHOULD be a new access token, invalidating the
    /// previous access token". The two rules that follow are why this matters:
    /// §5-MN13 forbids the client from calling again when no continuation came
    /// back, and §5-M14 obliges the AS to answer `invalid_continuation` if it
    /// does. An error that leaves the grant alive and says nothing would leave
    /// a grant that neither side may touch again.
    ///
    /// §3.6 allows `error` and `continue` together only while the grant is
    /// pending. When it is not, there is no way to say "carry on", so the
    /// record is dropped and the next call gets `invalid_continuation` — which
    /// is exactly what §5-M14 asks for.
    fn recover(
        &self,
        record: &mut GrantRecord,
        code: ErrorCode,
        reason: &str,
        now: u64,
    ) -> HttpResponse {
        if record.grant.state() != State::Pending {
            return error(code, reason);
        }
        self.hand_back(record, Some(GnapError::with_description(code, reason)), now)
    }

    /// Answers a call the AS is not going to act on, and hands the grant back.
    ///
    /// §5-M11 — "the AS MUST include a new continuation response" when the
    /// grant can continue. §5-M12 says the response "MUST include a continuation
    /// access token as well, and this token SHOULD be a new access token, invalidating
    /// the previous access token". This SDK follows that recommendation:
    /// committing the candidate removes the old index and publishes the new
    /// one together. A failed transaction publishes neither response nor token.
    fn hand_back(
        &self,
        record: &mut GrantRecord,
        failure: Option<GnapError>,
        now: u64,
    ) -> HttpResponse {
        let token = self.nonces.next();
        let Ok(value) = TokenValue::new(token.clone()) else {
            return misconfigured(
                "Nonces returned a continuation value outside token68 (RFC 9635 §3.2.1)",
            );
        };

        record
            .grant
            .offer_continuation(now, Some(gnap_core::DEFAULT_WAIT));
        record.continuation_token = Some(token);

        let status = if failure.is_some() { 400 } else { 200 };
        let response = GrantResponse {
            error: failure,
            r#continue: Some(Continue {
                uri: self.endpoints.continuation.clone(),
                access_token: BoundToken::new(value),
                wait: Some(gnap_core::DEFAULT_WAIT),
                extra: serde_json::Map::default(),
            }),
            ..GrantResponse::default()
        };

        HttpResponse {
            status,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    /// Reads the continuation token a call presents (§5).
    ///
    /// §5 lets the AS identify the grant from the continuation URI, the
    /// continuation token, or both; this server uses the token, presented with
    /// the GNAP scheme (§7.2).
    fn continuation_token(request: &HttpRequest) -> Result<String, HttpResponse> {
        gnap_token(request).map(ToOwned::to_owned).ok_or_else(|| {
            error(
                ErrorCode::InvalidContinuation,
                "no continuation access token was presented (RFC 9635 §5)",
            )
        })
    }

    fn encode_rotated_token(
        &self,
        record: &TokenRecord,
        aggregate: &GrantAggregate,
        now: u64,
        candidate: &TokenValue,
        management: &TokenValue,
    ) -> Result<EncodedToken, TokenEncodingError> {
        // A broken nonce source must not expose a management credential as
        // an encoder input, even by accidentally repeating its value.
        if candidate == management
            || credential_used(aggregate, candidate.as_str())
            || credential_used(aggregate, management.as_str())
        {
            return Err(TokenEncodingError);
        }
        self.encode_access_token(
            &record.client,
            record.token.access.as_deref().unwrap_or_default(),
            now,
            record.token.expires_in,
            candidate,
        )
    }

    fn encode_issued_token(
        &self,
        request: &GrantRequest,
        access: &[AccessItem],
        now: u64,
        keep_open: bool,
        authenticated: Option<&GrantSnapshot>,
    ) -> Result<PreparedToken, HttpResponse> {
        let expires_in = self.access_token_lifetime(request, now)?;
        let candidate = TokenValue::new(self.nonces.next()).map_err(|_| {
            misconfigured("Nonces returned an access value outside token68 (RFC 9635 §3.2.1)")
        })?;
        // Preserve the nominal candidate → handle → credential order, but
        // reserve all three before encoding. A repeating source must not pass
        // the management credential to the encoder as its candidate.
        let management = self.nonces.next();
        let management_token = TokenValue::new(self.nonces.next()).map_err(|_| {
            misconfigured("Nonces returned a management value outside token68 (RFC 9635 §3.2.1)")
        })?;
        let continuation = if keep_open {
            Some(
                TokenValue::new(self.nonces.next())
                    .map_err(|_| misconfigured("Nonces returned an invalid continuation value"))?,
            )
        } else {
            None
        };
        let repeated = |value: &str| {
            authenticated.is_some_and(|snapshot| credential_used(&snapshot.aggregate, value))
        };
        if candidate == management_token
            || continuation.as_ref().is_some_and(|value| {
                value == &candidate || value == &management_token || repeated(value.as_str())
            })
            || repeated(candidate.as_str())
            || repeated(management_token.as_str())
        {
            return Err(misconfigured(
                "generated values repeat access, management or continuation credentials",
            ));
        }
        let encoded = self
            .encode_access_token(&request.client, access, now, expires_in, &candidate)
            .map_err(|_| misconfigured("unable to encode an access token"))?;
        if encoded.value == management_token
            || continuation.as_ref() == Some(&encoded.value)
            || repeated(encoded.value.as_str())
        {
            return Err(misconfigured(
                "encoded access value repeats another credential",
            ));
        }
        if encoded.identifier.as_ref().is_some_and(|identifier| {
            authenticated.is_some_and(|snapshot| {
                snapshot
                    .aggregate
                    .tokens
                    .values()
                    .any(|token| token.identifier.as_ref() == Some(identifier))
            })
        }) {
            return Err(misconfigured(
                "encoded token repeats a previous format identifier",
            ));
        }
        Ok(PreparedToken {
            encoded,
            expires_in,
            management,
            management_token,
            continuation,
        })
    }

    fn encode_access_token(
        &self,
        client: &Client,
        access: &[AccessItem],
        issued_at: u64,
        expires_in: Option<u64>,
        candidate: &TokenValue,
    ) -> Result<EncodedToken, TokenEncodingError> {
        let encoded = self.encoder.encode(&TokenEncodingContext {
            issuer: &self.endpoints.grant,
            client,
            access,
            issued_at,
            expires_in,
            candidate_nonce: candidate.as_str(),
        })?;
        if encoded.identifier.as_ref().is_some_and(Vec::is_empty) {
            return Err(TokenEncodingError);
        }
        Ok(encoded)
    }

    fn access_token_lifetime(
        &self,
        request: &GrantRequest,
        now: u64,
    ) -> Result<Option<u64>, HttpResponse> {
        let seconds = self
            .policy
            .token_lifetime(request)
            .map(std::num::NonZeroU64::get);
        if seconds.is_some_and(|seconds| now.checked_add(seconds).is_none()) {
            Err(misconfigured(
                "token lifetime exceeds the representable expiration time",
            ))
        } else {
            Ok(seconds)
        }
    }

    /// Prepares a decision and its response; the caller commits the aggregate.
    fn settle(
        &self,
        aggregate: &mut GrantAggregate,
        decision: Decision,
        now: u64,
        authenticated: Option<&GrantSnapshot>,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        let grant = &mut record.grant;
        let event = match &decision {
            Decision::Approve { .. } => Event::AsNeedsNoInteraction,
            Decision::RequireInteraction => Event::AsRequiresInteraction,
            Decision::Deny(_) => Event::AsCannotProceed,
        };
        if grant.state() != State::Processing {
            // Coming back from interaction the grant is processing again; any
            // other state here is a bug in this server, not in the request.
            let _ = grant.apply(Event::Modify, now);
        }
        if let Err(e) = grant.apply(event, now) {
            return error(e.code, &e.reason);
        }

        match decision {
            Decision::Approve { access, subject } => {
                self.approve(aggregate, access, subject, now, authenticated)
            }
            Decision::Deny(code) => error(code, "the request was denied"),
            Decision::RequireInteraction => {
                // A new interaction gets a new finish nonce. An ordinary poll
                // of an unfinished interaction does not reach this branch.
                record.as_nonce = None;
                match self.offer_interaction(record, now) {
                    Ok(pending) => ok(&pending),
                    Err(response) => response,
                }
            }
        }
    }

    /// Prepares replacement access; the caller publishes it with the grant CAS.
    fn approve(
        &self,
        aggregate: &mut GrantAggregate,
        access: Vec<AccessItem>,
        subject: Option<ReleasedSubject>,
        now: u64,
        authenticated: Option<&GrantSnapshot>,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        let request = &record.request;
        let interacted = record.interaction_completed;
        let grant = &mut record.grant;
        let mut response = GrantResponse::default();
        if let Some(released) = &subject {
            if released.ground == SubjectGround::RoInteractedHere && !interacted {
                return misconfigured(
                    "subject information released on the ground that the RO \
                     interacted, on a grant that has been through no interaction",
                );
            }
            if let Err(e) = released.subject.validate() {
                return misconfigured(&e.to_string());
            }
        }
        let keep_open = self.policy.keep_grant_open(request);
        let PreparedToken {
            encoded,
            expires_in,
            management,
            management_token,
            continuation,
        } = match self.encode_issued_token(request, &access, now, keep_open, authenticated) {
            Ok(encoded) => encoded,
            Err(response) => return response,
        };

        // §3.2.1 — the management API the client may call to rotate or
        // revoke this token (§6). Both halves were reserved before
        // encoding: the URI handle and the credential protecting it.
        let manage = TokenManage {
            uri: format!(
                "{}/{}",
                self.endpoints.token_management.trim_end_matches('/'),
                management
            ),
            access_token: BoundToken::new(management_token.clone()),
        };

        let token = AccessToken {
            value: encoded.value,
            label: request
                .access_token
                .as_ref()
                .and_then(|a| a.tokens.first())
                .and_then(|t| t.label.clone()),
            manage: Some(manage),
            access: Some(access),
            expires_in,
            key: None,
            flags: Vec::new(),
            extra: serde_json::Map::default(),
        };
        // TokenManage validation also rejects an encoded access value
        // equal to its management credential before anything is stored.
        if let Err(e) = token.validate() {
            return misconfigured(&e.to_string());
        }
        // §6 — the AS has to find this token again from the management
        // URI and the management token, so it remembers both.
        if aggregate.tokens.contains_key(&management) {
            return misconfigured("token management handle collision");
        }
        // §5.3 permits revoking previous tokens after modification.
        // This SDK replaces the complete set only on successful
        // approval, in the same CAS that publishes the new token.
        aggregate.tokens.clear();
        aggregate.tokens.insert(
            management,
            TokenRecord {
                identifier: encoded.identifier,
                issued_at: now,
                token: token.clone(),
                client: request.client.clone(),
                management_token: management_token.as_str().to_owned(),
            },
        );

        // §3.2.1, §3.2.2 — the response mirrors the request's shape.
        let cardinality = request
            .access_token
            .as_ref()
            .map_or(gnap_types::Cardinality::Single, |a| a.cardinality);
        response.access_token = Some(AccessTokenResponse {
            cardinality,
            tokens: vec![token],
        });
        // §3.4-M01 — the AS returns `subject` "only in cases where the
        // AS is sure that the RO and the end user are the same party",
        // and names interaction as how that is established. The one
        // ground this server can check is that one: a grant that has
        // been through no interaction cannot claim it. The check is on
        // the deployment's claim, not on the client's request, so it
        // reports a server fault rather than blaming the caller.
        if let Some(released) = subject {
            response.subject = Some(*released.subject);
        }
        record.interact_handle = None;
        record.interact_ref = None;
        record.interact_expires_at = None;
        if let Some(continuation) = continuation {
            record.continuation_token = Some(continuation.as_str().to_owned());
            grant.offer_continuation(now, Some(gnap_core::DEFAULT_WAIT));
            response.r#continue = Some(Continue {
                uri: self.endpoints.continuation.clone(),
                access_token: BoundToken::new(continuation),
                wait: Some(gnap_core::DEFAULT_WAIT),
                extra: serde_json::Map::new(),
            });
        } else {
            grant.withhold_continuation();
        }

        ok(&response)
    }

    /// Answers `pending`: somewhere to send the end user, and a way back (§3.3).
    fn offer_interaction(
        &self,
        record: &mut GrantRecord,
        now: u64,
    ) -> Result<GrantResponse, HttpResponse> {
        let request = &record.request;
        let nonce = record
            .as_nonce
            .clone()
            .unwrap_or_else(|| self.nonces.next());
        let mut interact = InteractResponse::default();

        // §3.3 — never answer with a mode the client did not offer.
        let mut handle = None;
        if let Some(i) = &request.interact {
            let offers = |m: &str| i.start.iter().any(|s| s.method().as_str() == m);
            if offers("redirect") {
                // §4.2 has to find this grant again once the RO is done, and
                // the interaction URI is all the AS will see at that point;
                // the handle in it is the link back.
                let issued = self.nonces.next();
                interact.redirect = Some(format!(
                    "{}/{}",
                    self.endpoints.interaction.trim_end_matches('/'),
                    issued
                ));
                handle = Some(issued);
                // §3.3 — the client is told how long the interaction lasts
                // rather than left to guess at the timeout §4-M04 asks for.
                interact.expires_in = Some(INTERACTION_LIFETIME);
            }
            if i.finish.is_some() {
                interact.finish = Some(nonce.clone());
            }
        }

        // §2.5 — when interaction is required, the client offers no mode this
        // AS can drive, and the AS has no way to reach the RO on its own, it
        // MUST say so. Answering `pending` with an empty `interact` would leave
        // the client polling a grant that can never advance.
        if interact.redirect.is_none() && interact.app.is_none() {
            return Err(error(
                ErrorCode::InvalidInteraction,
                "interaction is required, the client instance offers no mechanism this AS \
                 supports, and the AS cannot reach the resource owner asynchronously \
                 (RFC 9635 §2.5)",
            ));
        }

        let token = self.nonces.next();
        let Ok(token_value) = TokenValue::new(token.clone()) else {
            return Err(misconfigured(
                "Nonces returned a continuation value outside token68 (RFC 9635 §3.2.1)",
            ));
        };

        let mut response = GrantResponse {
            interact: Some(interact),
            ..GrantResponse::default()
        };
        response.r#continue = Some(Continue {
            uri: self.endpoints.continuation.clone(),
            access_token: BoundToken::new(token_value),
            wait: Some(gnap_core::DEFAULT_WAIT),
            extra: serde_json::Map::default(),
        });
        record
            .grant
            .offer_continuation(now, Some(gnap_core::DEFAULT_WAIT));
        record.continuation_token = Some(token);
        record.as_nonce = Some(nonce);
        record.interact_handle = handle;
        record.interact_expires_at = Some(now.saturating_add(INTERACTION_LIFETIME));
        record.interact_ref = None;
        record.interaction_completed = false;
        Ok(response)
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

/// The key a client presented by value, if it did (§2.3, §7.1).
///
/// A client named by reference has no key in the message; the AS knows it from
/// its own records, which is what the [`KeyResolver`] speaks for.
fn presented_key(client: &gnap_types::client::Client) -> Option<&gnap_types::key::KeyObject> {
    client.as_value()?.key.as_value()
}

/// Checks the supported proof method and the algorithm half of §7.3.1-M15,
/// and returns the `kid` the other half needs.
///
/// "If the signer's key presented is a JWK, the keyid parameter of the
/// signature MUST be set to the kid value of the JWK, and the signing algorithm
/// used MUST be the JWS algorithm denoted by the key's alg field of the JWK."
///
/// The algorithm is a property of the verifier, of which there is one, so it is
/// settled here. The `kid` is a property of each candidate signature, so it
/// travels down to where each one is judged: checking it against *some*
/// signature in the message would let a forged candidate carry the right name
/// while a different, genuinely valid one carried the wrong one.
///
/// Both come from the key the client presented, not from the resolver's word
/// for it: nothing stops a resolver from returning a verifier whose algorithm
/// is not the one the JWK declares.
fn check_presented_key<'a>(
    key: &'a gnap_types::key::KeyObject,
    verifier: &dyn gnap_crypto::proof::Verifier,
) -> Result<Option<&'a str>, HttpResponse> {
    if key.proof.method().as_str() != "httpsig" {
        return Err(error(
            ErrorCode::InvalidClient,
            "the presented key requires a proof method this server does not support \
             (RFC 9635 §2.3, §7.3)",
        ));
    }
    if let Some(declared) = key.jwk_algorithm() {
        // The JWS algorithm names are registered strings, so `ps256` is not
        // `PS256`; comparing loosely would accept a value the registry does
        // not contain.
        if declared != verifier.algorithm() {
            return Err(error(
                ErrorCode::InvalidClient,
                &format!(
                    "the key declares alg=`{declared}` but the signature would be verified \
                     with `{}`; the signing algorithm MUST be the one the JWK denotes \
                     (RFC 9635 §7.3.1)",
                    verifier.algorithm()
                ),
            ));
        }
    }
    Ok(key.jwk_key_id())
}

/// Checks that the AS can actually follow the callback the client asks for.
///
/// §4.2 makes following the finish method a MUST once one is associated with
/// the request. Announcing `interact.finish` and discovering at the end of the
/// interaction that the method or the hash algorithm is one this server does
/// not implement would strand a client whose RO has already answered, so the
/// request is refused before any of that happens.
fn supported_finish(finish: &InteractFinish) -> Result<(), String> {
    finish.validate().map_err(|e| e.to_string())?;

    if let InteractionFinishMethod::Unregistered(name) = &finish.method {
        return Err(format!(
            "`{name}` is not a finish method this server implements (RFC 9635 §2.5.2)"
        ));
    }
    if gnap_crypto::hash::HashMethod::from_name(finish.effective_hash_method()).is_none() {
        return Err(format!(
            "hash_method `{}` is not one this server implements; names come from the IANA \
             \"Named Information Hash Algorithm\" registry (RFC 9635 §4.2.3)",
            finish.effective_hash_method()
        ));
    }
    Ok(())
}

/// Reads what a continuation call is asking for (§5.1, §5.2, §5.3).
///
/// §5 gives each operation its own method and its own shape, so both decide
/// together: a POST with no content polls (§5.2), a POST carrying the reference
/// the AS issued returns from interaction (§5.1), and a PATCH carrying the
/// fields to change modifies the request (§5.3). Inferring the operation from
/// the fields alone would let one request be read as two different things
/// depending on who reads it.
///
/// # Errors
///
/// Fails when the content does not belong on the method used.
fn classify(
    modifying: bool,
    has_content: bool,
    continuation: &ContinueRequest,
) -> Result<Event, &'static str> {
    if modifying {
        // §5.3 — "the client instance makes an HTTP PATCH request to the
        // continuation URI and includes any fields it needs to modify."
        if !has_content {
            return Err(
                "a modification request carries the fields it needs to modify; this PATCH \
                 carries none (RFC 9635 §5.3)",
            );
        }
        // §5.3 — "The client instance MUST NOT include post-interaction
        // responses such as those described in Section 5.1."
        if continuation.interact_ref.is_some() {
            return Err(
                "a modification request carries an interaction reference; it MUST NOT \
                 include post-interaction responses (RFC 9635 §5.3)",
            );
        }
        return Ok(Event::Modify);
    }

    // §5.2 — "the client instance makes a POST request to the continuation URI
    // as in Section 5.1 but does not include message content."
    if !has_content {
        return Ok(Event::ContinuePoll);
    }

    // §5.1 — the only POST that carries content is the one returning the
    // reference the AS issued. An extension that defines another one is not
    // supported here, and saying so is better than guessing what it meant.
    let Some(reference) = &continuation.interact_ref else {
        return Err(
            "a POST to the continuation URI either polls with no content (RFC 9635 §5.2) \
             or returns from interaction with an interaction reference (§5.1); modifying \
             the request is a PATCH (§5.3)",
        );
    };
    if modifies(continuation) {
        return Err(
            "the request returns from interaction and modifies the grant at once; \
             modifying an existing request is a PATCH (RFC 9635 §5.3)",
        );
    }
    Ok(Event::ContinueWithInteractRef(reference.clone()))
}

/// Whether a continuation request changes what was asked for (§5.3).
///
/// Extension fields are deliberately not counted. Appendix D lets an extension
/// add fields to any message, including the §5.1 return, and reading one as a
/// modification would refuse a request the RFC allows. What an extension field
/// means is the extension's business; §5.3 names the four fields that modify a
/// request, and these are they.
const fn modifies(continuation: &ContinueRequest) -> bool {
    continuation.access_token.is_some()
        || continuation.subject.is_some()
        || continuation.interact.is_some()
        || continuation.user.is_some()
}

/// Applies a modification to the request on file (§5.3).
///
/// "Fields that aren't included in the request are considered unchanged from
/// the original request", so each present field replaces its counterpart and
/// the rest is left alone.
fn apply_modification(mut request: GrantRequest, continuation: ContinueRequest) -> GrantRequest {
    if let Some(access_token) = continuation.access_token {
        request.access_token = Some(access_token);
    }
    if let Some(subject) = continuation.subject {
        request.subject = Some(subject);
    }
    if let Some(interact) = continuation.interact {
        request.interact = Some(interact);
    }
    // §5.3-Y07 — the client may "present new assertions or information about
    // the end user". §5.3-S08 asks the AS to check the new information against
    // what it already has; that judgement belongs to the policy, which sees the
    // request this returns.
    if let Some(user) = continuation.user {
        request.user = Some(user);
    }
    // "Fields that aren't included in the request are considered unchanged from
    // the original request" applies to extension fields too: a key that is
    // present replaces its counterpart, the rest is left alone.
    request.extra.extend(continuation.extra);
    request
}

/// Whether a byte is `unreserved` as RFC 3986 §2.3 defines it.
const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Adds the callback parameters to a redirect URI (§4.2.1).
///
/// The client's URI may already carry a query of its own, which §2.5.2.1 does
/// not forbid, so the parameters are appended rather than assumed to be first.
fn with_callback_query(uri: &str, callback: &InteractCallback) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };
    format!(
        "{uri}{separator}hash={}&interact_ref={}",
        callback.hash, callback.interact_ref
    )
}

/// The answer to a continuation token that names no live grant (§5).
fn unknown_continuation() -> HttpResponse {
    error(
        ErrorCode::InvalidContinuation,
        "the continuation access token does not map to a single active grant request \
         (RFC 9635 §5)",
    )
}

/// A GNAP token in the HTTP credentials grammar (RFC 9110 §11.1, §11.4).
/// Authorization is not a list field: duplicate instances are ambiguous.
fn gnap_token(request: &HttpRequest) -> Option<&str> {
    let mut fields = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    let (_, value) = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let (scheme, token) = value.trim_matches([' ', '\t']).split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("GNAP") {
        return None;
    }
    let token = token.trim_start_matches(' ');
    TokenValue::new(token.to_owned()).ok()?;
    Some(token)
}

fn invalid_management_credentials() -> HttpResponse {
    error(
        ErrorCode::InvalidClient,
        "the token management credentials could not be validated (RFC 9635 §6)",
    )
}

/// An empty 204, as §5.4 requires of a successful revocation.
fn no_content() -> HttpResponse {
    HttpResponse {
        status: 204,
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: Vec::new(),
    }
}

/// A successful response, with the cache directive §3 requires.
fn ok(response: &GrantResponse) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            // §3 — "The AS MUST include the HTTP Cache-Control response
            // header field [RFC9111] with a value set to no-store."
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: serde_json::to_vec(response).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

/// An error response (§3.6).
fn error(code: ErrorCode, description: &str) -> HttpResponse {
    let response = GrantResponse {
        error: Some(GnapError::with_description(code, description)),
        ..Default::default()
    };
    HttpResponse {
        status: 400,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

/// The deployment handed the server something it cannot use.
///
/// Invalid generated values, endpoint configuration or policy output land here.
/// This is a technical failure, not an authoritative GNAP error response: no
/// grant change has been committed. In particular, a client must not mistake
/// this response for a denial that terminates its continuation.
fn misconfigured(what: &str) -> HttpResponse {
    HttpResponse {
        status: 500,
        headers: vec![
            ("Content-Type".into(), "text/plain; charset=utf-8".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: format!("server configuration: {what}").into_bytes(),
    }
}

/// Checks the content type §2 requires of a request that carries JSON.
///
/// §2-Y07 lets a key proofing mechanism define an alternative content type "as
/// long as the content is formed from the JSON object"; `httpsig` defines none,
/// so `application/json` is the only one this server accepts.
fn require_json_content(request: &HttpRequest) -> Result<(), HttpResponse> {
    // A body is what carries the JSON; a request without one (polling a
    // continuation) has no content type to check.
    if request.body.as_ref().is_none_or(Vec::is_empty) {
        return Ok(());
    }

    // The media type may carry parameters, `; charset=utf-8` being the common
    // one, so only the type itself is compared.
    let content_type = request.header_value("content-type").unwrap_or_default();
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(unsupported_media_type())
    }
}

/// 405, naming the methods the endpoint does answer.
fn method_not_allowed(allowed: &str) -> HttpResponse {
    HttpResponse {
        status: 405,
        headers: vec![
            ("Cache-Control".into(), "no-store".into()),
            ("Allow".into(), allowed.into()),
        ],
        body: Vec::new(),
    }
}

/// 415, for content that is not the JSON object §2 requires.
fn unsupported_media_type() -> HttpResponse {
    HttpResponse {
        status: 415,
        headers: vec![
            ("Cache-Control".into(), "no-store".into()),
            ("Accept".into(), "application/json".into()),
        ],
        body: Vec::new(),
    }
}

fn not_found() -> HttpResponse {
    HttpResponse {
        status: 404,
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: Vec::new(),
    }
}

// A transaction failure is not a committed GNAP decision. In particular, do not
// return a fabricated continuation or success whose indexes were never published.
fn storage_failure(failure: StoreError) -> HttpResponse {
    HttpResponse {
        status: match failure {
            StoreError::Invalid | StoreError::Collision => 500,
            _ => 503,
        },
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: Vec::new(),
    }
}
