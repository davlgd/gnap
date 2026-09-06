//! Real HTTP GNAP client/AS application. All records and credentials are synthetic.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Request, State},
    http::{uri::Authority, HeaderMap, Method, StatusCode, Uri, Version},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gnap_as::{
    AuthorizationServer, Decision, DerivedGrantStore, Endpoints, EvaluationContext, Finish,
    GrantAggregate, GrantId, GrantSelector, GrantSnapshot, GrantStore, KeyResolver, MemoryStorage,
    NonceStore, OsNonces, Policy, Revision, RotationNonceStore, StoreError,
};
use gnap_client::{sign_request, HttpRequest, HttpResponse, HttpTransport, Session};
use gnap_crypto::{httpsig::fresh_nonce, proof::Verifier, ps256::Ps256Signer};
use gnap_types::{
    access::AccessItem,
    client::Client,
    interact::InteractCallback,
    message::{ContinueRequest, GrantRequest},
    token::TokenValue,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU64,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_SESSIONS: usize = 64;
const MAX_GRANTS: usize = 256;
const SESSION_LIFETIME: Duration = Duration::from_secs(1200);
const FINISH_TIMEOUT: NonZeroU64 = NonZeroU64::new(300).unwrap();
const FOLDER_READ: &str = "synthetic-folder:read";
const ARCHIVE_READ: &str = "synthetic-archive:read";
mod derivation;
mod identity;
mod introspection;
mod multiple;
mod push_finish;
mod resource_registration;
mod secondary_device;
#[derive(Default)]
struct ConsentRegistry {
    push: push_finish::Registry,
    identity: Option<Arc<identity::Identity>>,
    clients: HashSet<String>,
    grants: HashMap<GrantId, Consent>,
}
struct Consent {
    decided_at: u64,
    request: GrantRequest,
    interaction_reference: Option<String>,
    as_nonce: Option<String>,
    allowed: multiple::Choice,
}
type Decisions = Arc<Mutex<ConsentRegistry>>;
type As = AuthorizationServer<ConsentPolicy, KnownKeys, Arc<IndexedStorage>, OsNonces>;

#[derive(Clone)]
struct CanonicalOrigin {
    value: String,
    scheme: String,
    authority: (String, u16),
}
impl CanonicalOrigin {
    fn listener_ip(&self) -> IpAddr {
        if self.scheme == "https" {
            Ipv4Addr::UNSPECIFIED.into()
        } else if self.authority.0 == "[::1]" {
            Ipv6Addr::LOCALHOST.into()
        } else {
            // The parser permits only localhost and 127.0.0.1 here. Do not
            // resolve localhost through DNS to choose a listening interface.
            Ipv4Addr::LOCALHOST.into()
        }
    }
    async fn bind(&self, port: u16) -> Result<tokio::net::TcpListener, &'static str> {
        tokio::net::TcpListener::bind((self.listener_ip(), port))
            .await
            .map_err(|_| "HTTP listener unavailable")
    }
    fn parse(value: &str) -> Result<Self, &'static str> {
        let parsed = reqwest::Url::parse(value).map_err(|_| "APP_ORIGIN must be a URL")?;
        if parsed.origin().ascii_serialization() != value
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(
                "APP_ORIGIN must use canonical spelling (lowercase host, no default port), \
                 without credentials, path, query, fragment or trailing slash",
            );
        }
        if parsed.scheme() != "https"
            && !(parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
        {
            return Err("Public deployments require HTTPS; HTTP is only allowed on loopback");
        }
        Ok(Self {
            value: value.into(),
            scheme: parsed.scheme().into(),
            authority: (
                parsed
                    .host_str()
                    .ok_or("APP_ORIGIN requires a host")?
                    .into(),
                parsed
                    .port_or_known_default()
                    .ok_or("APP_ORIGIN requires a port")?,
            ),
        })
    }

    fn authority(&self, value: &str) -> Result<(String, u16), StatusCode> {
        let invalid = StatusCode::BAD_REQUEST;
        if !value.is_ascii()
            || value
                .bytes()
                .any(|c| c.is_ascii_whitespace() || b"@\\%/?#".contains(&c))
            || value.ends_with(':')
        {
            return Err(invalid);
        }
        let authority: Authority = value.parse().map_err(|_| invalid)?;
        // Authority::port() returns None for an invalid port as well as an
        // absent one. Inspect the suffix so malformed ports cannot default.
        let suffix = &value[authority.host().len()..];
        let port = match suffix.strip_prefix(':') {
            Some(port) if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) => {
                port.parse::<u16>().map_err(|_| invalid)?
            }
            None if suffix.is_empty() => {
                if self.scheme == "https" {
                    443
                } else {
                    80
                }
            }
            _ => return Err(invalid),
        };
        Ok((authority.host().to_ascii_lowercase(), port))
    }

    fn matches_request(&self, request: &Request) -> Result<bool, StatusCode> {
        let mut hosts = request.headers().get_all("host").iter();
        let host = hosts.next();
        if hosts.next().is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let host = host
            .map(|h| self.authority(h.to_str().map_err(|_| StatusCode::BAD_REQUEST)?))
            .transpose()?;
        let uri_authority = request
            .uri()
            .authority()
            .map(|a| self.authority(a.as_str()))
            .transpose()?;
        if host.is_some() && uri_authority.is_some() && host != uri_authority {
            return Err(StatusCode::BAD_REQUEST);
        }
        // HTTP/1 requires Host even for an absolute-form request target. HTTP/2
        // may carry its authority solely in the URI's :authority component.
        if host.is_none() && request.version() != Version::HTTP_2 {
            return Err(StatusCode::BAD_REQUEST);
        }
        // TLS may terminate at a proxy: the backend scheme is not the public
        // scheme used to reconstruct signed URIs from APP_ORIGIN.
        if request
            .uri()
            .scheme_str()
            .is_some_and(|scheme| !matches!(scheme, "http" | "https"))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(host.or(uri_authority).ok_or(StatusCode::BAD_REQUEST)? == self.authority)
    }
}

fn request_target(uri: &Uri) -> &str {
    uri.path_and_query().map_or("/", |target| target.as_str())
}

async fn canonical_authority(
    State(origin): State<CanonicalOrigin>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/health" {
        return next.run(request).await;
    }
    match origin.matches_request(&request) {
        Ok(true) => next.run(request).await,
        Err(status) => status.into_response(),
        Ok(false) => {
            let navigation = path == "/"
                || path == "/callback"
                || path
                    .strip_prefix("/interact/")
                    .is_some_and(|handle| !handle.is_empty() && !handle.contains('/'));
            if navigation && matches!(*request.method(), Method::GET | Method::HEAD) {
                // Concatenate onto a configured origin, never resolve an
                // untrusted URL or decode/re-encode callback parameters.
                let destination = format!("{}{}", origin.value, request_target(request.uri()));
                (StatusCode::TEMPORARY_REDIRECT, [("location", destination)]).into_response()
            } else {
                StatusCode::MISDIRECTED_REQUEST.into_response()
            }
        }
    }
}

/// Only retention metadata is local: all credential indexes belong to the SDK.
/// The outer lock serializes maintenance and commits, never proof or network IO.
#[derive(Default)]
struct RetainedGrants {
    base: MemoryStorage,
    continuation_deadlines: HashMap<GrantId, u64>,
}
#[derive(Default)]
struct IndexedStorage {
    state: Mutex<RetainedGrants>,
    nonces: MemoryStorage,
    #[cfg(test)]
    before_exchange: Mutex<Option<ExchangeHook>>,
}
#[cfg(test)]
type ExchangeHook = Arc<dyn Fn(&GrantAggregate) + Send + Sync>;
impl RetainedGrants {
    fn cleanup(&mut self, now: u64) -> Result<(), StoreError> {
        // Bounded by MAX_GRANTS. No clone of a credential index or token TTL.
        let ids: Vec<_> = self.continuation_deadlines.keys().copied().collect();
        for id in ids {
            let snapshot = self
                .base
                .lookup(GrantSelector::Id(id))?
                .ok_or(StoreError::Invalid)?;
            let mut candidate = snapshot.aggregate;
            let previous_count = candidate.tokens.len();
            candidate.tokens.retain(|_, token| token.is_valid_at(now));
            let continuation_expired = self.continuation_deadlines[&id] <= now;
            if candidate.revoked
                || (candidate.tokens.is_empty()
                    && (candidate.record.continuation_token.is_none() || continuation_expired))
            {
                self.base.remove(id, snapshot.revision)?;
                self.continuation_deadlines.remove(&id);
            } else {
                let clear_continuation =
                    continuation_expired && candidate.record.continuation_token.is_some();
                if clear_continuation {
                    candidate.record.continuation_token = None;
                    candidate.record.interact_handle = None;
                    candidate.record.user_code = None;
                    candidate.record.interact_ref = None;
                    candidate.record.interact_expires_at = None;
                }
                if clear_continuation || previous_count != candidate.tokens.len() {
                    self.base
                        .compare_exchange(id, snapshot.revision, candidate)?;
                }
            }
        }
        Ok(())
    }
}
impl IndexedStorage {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RetainedGrants>, StoreError> {
        self.state.lock().map_err(|_| StoreError::Unavailable)
    }
    fn cleanup(&self) -> Result<(), StoreError> {
        self.lock()?.cleanup(now())
    }
}
impl GrantStore for IndexedStorage {
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        let mut state = self.lock()?;
        let now = now();
        state.cleanup(now)?;
        if state.continuation_deadlines.len() >= MAX_GRANTS {
            return Err(StoreError::Unavailable);
        }
        let deadline = now
            .checked_add(SESSION_LIFETIME.as_secs())
            .ok_or(StoreError::Exhausted)?;
        let snapshot = state.base.create(aggregate)?;
        state.continuation_deadlines.insert(snapshot.id, deadline);
        Ok(snapshot)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        let result = (|| {
            let mut state = self.lock()?;
            state.cleanup(now())?;
            state.base.lookup(selector)
        })();
        if result.is_err() {
            eprintln!("AS lookup unavailable");
        }
        result
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        #[cfg(test)]
        {
            let hook = self.before_exchange.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(&replacement);
            }
        }
        let mut state = self.lock()?;
        state.cleanup(now())?;
        // Neither a successful rewrite nor a refused CAS renews retention.
        state.base.compare_exchange(id, revision, replacement)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        let mut state = self.lock()?;
        state.base.remove(id, revision)?;
        state.continuation_deadlines.remove(&id);
        Ok(())
    }
}

impl DerivedGrantStore for IndexedStorage {
    fn create_derived(
        &self,
        parent: GrantId,
        revision: Revision,
        parent_value: &TokenValue,
        child: GrantAggregate,
        clock: &dyn Fn() -> u64,
    ) -> Result<GrantSnapshot, StoreError> {
        let mut state = self.lock()?;
        if state.continuation_deadlines.len() >= MAX_GRANTS {
            return Err(StoreError::Unavailable);
        }
        let deadline = clock().checked_add(60).ok_or(StoreError::Exhausted)?;
        let snapshot = state
            .base
            .create_derived(parent, revision, parent_value, child, clock)?;
        state.continuation_deadlines.insert(snapshot.id, deadline);
        Ok(snapshot)
    }
}
impl gnap_as::UserCodeStore for IndexedStorage {
    fn lookup_user_code(&self, code: &str) -> Result<Option<GrantSnapshot>, StoreError> {
        let mut state = self.lock()?;
        state.cleanup(now())?;
        gnap_as::UserCodeStore::lookup_user_code(&state.base, code)
    }
}
impl NonceStore for IndexedStorage {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.nonces.remember_nonce(nonce, now)
    }
}

impl RotationNonceStore for IndexedStorage {
    fn remember_nonce_pair(
        &self,
        previous: Option<&str>,
        replacement: Option<&str>,
        now: u64,
    ) -> bool {
        self.nonces.remember_nonce_pair(previous, replacement, now)
    }
}

struct ConsentPolicy(Decisions, Arc<gnap_as::MemoryResourceSetStore>);
fn requested_rights(
    request: &GrantRequest,
    resources: &gnap_as::MemoryResourceSetStore,
) -> Option<Vec<AccessItem>> {
    if request.client.as_reference() == Some(introspection::RS_ID) {
        return None;
    }
    let tokens = request.access_token.as_ref()?;
    if tokens.cardinality != gnap_types::token::Cardinality::Single || tokens.tokens.len() != 1 {
        return None;
    }
    resolve_rights(&tokens.tokens[0].access, resources)
}
/// Resolves one token's requested rights to the leaves this AS understands:
/// known leaves as they are, registered references to their leaves.
fn resolve_rights(
    rights: &[AccessItem],
    resources: &gnap_as::MemoryResourceSetStore,
) -> Option<Vec<AccessItem>> {
    use gnap_as::ResourceSetStore;
    if rights.is_empty() || rights.len() > 2 || (rights.len() == 2 && rights[0] == rights[1]) {
        return None;
    }
    let mut resolved = Vec::new();
    for right in rights {
        let leaves = if resource_registration::known_leaf(right) {
            vec![right.clone()]
        } else {
            let AccessItem::Reference(reference) = right else {
                return None;
            };
            let set = resources.lookup(reference).ok()??;
            if set.owner != gnap_as::RsId(resource_registration::RS_OWNER.into())
                || set.access.is_empty()
                || !set.access.iter().all(resource_registration::known_leaf)
            {
                return None;
            }
            set.access
        };
        for leaf in leaves {
            if !resolved.contains(&leaf) {
                resolved.push(leaf);
            }
        }
    }
    (resolved.len() <= 2).then_some(resolved)
}
impl Policy for ConsentPolicy {
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(1200)
    }
    fn keep_grant_open(&self, request: &GrantRequest) -> bool {
        request.subject.is_none() && !push_finish::is_push(request)
    }
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        if !push_finish::acceptable_request(request, &self.0.lock().unwrap().push) {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        }
        if !identity::acceptable_request(request, self.0.lock().unwrap().identity.as_deref()) {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        }
        if multiple::requested_slots(request, &self.1).is_some() {
            Decision::RequireInteraction
        } else {
            Decision::Deny(gnap_registry::ErrorCode::RequestDenied)
        }
    }
    fn evaluate_context(&self, request: &GrantRequest, context: EvaluationContext<'_>) -> Decision {
        if !push_finish::acceptable_request(request, &self.0.lock().unwrap().push) {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        }
        if !identity::acceptable_request(request, self.0.lock().unwrap().identity.as_deref()) {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        }
        let (Some(slots), Some(shape)) = (
            multiple::requested_slots(request, &self.1),
            request
                .access_token
                .as_ref()
                .map(|tokens| tokens.cardinality),
        ) else {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        };
        match context {
            EvaluationContext::Initial => Decision::RequireInteraction,
            // Within what is live for the same label: approved directly, as one
            // replacement lot. Anything else goes back to the resource owner.
            EvaluationContext::Modification(snapshot) => {
                if request.subject.is_some() || push_finish::is_push(request) {
                    Decision::Deny(gnap_registry::ErrorCode::RequestDenied)
                } else {
                    multiple::modification(shape, &slots, snapshot)
                }
            }
            EvaluationContext::AfterInteraction(snapshot) => {
                let choices = self.0.lock().unwrap();
                match choices.grants.get(&snapshot.id) {
                    Some(choice)
                        if choice.request == *request
                            && snapshot.aggregate.record.interact_ref
                                == choice.interaction_reference
                            && snapshot.aggregate.record.as_nonce == choice.as_nonce =>
                    {
                        let decision = multiple::decision(shape, &slots, &choice.allowed);
                        identity::release(
                            decision,
                            request,
                            choice.decided_at,
                            choices.identity.as_deref(),
                        )
                    }
                    _ => Decision::Deny(gnap_registry::ErrorCode::UserDenied),
                }
            }
        }
    }
}
fn client_id(client: &Client) -> String {
    client.as_reference().unwrap_or_default().to_owned()
}
struct KnownKeys {
    signer: Arc<Ps256Signer>,
    rs_key: gnap_types::key::KeyObject,
    decisions: Decisions,
}
impl KeyResolver for KnownKeys {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        if client.as_reference() == Some(introspection::RS_ID) {
            return gnap_crypto::Ps256Verifier::from_public_jwk(self.rs_key.jwk.as_ref()?)
                .ok()
                .map(|key| Box::new(key) as Box<dyn Verifier>);
        }
        self.decisions
            .lock()
            .unwrap()
            .clients
            .contains(&client_id(client))
            .then(|| Box::new(self.signer.verifier()) as Box<dyn Verifier>)
    }
}

/// Redirects are deliberately disabled: a signed request must not be forwarded.
struct Network {
    client: reqwest::blocking::Client,
    origin: String,
}
impl HttpTransport for Network {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let method =
            reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| e.to_string())?;
        let url = reqwest::Url::parse(&request.url).map_err(|e| e.to_string())?;
        let allowed = url.origin().ascii_serialization() == self.origin
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && (url.path() == "/gnap"
                || url.path() == "/continue"
                || url.path().starts_with("/token/")
                || matches!(
                    url.path(),
                    "/resource/folder"
                        | "/resource/archive"
                        | derivation::RS1_PATH
                        | multiple::REPORTS_PATH
                ));
        if !allowed {
            return Err("Network transport refused an endpoint outside this demo's fixed origin/path allow-list".into());
        }
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder.send().map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_owned()))
            .collect();
        let mut body = Vec::new();
        response
            .take(65_537)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if body.len() > 65_536 {
            return Err("AS response exceeds 64 KiB".into());
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[derive(Clone)]
struct App {
    origin: String,
    server: Arc<As>,
    storage: Arc<IndexedStorage>,
    // Test fixtures drive the client role without starting its browser worker.
    #[cfg(test)]
    signer: Arc<Ps256Signer>,
    decisions: Decisions,
    commands: mpsc::SyncSender<WorkerCommand>,
    push_outbound: Arc<tokio::sync::Semaphore>,
    starts: Arc<Mutex<VecDeque<Instant>>>,
    code_entries: Arc<Mutex<secondary_device::Entries>>,
    #[cfg(test)]
    code_completion_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    admission: Arc<tokio::sync::Semaphore>,
    resource_admission: Arc<tokio::sync::Semaphore>,
    metadata_admission: Arc<tokio::sync::Semaphore>,
    reports_admission: Arc<tokio::sync::Semaphore>,
    rs_registration: Arc<introspection::Registration>,
    resource_client: Arc<introspection::ResourceClient>,
    metadata_client: Arc<introspection::ResourceClient>,
    reports_client: Arc<introspection::ResourceClient>,
    bootstrap: resource_registration::Bootstrap,
}
struct Command {
    session: String,
    action: String,
    reply: tokio::sync::oneshot::Sender<Result<Value, String>>,
}
enum WorkerCommand {
    Browser(Command),
    Push(push_finish::Incoming),
}
struct BrowserSession<'a> {
    push: Option<push_finish::Registration>,
    identity: Option<Arc<identity::Identity>>,
    client: Session<'a, Network, Ps256Signer>,
    grant_id: GrantId,
    handle: String,
    code: Option<gnap_types::interact::UserCodeUri>,
    born: Instant,
    operations: usize,
    state: &'static str,
    events: Vec<String>,
    /// The token retired last, with the label it was managed under.
    retired: Option<multiple::Retired>,
    folder: Option<Value>,
    next_continuation: u64,
    continuation_open: bool,
    requested_rights: Vec<AccessItem>,
    /// What the current request asks for, slot by slot, as consent shows it.
    requested: Vec<multiple::Slot>,
    last_resource_status: Option<u16>,
    /// The flow this session started; actions select tokens by label in a lot.
    mode: multiple::Mode,
}

impl BrowserSession<'_> {
    fn received(
        &mut self,
        step: &gnap_client::Step,
        before: Option<multiple::Retired>,
    ) -> Result<(), String> {
        let response = step.response();
        self.continuation_open = response.r#continue.is_some();
        self.next_continuation = now().saturating_add(
            response
                .r#continue
                .as_ref()
                .and_then(|c| c.wait)
                .unwrap_or(0),
        );
        if let Some(uri) = response.interact.as_ref().and_then(|i| i.redirect.as_ref()) {
            self.handle = uri
                .rsplit('/')
                .next()
                .ok_or("Missing interaction handle")?
                .into();
            self.state = "pending";
        } else if self.code.is_some() && response.access_token.is_none() && self.state == "pending"
        {
            // A no-finish poll can return only a fresh continuation. It does
            // not turn a still-pending human-code request into an approval.
        } else {
            self.state = "approved";
        }
        if response.access_token.is_some() {
            self.code = None;
            // A replacement lot retires the primary token under its own label,
            // or nothing when the previous lot had no such token.
            self.retired = before;
            self.folder = None;
        }
        Ok(())
    }
}

/// The single-flow shorthand the existing tests use: everything or nothing.
#[cfg(test)]
fn consent_finish(
    server: &As,
    storage: &IndexedStorage,
    decisions: &Decisions,
    client: &str,
    grant: GrantId,
    handle: &str,
    allowed: bool,
) -> Result<String, String> {
    let choice = if allowed {
        multiple::Choice::All
    } else {
        multiple::Choice::Denied
    };
    consent_finish_choice(server, storage, decisions, client, grant, handle, choice)
}

/// Records the resource owner's choice for a pending grant: everything, a
/// named part of a lot, or nothing.
fn consent_finish_choice(
    server: &As,
    storage: &IndexedStorage,
    decisions: &Decisions,
    client: &str,
    grant: GrantId,
    handle: &str,
    allowed: multiple::Choice,
) -> Result<String, String> {
    match consent_complete_choice(server, storage, decisions, client, grant, handle, allowed)? {
        Finish::Redirect { uri } => Ok(uri),
        _ => Err("Unexpected completion method".into()),
    }
}

fn consent_complete_choice(
    server: &As,
    storage: &IndexedStorage,
    decisions: &Decisions,
    client: &str,
    grant: GrantId,
    handle: &str,
    allowed: multiple::Choice,
) -> Result<Finish, String> {
    let snapshot = storage
        .lookup(GrantSelector::Interaction(handle))
        .map_err(|_| "Consent storage unavailable")?
        .ok_or("Unknown interaction")?;
    if snapshot.id != grant || client_id(&snapshot.aggregate.record.request.client) != client {
        return Err("Interaction does not belong to this browser grant".into());
    }
    // Lock order: decisions, then storage. Storage never calls into decisions.
    // A concurrent post-completion poll must wait until its choice is visible.
    let mut choices = decisions.lock().map_err(|_| "Consent state unavailable")?;
    let finish = server
        .complete_interaction(handle, now())
        .map_err(|_| "Interaction completion refused")?;
    let callback = match &finish {
        Finish::Redirect { uri } => InteractCallback::from_redirect(uri),
        Finish::Push { body, .. } => InteractCallback::from_push(body),
        _ => return Err("Unexpected completion method".into()),
    }
    .map_err(|_| "Invalid completion reference")?;
    // Completion's CAS must succeed first. The decision is read, not popped,
    // during policy evaluation: a later CAS conflict cannot consume consent.
    choices.grants.insert(
        grant,
        Consent {
            decided_at: now(),
            request: snapshot.aggregate.record.request,
            interaction_reference: Some(callback.interact_ref),
            as_nonce: snapshot.aggregate.record.as_nonce,
            allowed,
        },
    );
    Ok(finish)
}

fn now() -> u64 {
    gnap_types::unix_now()
}

fn browser_view(session: &BrowserSession<'_>, origin: &str) -> Value {
    let push_finish = push_finish::view(session.push.as_ref());
    let tokens = session.client.usable_tokens(now());
    let rights: Vec<_> = tokens
        .iter()
        .flatten()
        .flat_map(|t| t.access.iter().flatten())
        .collect();
    json!({
        "push_finish": push_finish,
        "identity_requested": session.identity.is_some(),
        "identity": identity::view(session, now()),
        "state": session.state,
        "mode": session.mode.name(),
        "events": session.events,
        "rights": rights,
        "tokens": multiple::view(tokens.as_ref()),
        "requested_rights": session.requested_rights,
        "requested_tokens": multiple::slots_view(&session.requested),
        "token_present": tokens.is_some(),
        "resource_available": true,
        "retired_token_present": session.retired.is_some(),
        "retired_token_label": session.retired.as_ref().and_then(|retired| retired.label.clone()),
        "folder": session.folder,
        "last_resource_status": session.last_resource_status,
        "user_code_uri": session.code,
        "interaction_uri": session.code.is_none().then(|| format!("{origin}/interact/{}", session.handle)),
        "continuation_open": session.continuation_open,
        "continuation_wait_seconds": session.next_continuation.saturating_sub(now()),
    })
}

fn client_session<'a>(
    transport: &'a Network,
    signer: &'a Ps256Signer,
    origin: &str,
) -> Session<'a, Network, Ps256Signer> {
    Session::new(transport, signer, format!("{origin}/gnap"))
        .supporting(&["redirect"])
        .with_finish_timeout(FINISH_TIMEOUT)
}

fn client_worker(
    origin: String,
    signer: Arc<Ps256Signer>,
    server: Arc<As>,
    storage: Arc<IndexedStorage>,
    decisions: Decisions,
    receiver: mpsc::Receiver<WorkerCommand>,
    references: resource_registration::References,
) {
    let transport = Network {
        client: reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("HTTP client"),
        origin: origin.clone(),
    };
    let mut sessions: HashMap<String, BrowserSession<'_>> = HashMap::new();
    loop {
        sessions.retain(|id, session| {
            let live = session.born.elapsed() < SESSION_LIFETIME;
            if !live {
                let mut decisions = decisions.lock().unwrap();
                decisions.clients.remove(id);
                decisions.push.remove_client(id);
                decisions.grants.remove(&session.grant_id);
            }
            live
        });
        let command = match receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(WorkerCommand::Browser(c)) => c,
            Ok(WorkerCommand::Push(incoming)) => {
                push_finish::process(&mut sessions, &decisions, incoming);
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let result = (|| -> Result<Value, String> {
            if multiple::is_start(&command.action) {
                let identity = if command.action == "start-identity" {
                    Some(decisions.lock().unwrap().identity.clone().ok_or("Identity assertions require this demo's HTTPS origin; local HTTP flows remain available")?)
                } else {
                    None
                };
                // The HTTP front door creates a fresh browser session ID for every start.
                // Reject an internal duplicate before changing consent or AS state.
                if sessions.contains_key(&command.session) {
                    return Err("Session already started; use a new browser identity".into());
                }
                if sessions.len() >= MAX_SESSIONS {
                    return Err("Demo busy: 64 active sessions; retry later".into());
                }
                decisions
                    .lock()
                    .unwrap()
                    .clients
                    .insert(command.session.clone());
                let codes = command.action == "start-code";
                let push = if command.action == "start-push" {
                    Some(
                        decisions
                            .lock()
                            .unwrap()
                            .push
                            .register(&command.session, &origin)?,
                    )
                } else {
                    None
                };
                let mut client = if codes {
                    Session::new(&transport, signer.as_ref(), format!("{origin}/gnap"))
                        .supporting(&["user_code_uri"])
                } else {
                    client_session(&transport, signer.as_ref(), &origin)
                };
                let mode = if command.action == "start-multiple" {
                    multiple::Mode::Multiple
                } else {
                    multiple::Mode::Single
                };
                let access_token = match mode {
                    multiple::Mode::Single => json!({"access": [&references.both]}),
                    multiple::Mode::Multiple => multiple::lot(&references, true),
                };
                let interact = if codes {
                    json!({"start":["user_code_uri"]})
                } else if let Some(push) = &push {
                    json!({"start":["redirect"], "finish":{"method":"push", "uri":push.uri, "nonce":fresh_nonce().map_err(|_| "Interaction randomness unavailable")?}})
                } else {
                    json!({"start": ["redirect"], "finish": {"method":"redirect", "uri":format!("{origin}/callback"), "nonce":fresh_nonce().map_err(|e| e.to_string())?}})
                };
                let mut grant: GrantRequest = serde_json::from_value(json!({
                    "client": command.session,
                    "access_token": access_token,
                    "interact": interact
                }))
                .map_err(|e| e.to_string())?;
                if identity.is_some() {
                    grant.subject = Some(
                        serde_json::from_value(identity::request()).expect("fixed subject request"),
                    );
                }
                let step = client.start(&grant, now()).map_err(|e| e.to_string())?;
                let interaction = step
                    .response()
                    .interact
                    .as_ref()
                    .ok_or("AS did not request consent")?;
                let code = interaction.user_code_uri.clone();
                let handle = if let Some(code) = &code {
                    // Co-located bookkeeping for session cleanup and event
                    // views only. A separate client uses the offered code/URI
                    // and signed polling; it cannot call the AS resolver.
                    server
                        .resolve_user_code(&code.code, now())
                        .map_err(|_| "Code lookup unavailable")?
                } else {
                    interaction
                        .redirect
                        .as_ref()
                        .and_then(|uri| uri.rsplit('/').next())
                        .ok_or("Missing interaction handle")?
                        .to_owned()
                };
                let grant_id = storage
                    .lookup(GrantSelector::Interaction(&handle))
                    .map_err(|_| "Grant storage unavailable")?
                    .ok_or("Unknown new grant")?
                    .id;
                if let Some(push) = &push {
                    decisions.lock().unwrap().push.bind(push, grant_id)?;
                }
                sessions.insert(
                    command.session.clone(),
                    BrowserSession {
                        push,
                        identity,
                        client,
                        grant_id,
                        handle,
                        code,
                        born: Instant::now(),
                        operations: 0,
                        state: "pending",
                        events: vec![
                            "Signed POST /gnap over HTTP: AS requests explicit consent.".into()
                        ],
                        retired: None,
                        folder: None,
                        continuation_open: true,
                        requested_rights: multiple::requested_leaves(&multiple::requested(
                            mode, true,
                        )),
                        requested: multiple::requested(mode, true),
                        last_resource_status: None,
                        mode,
                        next_continuation: now()
                            + step
                                .response()
                                .r#continue
                                .as_ref()
                                .and_then(|c| c.wait)
                                .unwrap_or(0),
                    },
                );
            }
            let session = sessions
                .get_mut(&command.session)
                .ok_or("Session missing or expired; start again")?;
            if command.action != "status" && !multiple::is_start(&command.action) {
                session.operations += 1;
                if session.operations > 40 {
                    return Err("Demo limit: 40 actions per session".into());
                }
            }
            match command.action.as_str() {
                "approve" | "deny" | "approve-reports" => {
                    if session.code.is_some() {
                        return Err(
                            "Enter the code in the separate resource-owner browser to decide"
                                .into(),
                        );
                    }
                    if session.state != "pending" {
                        return Err("Consent already completed".into());
                    }
                    let choice = multiple::Choice::from_action(&command.action)
                        .ok_or("Unknown consent choice")?;
                    if command.action == "approve-reports" {
                        // Checked before the interaction is completed, so a
                        // refusal here consumes nothing.
                        if session.mode != multiple::Mode::Multiple {
                            return Err("A partial approval needs a two-token request; this grant asked for one token".into());
                        }
                        if !session
                            .requested
                            .iter()
                            .any(|slot| slot.label.as_deref() == Some(multiple::REPORTS))
                        {
                            return Err("The current request does not ask for a reports token; approve or deny it as a whole".into());
                        }
                    }
                    if session.push.is_some() {
                        push_finish::complete(
                            &server,
                            &storage,
                            &decisions,
                            &command.session,
                            session,
                            choice,
                        )?;
                        session.state = "awaiting_push";
                        session.events.push("Resource owner completed consent. The AS will attempt one HTTP push; its delivery does not change the recorded decision.".into());
                        return Ok(browser_view(session, &origin));
                    }
                    let uri = consent_finish_choice(
                        &server,
                        &storage,
                        &decisions,
                        &command.session,
                        session.grant_id,
                        &session.handle,
                        choice,
                    )?;
                    session.events.push(format!(
                        "Resource owner explicitly chose {}. AS returns a bound callback.",
                        command.action
                    ));
                    session.state = "awaiting_callback";
                    return Ok(json!({"redirect": uri}));
                }
                action if action.starts_with("callback:") => {
                    if session.state != "awaiting_callback" {
                        return Err("Unexpected or replayed callback".into());
                    }
                    let callback =
                        InteractCallback::from_redirect(&action[9..]).map_err(|e| e.to_string())?;
                    session
                        .client
                        .accept_callback(&callback, now())
                        .map_err(|e| e.to_string())?;
                    session.state = "ready";
                    session.events.push("Client validated the interaction callback hash; continuation is now available.".into());
                }
                "continue" => {
                    let before =
                        multiple::primary(session.client.usable_tokens(now()), session.mode);
                    let step = match session.client.continue_grant(now()) {
                        Ok(s) => s,
                        Err(e) => {
                            if matches!(&e,gnap_client::ClientError::Server(e) if e.code == gnap_registry::ErrorCode::UserDenied)
                            {
                                session.state = "denied";
                                session.code = None;
                                session.continuation_open = false;
                                session.events.push("AS refused the request and closed continuation. Any previously issued tokens keep their own lifecycle; refusal is not revocation.".into());
                            } else {
                                return Err(e.to_string());
                            }
                            return Ok(browser_view(session, &origin));
                        }
                    };
                    session.received(&step, before)?;
                    session.events.push(if step.response().access_token.is_some() { "Signed continuation approved the requested rights and atomically replaced all earlier tokens." } else { "Signed POST poll renewed continuation without issuing another token or renewing its lifetime." }.into());
                }
                "downscope" | "expand" => {
                    if !matches!(session.state, "approved" | "revoked")
                        || !session.continuation_open
                    {
                        return Err("An open approved grant is required for this change".into());
                    }
                    let both = command.action == "expand";
                    let access_token = match session.mode {
                        multiple::Mode::Single => json!({"access": [if both {
                            &references.both
                        } else {
                            &references.folder
                        }]}),
                        multiple::Mode::Multiple => multiple::lot(&references, both),
                    };
                    let changes: ContinueRequest = serde_json::from_value(json!({"access_token":access_token, "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":format!("{origin}/callback"),"nonce":fresh_nonce().map_err(|_| "Interaction randomness unavailable")?}}})).map_err(|_| "Modification encoding failed")?;
                    let before =
                        multiple::primary(session.client.usable_tokens(now()), session.mode);
                    let step = session
                        .client
                        .modify_grant(&changes, now())
                        .map_err(|_| "Grant modification refused or AS unavailable")?;
                    if matches!(step, gnap_client::Step::Recoverable(_)) {
                        return Err(
                            "AS refused this modification; existing rights are unchanged".into(),
                        );
                    }
                    session.requested = multiple::requested(session.mode, both);
                    session.requested_rights = multiple::requested_leaves(&session.requested);
                    session.received(&step, before)?;
                    session.events.push(if session.state == "pending" { "Signed PATCH requested additional rights. A new interaction is required; previous tokens remain live while consent is pending." } else { "Signed PATCH reduced access to a subset of live approved rights. New tokens replaced the entire previous set without another consent prompt." }.into());
                }
                "rotate" | "rotate-reports" => {
                    let purpose = if command.action == "rotate-reports" {
                        multiple::REPORTS
                    } else {
                        multiple::DOCUMENTS
                    };
                    let held = session.client.usable_tokens(now()).unwrap_or_default();
                    let before = multiple::held(&held, session.mode, purpose)?.value.clone();
                    let label = multiple::label_for(session.mode, purpose);
                    let token = session
                        .client
                        .rotate_token(label, now())
                        .map_err(|e| e.to_string())?;
                    if token.value == before {
                        return Err("Rotation did not replace token value".into());
                    }
                    session.retired = Some(multiple::Retired {
                        value: before,
                        label: label.map(str::to_owned),
                    });
                    session.folder = None;
                    session.events.push(match label {
                        Some(label) => format!("Signed management POST over HTTP: the {label} token's access and management values rotated; its sibling is untouched."),
                        None => "Signed management POST over HTTP: access and management token values rotated.".into(),
                    });
                }
                "revoke" | "revoke-reports" => {
                    let purpose = if command.action == "revoke-reports" {
                        multiple::REPORTS
                    } else {
                        multiple::DOCUMENTS
                    };
                    let held = session.client.usable_tokens(now()).unwrap_or_default();
                    let retiring = multiple::held(&held, session.mode, purpose)?.value.clone();
                    let label = multiple::label_for(session.mode, purpose);
                    session
                        .client
                        .revoke_token(label, now())
                        .map_err(|e| e.to_string())?;
                    session.retired = Some(multiple::Retired {
                        value: retiring,
                        label: label.map(str::to_owned),
                    });
                    if !matches!(session.state, "pending" | "awaiting_callback" | "ready")
                        && session.client.usable_tokens(now()).is_none()
                    {
                        session.state = "revoked";
                    }
                    session.folder = None;
                    session.events.push(match label {
                        Some(label) => format!("Signed management DELETE over HTTP: AS confirmed revocation of the {label} token (204); its sibling keeps its own lifecycle."),
                        None => "Signed management DELETE over HTTP: AS confirmed revocation (204).".into(),
                    });
                }
                "revoke-grant" => {
                    let retiring =
                        multiple::primary(session.client.usable_tokens(now()), session.mode);
                    session
                        .client
                        .revoke_grant(now())
                        .map_err(|_| "Grant revocation refused or AS unavailable")?;
                    session.retired = retiring;
                    session.continuation_open = false;
                    session.state = "grant_revoked";
                    session.folder = None;
                    session.events.push("Signed DELETE on continuation revoked the grant and all its tokens atomically (204).".into());
                }
                "read" | "read-archive" | "read-metadata" | "read-reports" | "check-retired" => {
                    let retired = session.retired.clone();
                    let purpose = if command.action == "read-reports"
                        || (command.action == "check-retired"
                            && retired.as_ref().is_some_and(|retired| {
                                retired.label.as_deref() == Some(multiple::REPORTS)
                            })) {
                        multiple::REPORTS
                    } else {
                        multiple::DOCUMENTS
                    };
                    let token = if command.action == "check-retired" {
                        retired
                            .map(|retired| retired.value)
                            .ok_or("Rotate or revoke a token first")?
                    } else {
                        let held = session.client.usable_tokens(now()).unwrap_or_default();
                        multiple::held(&held, session.mode, purpose)?.value.clone()
                    };
                    let path = if command.action == "read-metadata" {
                        derivation::RS1_PATH
                    } else if command.action == "read-archive" {
                        "/resource/archive"
                    } else if purpose == multiple::REPORTS {
                        multiple::REPORTS_PATH
                    } else {
                        "/resource/folder"
                    };
                    let request = sign_request(
                        HttpRequest::new("GET", format!("{origin}{path}")),
                        signer.as_ref(),
                        Some(&token),
                        now(),
                    )
                    .map_err(|_| "Resource signing failed")?;
                    let response = transport.send(request)?;
                    session.last_resource_status = Some(response.status);
                    if response.status == 503 {
                        return Err("The RS could not complete an AS or downstream exchange (503). Access is refused temporarily; this does not establish token invalidity.".into());
                    }
                    if command.action == "check-retired" {
                        if response.status != 401 {
                            return Err(format!(
                                "Retired token unexpectedly returned {}",
                                response.status
                            ));
                        }
                        session.events.push(format!("A fresh valid signature with the retired {} token was rejected at {path} (401).", session.retired.as_ref().and_then(|retired| retired.label.as_deref()).unwrap_or("access")));
                    } else {
                        if !matches!(response.status, 200 | 401) {
                            return Err(format!(
                                "RS refused the resource request ({})",
                                response.status
                            ));
                        }
                        session.folder = Some(
                            serde_json::from_slice(&response.body).map_err(|e| e.to_string())?,
                        );
                        session.events.push(if response.status == 200 {
                            format!("Signed GET {path} returned 200: authenticated AS introspection, local client proof and the exact resource right were accepted.")
                        } else {
                            format!("Signed GET {path} returned 401: the AS did not establish an active token in this context, or the RS refused the proof or rights.")
                        });
                    }
                }
                "status" => {}
                action if multiple::is_start(action) => {}
                action if action.starts_with("interaction:") => {
                    if action[12..] != session.handle || session.state != "pending" {
                        return Err("Unknown interaction for this browser session".into());
                    }
                }
                _ => return Err("Unknown action".into()),
            }
            Ok(browser_view(session, &origin))
        })();
        if result.is_err()
            && multiple::is_start(&command.action)
            && !sessions.contains_key(&command.session)
        {
            let mut choices = decisions.lock().unwrap();
            choices.clients.remove(&command.session);
            choices.push.remove_client(&command.session);
        }
        let _ = command.reply.send(result);
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("gnap_demo=").map(str::to_owned))
        .filter(|s| {
            s.len() == 22
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
fn browser_origin(headers: &HeaderMap, origin: &str) -> bool {
    headers.get("origin").and_then(|v| v.to_str().ok()) == Some(origin)
}
fn allow_start(starts: &Mutex<VecDeque<Instant>>) -> bool {
    let mut starts = starts.lock().unwrap();
    while starts
        .front()
        .is_some_and(|s| s.elapsed() >= Duration::from_secs(60))
    {
        starts.pop_front();
    }
    if starts.len() >= 10 {
        return false;
    }
    starts.push_back(Instant::now());
    true
}

#[cfg(test)]
fn resource_request(
    origin: &str,
    token: &str,
    signer: &Ps256Signer,
) -> Result<HttpRequest, String> {
    let url = format!("{origin}/resource/folder");
    let token = TokenValue::new(token).map_err(|e| e.to_string())?;
    sign_request(HttpRequest::new("GET", url), signer, Some(&token), now())
        .map_err(|e| e.to_string())
}

/// A refused resource request is distinct from an unusable AS exchange.
/// An inactive introspection result does not establish why access was refused.
#[derive(Debug)]
enum ResourceError {
    Denied,
    Unavailable,
}
fn read_resource(app: &App, request: &HttpRequest) -> Result<Value, ResourceError> {
    read_resource_with_clock(app, request, now)
}

fn read_resource_with_clock(
    app: &App,
    request: &HttpRequest,
    clock: impl Fn() -> u64,
) -> Result<Value, ResourceError> {
    if request.url == format!("{}{}", app.origin, derivation::RS1_PATH) && request.method == "GET" {
        return derivation::read(&app.resource_client, request, clock);
    }
    if request.url == format!("{}{}", app.origin, derivation::RS2_PATH) && request.method == "GET" {
        app.metadata_client.authorize_profile(
            request,
            derivation::METADATA_READ,
            introspection::Profile::Metadata,
            clock,
        )?;
        return Ok(json!({"source":"synthetic-archive","document_count":1}));
    }
    if request.url == format!("{}{}", app.origin, multiple::REPORTS_PATH) && request.method == "GET"
    {
        app.reports_client.authorize_profile(
            request,
            multiple::REPORTS_READ,
            introspection::Profile::Reports,
            clock,
        )?;
        return Ok(
            json!({"reports":"synthetic-quarterly-summary","entries":[{"period":"Q1","status":"synthetic"}],"granted_right":multiple::REPORTS_READ,"decision_source":"authenticated AS introspection by the reports RS and local client proof"}),
        );
    }
    let right = match request.url.strip_prefix(&app.origin) {
        Some("/resource/folder") if request.method == "GET" => FOLDER_READ,
        Some("/resource/archive") if request.method == "GET" => ARCHIVE_READ,
        _ => return Err(ResourceError::Denied),
    };
    app.resource_client.authorize(request, right, clock)?;
    Ok(
        json!({"folder":if right == FOLDER_READ { "synthetic-project-orion" } else { "synthetic-archive" },"documents":[{"name":"readme.txt","content":"Synthetic documents only. This read was authorized by a live key-bound GNAP token."}],"granted_right":right,"decision_source":"authenticated AS introspection and local client proof"}),
    )
}
async fn resource(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let admission = if uri.path() == derivation::RS2_PATH {
        &app.metadata_admission
    } else if uri.path() == multiple::REPORTS_PATH {
        &app.reports_admission
    } else {
        &app.resource_admission
    };
    let Ok(permit) = admission.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let request = HttpRequest {
        method: method.to_string(),
        url: format!("{}{}", app.origin, request_target(&uri)),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().into()))
            .collect(),
        body: (!body.is_empty() || headers.contains_key("content-digest")).then(|| body.to_vec()),
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read_resource(&app, &request)
    })
    .await
    {
        Ok(Ok(folder)) => Json(folder).into_response(),
        Ok(Err(ResourceError::Unavailable)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"resource_unavailable"})),
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(Err(ResourceError::Denied)) => (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "GNAP")],
            Json(json!({"error":"invalid_token_or_proof"})),
        )
            .into_response(),
    }
}
async fn dispatch(app: &App, session: String, action: String) -> Result<Value, String> {
    let (reply, receiver) = tokio::sync::oneshot::channel();
    app.commands
        .try_send(WorkerCommand::Browser(Command {
            session: session.clone(),
            action,
            reply,
        }))
        .map_err(|_| "Demo queue full; retry shortly".to_owned())?;
    // A browser disconnect must not discard an already committed push. The
    // reply observer stays alive independently of this HTTP request future.
    let app = app.clone();
    tokio::spawn(async move {
        let result = receiver
            .await
            .map_err(|_| "Client worker unavailable".to_owned())?;
        push_finish::kick(&app, &session);
        result
    })
    .await
    .map_err(|_| "Client reply unavailable".to_owned())?
}
async fn action(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if !browser_origin(&headers, &app.origin) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"Origin must match APP_ORIGIN"})),
        )
            .into_response();
    }
    let action = uri.path().trim_start_matches("/api/");
    if ![
        "start",
        "start-code",
        "approve",
        "deny",
        "continue",
        "rotate",
        "revoke",
        "read",
        "check-retired",
        "downscope",
        "expand",
        "read-archive",
        "read-metadata",
        "revoke-grant",
        "start-multiple",
        "start-identity",
        "start-push",
        "approve-reports",
        "read-reports",
        "rotate-reports",
        "revoke-reports",
    ]
    .contains(&action)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let session = if multiple::is_start(action) {
        if !matches!(app.bootstrap.get(), Some(Ok(_))) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"Resource registration is not ready"})),
            )
                .into_response();
        }
        if !allow_start(&app.starts) {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":"Demo start limit: 10 per minute globally; retry in one minute"}))).into_response();
        }
        match fresh_nonce() {
            Ok(n) => n,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        match session_cookie(&headers) {
            Some(s) => s,
            None => return StatusCode::UNAUTHORIZED.into_response(),
        }
    };
    let result = dispatch(&app, session.clone(), action.into()).await;
    let mut response = match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error":e}))).into_response(),
    };
    if multiple::is_start(action) && response.status().is_success() {
        let secure = if app.origin.starts_with("https:") {
            "; Secure"
        } else {
            ""
        };
        response.headers_mut().insert(
            "set-cookie",
            format!("gnap_demo={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1200{secure}")
                .parse()
                .unwrap(),
        );
    }
    response
}
async fn status(State(app): State<App>, headers: HeaderMap) -> Response {
    if !matches!(app.bootstrap.get(), Some(Ok(_))) {
        return Json(json!({"state":resource_registration::state(&app.bootstrap),"events":[]}))
            .into_response();
    }
    let Some(session) = session_cookie(&headers) else {
        return Json(json!({"state":"new", "events":[]})).into_response();
    };
    match dispatch(&app, session, "status".into()).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error":e}))).into_response(),
    }
}
async fn callback(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let Some(session) = session_cookie(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match dispatch(
        &app,
        session,
        format!("callback:{}{}", app.origin, request_target(&uri)),
    )
    .await
    {
        Ok(_) => (StatusCode::SEE_OTHER, [("location", "/")]).into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            "Invalid, expired or replayed interaction callback",
        )
            .into_response(),
    }
}
async fn interaction(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let Some(session) = session_cookie(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let handle = uri.path().trim_start_matches("/interact/");
    match dispatch(&app, session, format!("interaction:{handle}")).await {
        Ok(_) => Html(include_str!("../static/index.html")).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn protocol(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(permit) = app.admission.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let request = HttpRequest {
        method: method.to_string(),
        url: format!("{}{}", app.origin, request_target(&uri)),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_owned()))
            .collect(),
        body: (!body.is_empty() || headers.contains_key("content-digest")).then(|| body.to_vec()),
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        app.storage.cleanup()?;
        Ok::<_, StoreError>(
            if matches!(
                uri.path(),
                "/.well-known/gnap-as-rs" | "/introspect" | resource_registration::PATH
            ) {
                introspection::handle(&app, &request, now())
            } else {
                let registration = &app.rs_registration;
                app.server.handle_grant_with_derivation(
                    &request,
                    &derivation::Requesters(registration),
                    registration.as_ref(),
                    &registration.derivation_nonces,
                    &now,
                )
            },
        )
    })
    .await;
    let Ok(result) = result else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let result = match result {
        Ok(response) => response,
        Err(error) => {
            eprintln!("Protocol store failure: {error}");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"storage_unavailable"})),
            )
                .into_response();
        }
    };
    let mut response = (
        StatusCode::from_u16(result.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        result.body,
    )
        .into_response();
    response.headers_mut().remove("content-type");
    for (name, value) in result.headers {
        if let (Ok(n), Ok(v)) = (name.parse::<axum::http::HeaderName>(), value.parse()) {
            response.headers_mut().append(n, v);
        }
    }
    response
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse::<u16>()
        .unwrap_or_else(|_| {
            eprintln!("Invalid PORT");
            std::process::exit(1);
        });
    let origin = std::env::var("APP_ORIGIN").unwrap_or_else(|_| format!("http://127.0.0.1:{port}"));
    let canonical = CanonicalOrigin::parse(&origin).unwrap_or_else(|reason| {
        // Do not echo the supplied URL: an invalid value may contain credentials.
        eprintln!("Invalid APP_ORIGIN: {reason}");
        std::process::exit(1);
    });
    eprintln!("Generating an ephemeral 2048-bit RSA client key; no fixtures or private key files are used.");
    let signer = Arc::new(
        Ps256Signer::generate(2048, "delegation-demo-ephemeral")
            .expect("OS randomness and RSA generation"),
    );
    let rs_signer = Arc::new(
        Ps256Signer::generate(2048, "delegation-demo-rs")
            .expect("OS randomness and RSA generation"),
    );
    let metadata_signer = Arc::new(
        Ps256Signer::generate(2048, "delegation-demo-metadata-rs")
            .expect("OS randomness and RSA generation"),
    );
    let reports_signer = Arc::new(
        Ps256Signer::generate(2048, "delegation-demo-reports-rs")
            .expect("OS randomness and RSA generation"),
    );
    let decisions: Decisions = Arc::default();
    decisions.lock().unwrap().identity =
        identity::Identity::generate(&origin, &signer).expect("Ephemeral subject configuration");
    let storage = Arc::new(IndexedStorage::default());
    let resources = resource_registration::store();
    let server = AuthorizationServer::new(
        ConsentPolicy(decisions.clone(), resources.clone()),
        KnownKeys {
            signer: signer.clone(),
            rs_key: introspection::public_key(&rs_signer),
            decisions: decisions.clone(),
        },
        storage.clone(),
        OsNonces,
        Endpoints {
            grant: format!("{origin}/gnap"),
            continuation: format!("{origin}/continue"),
            interaction: format!("{origin}/interact"),
            token_management: format!("{origin}/token"),
        },
    );
    // CanonicalOrigin has already restricted HTTP to explicit loopback hosts.
    // Local discovery is a labelled development deviation from RFC 9635 §9;
    // the production HTTPS path never opts in to this exception.
    let server = server
        .with_user_code_uri(format!("{origin}/code"))
        .expect("code entry URI");
    let server = Arc::new(if origin.starts_with("http:") {
        eprintln!("Development-only HTTP loopback discovery enabled; RFC 9635 §9 requires HTTPS in production.");
        server.with_development_http_discovery()
    } else {
        server
    });
    let (sender, receiver) = mpsc::sync_channel(32);
    let rs_registration = Arc::new(introspection::Registration {
        key: introspection::public_key(&rs_signer),
        metadata_key: introspection::public_key(&metadata_signer),
        reports_key: introspection::public_key(&reports_signer),
        client_key: introspection::public_key(&signer),
        decisions: decisions.clone(),
        nonces: MemoryStorage::default(),
        derivation_nonces: MemoryStorage::default(),
        resources,
    });
    let resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: rs_signer,
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let metadata_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: metadata_signer,
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let reports_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: reports_signer,
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let app = App {
        origin: origin.clone(),
        server: server.clone(),
        storage: storage.clone(),
        #[cfg(test)]
        signer: signer.clone(),
        decisions: decisions.clone(),
        commands: sender,
        push_outbound: Arc::new(tokio::sync::Semaphore::new(4)),
        starts: Arc::default(),
        code_entries: Arc::default(),
        #[cfg(test)]
        code_completion_hook: None,
        admission: Arc::new(tokio::sync::Semaphore::new(16)),
        resource_admission: Arc::new(tokio::sync::Semaphore::new(4)),
        metadata_admission: Arc::new(tokio::sync::Semaphore::new(4)),
        reports_admission: Arc::new(tokio::sync::Semaphore::new(4)),
        rs_registration,
        resource_client,
        metadata_client,
        reports_client,
        bootstrap: Arc::default(),
    };
    let worker_storage = storage.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        if let Err(error) = storage.cleanup() {
            eprintln!("Background store maintenance failed: {error}");
        }
    });
    let listener = canonical.bind(port).await.expect("listener initialization");
    let bootstrap_app = app.clone();
    let router = application_router(app, canonical);
    let serving = tokio::spawn(async move { axum::serve(listener, router).await });
    std::thread::spawn(move || {
        let started = Instant::now();
        let result = resource_registration::bootstrap(
            &bootstrap_app,
            || started.elapsed(),
            std::thread::sleep,
        )
        .and_then(|references| {
            if started.elapsed() < resource_registration::BUDGET {
                Ok(references)
            } else {
                Err("Resource registration bootstrap failed")
            }
        });
        let _ = bootstrap_app.bootstrap.set(result.clone());
        match result {
            Ok(references) => client_worker(
                origin,
                signer,
                server,
                worker_storage,
                decisions,
                receiver,
                references,
            ),
            Err(_) => {
                eprintln!("Resource registration bootstrap failed");
                std::process::exit(1);
            }
        }
    });
    eprintln!("GNAP delegation demo listening on PORT={port}; no credential values are logged.");
    serving
        .await
        .expect("HTTP server task")
        .expect("HTTP server");
}

fn application_router(app: App, canonical: CanonicalOrigin) -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("../static/index.html")) }))
        .route("/health", get(|State(app):State<App>| async move { Json(json!({"status":"ok", "bootstrap":resource_registration::state(&app.bootstrap), "profile":"GNAP HTTPSig client/AS demonstrator; not certification"})) }))
        .route("/api/status", get(status))
        .route("/code", get(secondary_device::entry))
        .route("/code/lookup", post(secondary_device::submit).layer(DefaultBodyLimit::max(1024)))
        .route("/code/consent", post(secondary_device::submit).layer(DefaultBodyLimit::max(1024)))
        .route("/code.js", get(|| async { ([("content-type", "text/javascript")], include_str!("../static/code.js")) }))
        .route("/api/{action}", post(action))
        .route("/callback", get(callback))
        .route("/push-callback/{id}", post(push_finish::receive).layer(DefaultBodyLimit::max(1024)))
        .route("/interact/{handle}", get(interaction))
        .route("/gnap", post(protocol).options(protocol))
        .route("/.well-known/gnap-as-rs", get(protocol))
        .route("/introspect", post(protocol))
        .route(resource_registration::PATH, post(protocol))
        .route("/continue", axum::routing::any(protocol))
        .route("/resource/folder", get(resource))
        .route("/resource/archive", get(resource))
        .route(derivation::RS1_PATH, get(resource))
        .route(derivation::RS2_PATH, get(resource))
        .route(multiple::REPORTS_PATH, get(resource))
        .route("/continue/{handle}", axum::routing::any(protocol))
        .route("/token/{handle}", axum::routing::any(protocol))
        .route("/app.js", get(|| async { ([("content-type", "text/javascript")], include_str!("../static/app.js")) }))
        .route_layer(axum::middleware::from_fn_with_state(canonical, canonical_authority))
        .layer(DefaultBodyLimit::max(65_536))
        .layer(axum::middleware::map_response(|mut response: Response| async move {
            let h = response.headers_mut();
            h.insert("cache-control", "no-store".parse().unwrap());
            h.insert("referrer-policy", "no-referrer".parse().unwrap());
            h.insert("x-content-type-options", "nosniff".parse().unwrap());
            h.insert("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'".parse().unwrap());
            response
        }))
        .with_state(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnap_as::{GrantRecord, TokenRecord};
    use tower::ServiceExt;

    #[tokio::test]
    async fn listener_is_loopback_for_local_http_and_reachable_by_https_proxy() {
        for (configured, ip, host) in [
            ("http://127.0.0.1:18080", "127.0.0.1", "127.0.0.1"),
            ("http://localhost:18080", "127.0.0.1", "localhost"),
            ("http://[::1]:18080", "::1", "[::1]"),
            ("https://demo.example", "0.0.0.0", "127.0.0.1"),
        ] {
            let origin = CanonicalOrigin::parse(configured).unwrap();
            let listener = origin
                .bind(0)
                .await
                .expect("listener regression requires IPv4 and IPv6 loopback");
            let address = listener.local_addr().unwrap();
            assert_eq!(address.ip(), ip.parse::<IpAddr>().unwrap());
            assert_ne!(address.port(), 0);
            let serving = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route("/health", get(|| async { "ok" })),
                )
                .await
                .unwrap();
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap()
                .get(format!("http://{host}:{}/health", address.port()))
                .send()
                .await;
            serving.abort();
            assert_eq!(response.unwrap().status(), 200);
        }
    }

    #[tokio::test]
    async fn actual_router_serves_discovery_and_does_not_redirect_options_aliases() {
        let app = test_app();
        let router =
            application_router(app, CanonicalOrigin::parse("https://demo.example").unwrap());
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/gnap")
                    .header("host", "demo.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(!response.headers().contains_key("gnap-development-only"));
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let discovery: gnap_types::message::AsDiscovery = serde_json::from_slice(&body).unwrap();
        assert_eq!(discovery.validate_for("https://demo.example/gnap"), Ok(()));
        assert_eq!(discovery.key_rotation_supported, Some(false));
        assert_eq!(
            discovery.interaction_start_modes_supported,
            Some(vec![
                gnap_registry::InteractionStartMode::Redirect,
                gnap_registry::InteractionStartMode::UserCode,
                gnap_registry::InteractionStartMode::UserCodeUri
            ])
        );
        let response = router
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/gnap")
                    .header("host", "alias.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
        assert!(!response.headers().contains_key("location"));
    }

    #[test]
    fn canonical_origin_rejects_ambiguous_configuration() {
        for value in [
            "https://demo.example/",
            "https://DEMO.example",
            "https://demo.example:443",
            "https://user@demo.example",
            "https://demo.example/path",
            "https://demo.example?next=x",
            "https://demo.example#fragment",
            "http://demo.example",
            "http://[::2]:18081",
            "ftp://demo.example",
        ] {
            assert!(CanonicalOrigin::parse(value).is_err(), "{value}");
        }
        assert!(CanonicalOrigin::parse("https://demo.example").is_ok());
        assert!(CanonicalOrigin::parse("http://127.0.0.1:18081").is_ok());
        assert!(CanonicalOrigin::parse("http://[::1]:18081").is_ok());
    }

    #[test]
    fn ipv6_authorities_preserve_the_bracketed_host_and_port() {
        for (value, host) in [
            ("http://[::1]:18081", "[::1]:18081"),
            ("https://[::1]", "[::1]"),
            ("https://[::1]:8443", "[::1]:8443"),
            ("https://[2001:db8::1]:8443", "[2001:db8::1]:8443"),
        ] {
            let origin = CanonicalOrigin::parse(value).unwrap();
            let parsed: Authority = host.parse().unwrap();
            assert_eq!(
                parsed.host(),
                reqwest::Url::parse(value).unwrap().host_str().unwrap()
            );
            for version in [Version::HTTP_11, Version::HTTP_2] {
                let request = Request::builder()
                    .version(version)
                    .uri(format!("{value}/api/status"))
                    .header("host", host)
                    .body(axum::body::Body::empty())
                    .unwrap();
                assert_eq!(origin.matches_request(&request), Ok(true));
            }
            for invalid in ["[::1]:", "[::1]:invalid", "[::1]:65536"] {
                assert_eq!(origin.authority(invalid), Err(StatusCode::BAD_REQUEST));
            }
            assert_ne!(origin.authority("[::1]:9443").unwrap(), origin.authority);
        }
    }

    #[test]
    fn authority_checks_host_uri_and_http_version_without_forwarded_trust() {
        let origin = CanonicalOrigin::parse("https://demo.example").unwrap();
        let build = |uri: &str, version, host: Option<&str>| {
            let mut request = Request::builder().uri(uri).version(version);
            if let Some(host) = host {
                request = request.header("host", host);
            }
            request.body(axum::body::Body::empty()).unwrap()
        };
        assert_eq!(
            origin.matches_request(&build("/", Version::HTTP_11, Some("DEMO.example:443"))),
            Ok(true)
        );
        assert_eq!(
            origin.matches_request(&build("/", Version::HTTP_11, Some("demo.example:444"))),
            Ok(false)
        );
        assert_eq!(
            origin.matches_request(&build(
                "https://demo.example/callback?a=%2F",
                Version::HTTP_2,
                None
            )),
            Ok(true)
        );
        assert_eq!(
            request_target(&"https://demo.example/callback?a=%2F".parse().unwrap()),
            "/callback?a=%2F"
        );
        assert_eq!(
            origin.matches_request(&build(
                "http://demo.example/",
                Version::HTTP_2,
                Some("demo.example")
            )),
            Ok(true)
        );
        for request in [
            build("/", Version::HTTP_11, None),
            build("/", Version::HTTP_2, None),
            build("https://demo.example/", Version::HTTP_11, None),
            build(
                "https://demo.example/",
                Version::HTTP_2,
                Some("other.example"),
            ),
            build("ftp://demo.example/", Version::HTTP_2, Some("demo.example")),
            build("/", Version::HTTP_11, Some("demo.example:invalid")),
            build("/", Version::HTTP_11, Some("demo.example:65536")),
            build("/", Version::HTTP_11, Some("demo.example:+443")),
            build("/", Version::HTTP_11, Some("demo.example:")),
            build("/", Version::HTTP_11, Some("user@demo.example")),
            build("/", Version::HTTP_11, Some("demo.example/path")),
            build("/", Version::HTTP_11, Some("%64emo.example")),
        ] {
            assert_eq!(
                origin.matches_request(&request),
                Err(StatusCode::BAD_REQUEST),
                "{:?}",
                request.uri()
            );
        }
        let mut duplicate = build("/", Version::HTTP_11, Some("demo.example"));
        duplicate
            .headers_mut()
            .append("host", "demo.example".parse().unwrap());
        assert_eq!(
            origin.matches_request(&duplicate),
            Err(StatusCode::BAD_REQUEST)
        );
        let mut forwarded = build("/", Version::HTTP_11, Some("alias.example"));
        forwarded.headers_mut().insert(
            "forwarded",
            "host=demo.example;proto=https".parse().unwrap(),
        );
        forwarded
            .headers_mut()
            .insert("x-forwarded-host", "demo.example".parse().unwrap());
        assert_eq!(origin.matches_request(&forwarded), Ok(false));
    }

    #[tokio::test]
    async fn router_canonicalizes_navigation_before_sessions_and_never_redirects_protocols() {
        // The command receiver is absent: reaching a session handler would fail.
        let app = test_app();
        let starts = app.starts.clone();
        let router =
            application_router(app, CanonicalOrigin::parse("https://demo.example").unwrap());
        for method in [Method::GET, Method::HEAD] {
            for target in [
                "/",
                "/interact/synthetic",
                "/callback?hash=a%2Bb%2F%3D&interact_ref=x%26y",
            ] {
                let response = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(target)
                            .header("host", "alias.example")
                            .header("forwarded", "host=attacker.invalid")
                            .header("x-forwarded-host", "attacker.invalid")
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
                assert_eq!(
                    response.headers()["location"],
                    format!("https://demo.example{target}")
                );
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert_eq!(response.headers()["referrer-policy"], "no-referrer");
                assert!(!response.headers().contains_key("set-cookie"));
            }
        }
        for (method, target) in [
            (Method::POST, "/api/start"),
            (Method::GET, "/api/status"),
            (Method::POST, "/gnap"),
            (Method::POST, "/continue"),
            (Method::GET, "/continue/handle"),
            (Method::DELETE, "/token/handle"),
            (Method::GET, "/resource/folder"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(target)
                        .header("host", "alias.example")
                        .header("origin", "https://demo.example")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{target}"
            );
            assert!(!response.headers().contains_key("location"));
            assert!(!response.headers().contains_key("set-cookie"));
        }
        assert!(starts.lock().unwrap().is_empty());
        for scheme in ["https", "http"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .version(Version::HTTP_2)
                        .uri(format!("{scheme}://demo.example/api/status"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        for (target, host, expected) in [
            ("/", Some("demo.example"), StatusCode::OK),
            ("/app.js", Some("demo.example"), StatusCode::OK),
            ("/api/status", Some("demo.example"), StatusCode::OK),
            (
                "/callback?hash=x",
                Some("demo.example"),
                StatusCode::UNAUTHORIZED,
            ),
            ("/", None, StatusCode::BAD_REQUEST),
            ("/health", None, StatusCode::OK),
            ("/health", Some("internal.example"), StatusCode::OK),
            ("/unknown", Some("alias.example"), StatusCode::NOT_FOUND),
        ] {
            let mut request = Request::builder().uri(target);
            if let Some(host) = host {
                request = request.header("host", host);
            }
            let response = router
                .clone()
                .oneshot(request.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{target}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            assert!(response.headers().contains_key("content-security-policy"));
        }
    }

    #[test]
    fn origin_check_is_exact_and_mandatory() {
        let mut headers = HeaderMap::new();
        assert!(!browser_origin(&headers, "https://demo.example"));
        headers.insert(
            "origin",
            "https://demo.example.attacker.invalid".parse().unwrap(),
        );
        assert!(!browser_origin(&headers, "https://demo.example"));
        headers.insert("origin", "https://demo.example".parse().unwrap());
        assert!(browser_origin(&headers, "https://demo.example"));
    }
    #[test]
    fn cookie_is_bounded_and_base64url_only() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "gnap_demo=bad-value".parse().unwrap());
        assert!(session_cookie(&headers).is_none());
        headers.insert(
            "cookie",
            "other=x; gnap_demo=abcdefghijklmnopqrstuv".parse().unwrap(),
        );
        assert_eq!(session_cookie(&headers).unwrap().len(), 22);
    }

    pub(super) fn test_app() -> App {
        test_app_at("https://demo.example")
    }
    pub(super) fn test_app_at(origin: &str) -> App {
        configured_test_app(origin, true)
    }
    pub(super) fn starting_app_at(origin: &str) -> App {
        configured_test_app(origin, false)
    }
    fn configured_test_app(origin: &str, ready: bool) -> App {
        let signer = Arc::new(Ps256Signer::generate(2048, "test-client").unwrap());
        let rs_signer = Arc::new(Ps256Signer::generate(2048, "test-rs").unwrap());
        let metadata_signer = Arc::new(Ps256Signer::generate(2048, "test-metadata-rs").unwrap());
        let reports_signer = Arc::new(Ps256Signer::generate(2048, "test-reports-rs").unwrap());
        let storage = Arc::new(IndexedStorage::default());
        let resources = resource_registration::store();
        let bootstrap = Arc::new(std::sync::OnceLock::new());
        if ready {
            bootstrap
                .set(Ok(resource_registration::fixture(&resources)))
                .unwrap();
        }
        let decisions: Decisions = Arc::default();
        decisions
            .lock()
            .unwrap()
            .clients
            .insert("test-client".into());
        let server = AuthorizationServer::new(
            ConsentPolicy(decisions.clone(), resources.clone()),
            KnownKeys {
                signer: signer.clone(),
                rs_key: introspection::public_key(&rs_signer),
                decisions: decisions.clone(),
            },
            storage.clone(),
            OsNonces,
            Endpoints {
                grant: format!("{origin}/gnap"),
                continuation: format!("{origin}/continue"),
                interaction: format!("{origin}/interact"),
                token_management: format!("{origin}/token"),
            },
        );
        let server = server.with_user_code_uri(format!("{origin}/code")).unwrap();
        let server = Arc::new(if origin.starts_with("http:") {
            server.with_development_http_discovery()
        } else {
            server
        });
        let (commands, _) = mpsc::sync_channel(1);
        let rs_registration = Arc::new(introspection::Registration {
            key: introspection::public_key(&rs_signer),
            metadata_key: introspection::public_key(&metadata_signer),
            reports_key: introspection::public_key(&reports_signer),
            client_key: introspection::public_key(&signer),
            decisions: decisions.clone(),
            nonces: MemoryStorage::default(),
            derivation_nonces: MemoryStorage::default(),
            resources,
        });
        let resource_client = Arc::new(introspection::ResourceClient {
            origin: origin.into(),
            signer: rs_signer,
            transport: Arc::new(introspection::Direct {
                server: server.clone(),
                storage: storage.clone(),
                registration: rs_registration.clone(),
                origin: origin.into(),
            }),
            nonces: MemoryStorage::default(),
        });
        let metadata_client = Arc::new(introspection::ResourceClient {
            origin: origin.into(),
            signer: metadata_signer,
            transport: Arc::new(introspection::Http {
                origin: origin.into(),
            }),
            nonces: MemoryStorage::default(),
        });
        let reports_client = Arc::new(introspection::ResourceClient {
            origin: origin.into(),
            signer: reports_signer,
            transport: Arc::new(introspection::Http {
                origin: origin.into(),
            }),
            nonces: MemoryStorage::default(),
        });
        App {
            origin: origin.into(),
            server,
            storage,
            signer,
            decisions,
            commands,
            push_outbound: Arc::new(tokio::sync::Semaphore::new(4)),
            starts: Arc::default(),
            code_entries: Arc::default(),
            code_completion_hook: None,
            admission: Arc::new(tokio::sync::Semaphore::new(2)),
            resource_admission: Arc::new(tokio::sync::Semaphore::new(2)),
            metadata_admission: Arc::new(tokio::sync::Semaphore::new(2)),
            reports_admission: Arc::new(tokio::sync::Semaphore::new(2)),
            rs_registration,
            resource_client,
            metadata_client,
            reports_client,
            bootstrap,
        }
    }
    pub(super) fn test_record(value: &str) -> TokenRecord {
        TokenRecord {
            derivation: None,
            identifier: None,
            issued_at: now(),
            token: serde_json::from_value(
                json!({"value":value,"access":["synthetic-folder:read"],"expires_in":1200}),
            )
            .unwrap(),
            client: serde_json::from_value(json!("test-client")).unwrap(),
            management_token: format!("management-{value}"),
        }
    }
    pub(super) fn test_aggregate(handle: &str, token: TokenRecord) -> GrantAggregate {
        let mut aggregate = GrantAggregate::new(GrantRecord {
            grant: Default::default(),
            request: serde_json::from_value(json!({"client":"test-client"})).unwrap(),
            continuation_token: None,
            as_nonce: None,
            user_code: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        });
        aggregate.tokens.insert(handle.into(), token);
        aggregate
    }
    #[test]
    fn resource_requires_live_bound_token_and_rejects_replays_and_management_tokens() {
        let app = test_app();
        let store = app.storage.clone();
        let snapshot = store
            .create(test_aggregate("handle", test_record("access-one")))
            .unwrap();
        assert!(read_resource(
            &app,
            &HttpRequest::new("GET", "https://demo.example/resource/folder")
        )
        .is_err());
        let request = resource_request(&app.origin, "access-one", &app.signer).unwrap();
        assert!(read_resource(&app, &request).is_ok());
        assert!(read_resource(&app, &request).is_err());
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "management-access-one", &app.signer).unwrap()
        )
        .is_err());
        let other = Ps256Signer::generate(2048, "test-client").unwrap();
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-one", &other).unwrap()
        )
        .is_err());
        let mut replacement = snapshot.aggregate.clone();
        replacement.tokens.clear();
        replacement
            .tokens
            .insert("new-handle".into(), test_record("access-two"));
        let rotated = store
            .compare_exchange(snapshot.id, snapshot.revision, replacement)
            .unwrap();
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-one", &app.signer).unwrap()
        )
        .is_err());
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-two", &app.signer).unwrap()
        )
        .is_ok());
        let mut replacement = rotated.aggregate.clone();
        replacement.tokens.clear();
        store
            .compare_exchange(rotated.id, rotated.revision, replacement)
            .unwrap();
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-two", &app.signer).unwrap()
        )
        .is_err());
        assert!(store
            .lookup(GrantSelector::AccessToken("access-two"))
            .unwrap()
            .is_none());
    }
    #[test]
    fn expiry_is_enforced_before_background_cleanup_and_wrong_rights_fail() {
        let app = test_app();
        let store = app.storage.clone();
        let mut expired = test_record("access-expired");
        expired.issued_at = now().saturating_sub(1200);
        store.create(test_aggregate("expired", expired)).unwrap();
        assert!(
            store
                .lock()
                .unwrap()
                .base
                .lookup(GrantSelector::Management("expired"))
                .unwrap()
                .is_some(),
            "no sweep has run"
        );
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-expired", &app.signer).unwrap()
        )
        .is_err());
        assert!(store
            .lookup(GrantSelector::Management("expired"))
            .unwrap()
            .is_none());
        assert!(store
            .lookup(GrantSelector::AccessToken("access-expired"))
            .unwrap()
            .is_none());
        let mut record = test_record("wrong-right");
        record.token.access = Some(vec![AccessItem::Reference("other:read".into())]);
        store.create(test_aggregate("wrong", record)).unwrap();
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "wrong-right", &app.signer).unwrap()
        )
        .is_err());
    }
    #[test]
    fn concurrent_replay_has_one_winner() {
        let app = test_app();
        app.storage
            .create(test_aggregate("h", test_record("access-one")))
            .unwrap();
        let request = resource_request(&app.origin, "access-one", &app.signer).unwrap();
        let successes = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| read_resource(&app, &request).is_ok()))
                .collect();
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 1);
    }
    #[test]
    fn rate_limit_recovers_after_window() {
        let starts = Mutex::new(VecDeque::new());
        for _ in 0..10 {
            assert!(allow_start(&starts));
        }
        assert!(!allow_start(&starts));
        starts
            .lock()
            .unwrap()
            .iter_mut()
            .for_each(|i| *i -= Duration::from_secs(61));
        assert!(allow_start(&starts));
    }

    #[test]
    fn restoring_a_record_does_not_renew_its_sdk_deadline() {
        let storage = IndexedStorage::default();
        let mut original = test_record("access-one");
        original.issued_at = now().saturating_sub(600);
        let deadline = original.expires_at();
        let snapshot = storage
            .create(test_aggregate("handle", original.clone()))
            .unwrap();
        // An earlier deadline makes an accidental reset observable even when
        // create and CAS happen within the same wall-clock second.
        let retention = now() + 600;
        storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .insert(snapshot.id, retention);
        let rewritten = storage
            .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate.clone())
            .unwrap();
        assert!(matches!(
            storage.compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate),
            Err(StoreError::Conflict)
        ));
        assert_eq!(
            storage.lock().unwrap().continuation_deadlines[&snapshot.id],
            retention
        );
        let restored = &rewritten.aggregate.tokens["handle"];
        assert_eq!(restored.issued_at, original.issued_at);
        assert_eq!(restored.expires_at(), deadline);
        assert_eq!(restored.token, original.token);
        storage.cleanup().unwrap();
        assert!(storage
            .lookup(GrantSelector::Management("handle"))
            .unwrap()
            .is_some());
        original.issued_at = now().saturating_sub(1200);
        let mut replacement = rewritten.aggregate;
        replacement.tokens.insert("handle".into(), original);
        storage
            .compare_exchange(rewritten.id, rewritten.revision, replacement)
            .unwrap();
        storage.cleanup().unwrap();
        assert!(storage
            .lookup(GrantSelector::Management("handle"))
            .unwrap()
            .is_none());
        assert!(storage
            .lookup(GrantSelector::AccessToken("access-one"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn resource_rechecks_expiration_after_signature_verification() {
        let app = test_app();
        let record = test_record("access-one");
        let issued_at = record.issued_at;
        app.storage
            .create(test_aggregate("handle", record))
            .unwrap();
        let request = resource_request(&app.origin, "access-one", &app.signer).unwrap();
        let calls = std::cell::Cell::new(0);
        let clock = || {
            let call = calls.get();
            calls.set(call + 1);
            if call < 2 {
                issued_at
            } else {
                issued_at + 1200
            }
        };
        assert!(read_resource_with_clock(&app, &request, clock).is_err());
        assert_eq!(
            calls.get(),
            3,
            "checked again after successful proof verification"
        );
        // A remote RS enforces the returned deadline; it does not mutate AS
        // storage using its own clock. AS maintenance uses the AS's clock.
        assert!(app
            .storage
            .lookup(GrantSelector::AccessToken("access-one"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn aggregate_capacity_refuses_new_grants_without_evicting_live_tokens() {
        let storage = IndexedStorage::default();
        for index in 0..MAX_GRANTS {
            storage
                .create(test_aggregate(
                    &format!("handle-{index}"),
                    test_record(&format!("access-{index}")),
                ))
                .unwrap();
        }
        assert!(matches!(
            storage.create(test_aggregate("overflow", test_record("overflow"))),
            Err(StoreError::Unavailable)
        ));
        assert_eq!(
            storage.lock().unwrap().continuation_deadlines.len(),
            MAX_GRANTS
        );
        assert!(storage
            .lookup(GrantSelector::AccessToken("access-0"))
            .unwrap()
            .is_some());
        assert!(storage
            .lookup(GrantSelector::AccessToken("overflow"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn continuation_retention_does_not_shorten_a_live_token_or_renew_on_cas() {
        let storage = IndexedStorage::default();
        let mut aggregate = test_aggregate("handle", test_record("access"));
        aggregate.record.continuation_token = Some("continue-secret".into());
        aggregate.record.interact_handle = Some("interaction".into());
        aggregate.record.interact_expires_at = Some(now() + 60);
        let snapshot = storage.create(aggregate).unwrap();
        // Simulate the original continuation deadline having elapsed while a
        // recently issued/rotated token still has its own SDK lifetime.
        storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .insert(snapshot.id, now().saturating_sub(1));
        storage.cleanup().unwrap();
        let current = storage
            .lookup(GrantSelector::AccessToken("access"))
            .unwrap()
            .unwrap();
        assert!(current.aggregate.record.continuation_token.is_none());
        assert!(current.aggregate.record.interact_expires_at.is_none());
        assert!(storage
            .lookup(GrantSelector::Continuation("continue-secret"))
            .unwrap()
            .is_none());
        assert!(storage
            .lookup(GrantSelector::Interaction("interaction"))
            .unwrap()
            .is_none());
        assert_eq!(
            current.aggregate.tokens["handle"].issued_at,
            snapshot.aggregate.tokens["handle"].issued_at
        );
        assert!(matches!(
            storage.compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate),
            Err(StoreError::Conflict)
        ));
        assert!(storage
            .lookup(GrantSelector::AccessToken("access"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn cleanup_removes_all_indexes_and_stale_cas_cannot_resurrect() {
        let storage = IndexedStorage::default();
        let mut aggregate = test_aggregate("handle", test_record("access"));
        aggregate.tokens.clear();
        aggregate.record.continuation_token = Some("continuation".into());
        aggregate.record.interact_handle = Some("interaction".into());
        let snapshot = storage.create(aggregate).unwrap();
        storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .insert(snapshot.id, 0);
        storage.cleanup().unwrap();
        assert!(storage
            .lookup(GrantSelector::Id(snapshot.id))
            .unwrap()
            .is_none());
        assert!(storage
            .lookup(GrantSelector::Continuation("continuation"))
            .unwrap()
            .is_none());
        assert!(storage
            .lookup(GrantSelector::Interaction("interaction"))
            .unwrap()
            .is_none());
        assert!(matches!(
            storage.compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate),
            Err(StoreError::Conflict)
        ));
        let next = storage
            .create(test_aggregate("next", test_record("next")))
            .unwrap();
        assert_ne!(next.id, snapshot.id);
    }

    #[test]
    fn an_introspection_already_decided_can_race_revocation_but_next_read_is_denied() {
        let app = test_app();
        for rotate in [true, false] {
            let snapshot = app
                .storage
                .create(test_aggregate("handle", test_record("access")))
                .unwrap();
            let request = resource_request(&app.origin, "access", &app.signer).unwrap();
            let calls = std::cell::Cell::new(0);
            let result = read_resource_with_clock(&app, &request, || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    // The authenticated response is already received. A
                    // network RS cannot retroactively withdraw that decision.
                    let mut replacement = snapshot.aggregate.clone();
                    replacement.tokens.clear();
                    if rotate {
                        replacement
                            .tokens
                            .insert("new-handle".into(), test_record("new-access"));
                    } else {
                        replacement.revoked = true;
                    }
                    app.storage
                        .compare_exchange(snapshot.id, snapshot.revision, replacement)
                        .unwrap();
                }
                now()
            });
            assert!(result.is_ok());
            assert_eq!(calls.get(), 3);
            let fresh = resource_request(&app.origin, "access", &app.signer).unwrap();
            assert!(matches!(
                read_resource(&app, &fresh),
                Err(ResourceError::Denied)
            ));
            if let Some(current) = app.storage.lookup(GrantSelector::Id(snapshot.id)).unwrap() {
                app.storage.remove(current.id, current.revision).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn store_failures_are_503_not_authentication_failures_or_secret_reflections() {
        use tower::ServiceExt;
        let app = test_app();
        let storage = app.storage.clone();
        let _ = std::panic::catch_unwind(|| {
            let _guard = storage.state.lock().unwrap();
            panic!("synthetic storage failure");
        });
        assert!(matches!(
            storage.lookup(GrantSelector::AccessToken("secret")),
            Err(StoreError::Unavailable)
        ));
        let router =
            application_router(app, CanonicalOrigin::parse("https://demo.example").unwrap());
        for (method, path) in [("GET", "/resource/folder"), ("POST", "/gnap")] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(path)
                        .header("host", "demo.example")
                        .header("authorization", "GNAP secret-not-for-reflection")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(!response.headers().contains_key("www-authenticate"));
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"error":if path == "/resource/folder" {"resource_unavailable"} else {"storage_unavailable"}})
            );
        }
    }
}

#[cfg(test)]
mod derivation_tests;
#[cfg(test)]
mod finish_timeout_tests;
#[cfg(test)]
mod introspection_tests;
#[cfg(test)]
mod multiple_tests;
#[cfg(test)]
mod ongoing_tests;
#[cfg(test)]
mod registration_tests;
