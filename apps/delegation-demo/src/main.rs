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
    AuthorizationServer, Decision, Endpoints, EvaluationContext, Finish, GrantAggregate, GrantId,
    GrantSelector, GrantSnapshot, GrantStore, KeyResolver, MemoryStorage, NonceStore, OsNonces,
    Policy, Revision, StoreError,
};
use gnap_client::{sign_request, HttpRequest, HttpResponse, HttpTransport, Session};
use gnap_crypto::{
    httpsig::fresh_nonce,
    proof::Verifier,
    ps256::Ps256Signer,
    verify::{verify_request, Expectations, SignedRequest},
};
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
const FOLDER_READ: &str = "synthetic-folder:read";
const ARCHIVE_READ: &str = "synthetic-archive:read";
#[derive(Default)]
struct ConsentRegistry {
    clients: HashSet<String>,
    grants: HashMap<GrantId, Consent>,
}
struct Consent {
    request: GrantRequest,
    interaction_reference: String,
    allowed: bool,
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
    resource_nonces: MemoryStorage,
}
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
        let mut state = self.lock()?;
        state.cleanup(now())?;
        state.base.lookup(selector)
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
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
impl NonceStore for IndexedStorage {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.nonces.remember_nonce(nonce, now)
    }
}

struct ConsentPolicy(Decisions);
fn requested_rights(request: &GrantRequest) -> Option<Vec<AccessItem>> {
    let tokens = &request.access_token.as_ref()?.tokens;
    if tokens.len() != 1 {
        return None;
    }
    let rights = &tokens[0].access;
    if rights.is_empty() || rights.len() > 2 || rights.iter().any(|r| !matches!(r, AccessItem::Reference(v) if matches!(v.as_str(), FOLDER_READ | ARCHIVE_READ))) || (rights.len() == 2 && rights[0] == rights[1]) {
        return None;
    }
    Some(rights.clone())
}
impl Policy for ConsentPolicy {
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(1200)
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        if requested_rights(request).is_some() {
            Decision::RequireInteraction
        } else {
            Decision::Deny(gnap_registry::ErrorCode::RequestDenied)
        }
    }
    fn evaluate_context(&self, request: &GrantRequest, context: EvaluationContext<'_>) -> Decision {
        let Some(rights) = requested_rights(request) else {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        };
        match context {
            EvaluationContext::Initial => Decision::RequireInteraction,
            EvaluationContext::Modification(snapshot) => {
                let time = now();
                let live_rights: Vec<_> = snapshot
                    .aggregate
                    .tokens
                    .values()
                    .filter(|t| t.is_valid_at(time))
                    .flat_map(|t| t.token.access.iter().flatten())
                    .collect();
                if rights.iter().all(|r| live_rights.contains(&r)) {
                    Decision::Approve {
                        access: rights,
                        subject: None,
                    }
                } else {
                    Decision::RequireInteraction
                }
            }
            EvaluationContext::AfterInteraction(snapshot) => {
                let choices = self.0.lock().unwrap();
                match choices.grants.get(&snapshot.id) {
                    Some(choice)
                        if choice.allowed
                            && choice.request == *request
                            && snapshot.aggregate.record.interact_ref.as_deref()
                                == Some(&choice.interaction_reference) =>
                    {
                        Decision::Approve {
                            access: rights,
                            subject: None,
                        }
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
    decisions: Decisions,
}
impl KeyResolver for KnownKeys {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
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
                || matches!(url.path(), "/resource/folder" | "/resource/archive"));
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
    signer: Arc<Ps256Signer>,
    decisions: Decisions,
    commands: mpsc::SyncSender<Command>,
    starts: Arc<Mutex<VecDeque<Instant>>>,
    admission: Arc<tokio::sync::Semaphore>,
}
struct Command {
    session: String,
    action: String,
    reply: tokio::sync::oneshot::Sender<Result<Value, String>>,
}
struct BrowserSession<'a> {
    client: Session<'a, Network, Ps256Signer>,
    grant_id: GrantId,
    handle: String,
    born: Instant,
    operations: usize,
    state: &'static str,
    events: Vec<String>,
    retired_token: Option<gnap_types::token::TokenValue>,
    folder: Option<Value>,
    next_continuation: u64,
    continuation_open: bool,
    requested_rights: Vec<AccessItem>,
    last_resource_status: Option<u16>,
}

impl BrowserSession<'_> {
    fn received(
        &mut self,
        step: &gnap_client::Step,
        before: Option<TokenValue>,
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
        } else {
            self.state = "approved";
        }
        if response.access_token.is_some() {
            self.retired_token = before;
            self.folder = None;
        }
        Ok(())
    }
}

fn consent_finish(
    server: &As,
    storage: &IndexedStorage,
    decisions: &Decisions,
    client: &str,
    grant: GrantId,
    handle: &str,
    allowed: bool,
) -> Result<String, String> {
    let snapshot = storage
        .lookup(GrantSelector::Interaction(handle))
        .map_err(|_| "Consent storage unavailable")?
        .ok_or("Unknown interaction")?;
    if snapshot.id != grant || client_id(&snapshot.aggregate.record.request.client) != client {
        return Err("Interaction does not belong to this browser grant".into());
    }
    let Finish::Redirect { uri } = server
        .complete_interaction(handle, now())
        .map_err(|_| "Interaction completion refused")?
    else {
        return Err("Unexpected completion method".into());
    };
    let callback =
        InteractCallback::from_redirect(&uri).map_err(|_| "Invalid completion reference")?;
    // Completion's CAS must succeed first. The decision is read, not popped,
    // during policy evaluation: a later CAS conflict cannot consume consent.
    decisions.lock().unwrap().grants.insert(
        grant,
        Consent {
            request: snapshot.aggregate.record.request,
            interaction_reference: callback.interact_ref,
            allowed,
        },
    );
    Ok(uri)
}

fn now() -> u64 {
    gnap_types::unix_now()
}

fn browser_view(session: &BrowserSession<'_>, origin: &str) -> Value {
    let tokens = session.client.usable_tokens(now());
    let rights: Vec<_> = tokens
        .iter()
        .flatten()
        .flat_map(|t| t.access.iter().flatten())
        .collect();
    json!({"state":session.state, "events":session.events, "rights":rights, "requested_rights":session.requested_rights, "token_present":tokens.is_some(), "resource_available":true, "retired_token_present":session.retired_token.is_some(), "folder":session.folder, "last_resource_status":session.last_resource_status, "interaction_uri":format!("{origin}/interact/{}",session.handle), "continuation_open":session.continuation_open, "continuation_wait_seconds":session.next_continuation.saturating_sub(now())})
}

fn client_worker(
    origin: String,
    signer: Arc<Ps256Signer>,
    server: Arc<As>,
    storage: Arc<IndexedStorage>,
    decisions: Decisions,
    receiver: mpsc::Receiver<Command>,
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
                decisions.grants.remove(&session.grant_id);
            }
            live
        });
        let command = match receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(c) => c,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let result = (|| -> Result<Value, String> {
            if command.action == "start" {
                if sessions.len() >= MAX_SESSIONS {
                    return Err("Demo busy: 64 active sessions; retry later".into());
                }
                decisions
                    .lock()
                    .unwrap()
                    .clients
                    .insert(command.session.clone());
                let mut client =
                    Session::new(&transport, signer.as_ref(), format!("{origin}/gnap"))
                        .supporting(&["redirect"]);
                let grant: GrantRequest = serde_json::from_value(json!({
                    "client": command.session,
                    "access_token": {"access": [FOLDER_READ, ARCHIVE_READ]},
                    "interact": {"start": ["redirect"], "finish": {"method":"redirect", "uri":format!("{origin}/callback"), "nonce":fresh_nonce().map_err(|e| e.to_string())?}}
                })).map_err(|e| e.to_string())?;
                let step = client.start(&grant, now()).map_err(|e| e.to_string())?;
                let interaction = step
                    .response()
                    .interact
                    .as_ref()
                    .and_then(|i| i.redirect.as_ref())
                    .ok_or("AS did not request consent")?;
                let handle = interaction
                    .rsplit('/')
                    .next()
                    .ok_or("Missing interaction handle")?
                    .to_owned();
                let grant_id = storage
                    .lookup(GrantSelector::Interaction(&handle))
                    .map_err(|_| "Grant storage unavailable")?
                    .ok_or("Unknown new grant")?
                    .id;
                sessions.insert(
                    command.session.clone(),
                    BrowserSession {
                        client,
                        grant_id,
                        handle,
                        born: Instant::now(),
                        operations: 0,
                        state: "pending",
                        events: vec![
                            "Signed POST /gnap over HTTP: AS requests explicit consent.".into()
                        ],
                        retired_token: None,
                        folder: None,
                        continuation_open: true,
                        requested_rights: requested_rights(&grant).unwrap(),
                        last_resource_status: None,
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
            if command.action != "status" && command.action != "start" {
                session.operations += 1;
                if session.operations > 40 {
                    return Err("Demo limit: 40 actions per session".into());
                }
            }
            match command.action.as_str() {
                "approve" | "deny" => {
                    if session.state != "pending" {
                        return Err("Consent already completed".into());
                    }
                    let uri = consent_finish(
                        &server,
                        &storage,
                        &decisions,
                        &command.session,
                        session.grant_id,
                        &session.handle,
                        command.action == "approve",
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
                    let before = session
                        .client
                        .usable_tokens(now())
                        .and_then(|t| t.first().map(|t| t.value.clone()));
                    let step = match session.client.continue_grant(now()) {
                        Ok(s) => s,
                        Err(e) => {
                            if matches!(&e,gnap_client::ClientError::Server(e) if e.code == gnap_registry::ErrorCode::UserDenied)
                            {
                                session.state = "denied";
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
                    let rights = if command.action == "downscope" {
                        vec![FOLDER_READ]
                    } else {
                        vec![FOLDER_READ, ARCHIVE_READ]
                    };
                    let changes: ContinueRequest = serde_json::from_value(json!({"access_token":{"access":rights}, "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":format!("{origin}/callback"),"nonce":fresh_nonce().map_err(|_| "Interaction randomness unavailable")?}}})).map_err(|_| "Modification encoding failed")?;
                    let before = session
                        .client
                        .usable_tokens(now())
                        .and_then(|t| t.first().map(|t| t.value.clone()));
                    let step = session
                        .client
                        .modify_grant(&changes, now())
                        .map_err(|_| "Grant modification refused or AS unavailable")?;
                    if matches!(step, gnap_client::Step::Recoverable(_)) {
                        return Err(
                            "AS refused this modification; existing rights are unchanged".into(),
                        );
                    }
                    session.requested_rights =
                        changes.access_token.unwrap().tokens[0].access.clone();
                    session.received(&step, before)?;
                    session.events.push(if session.state == "pending" { "Signed PATCH requested additional rights. A new interaction is required; previous tokens remain live while consent is pending." } else { "Signed PATCH reduced access to a subset of live approved rights. New tokens replaced the entire previous set without another consent prompt." }.into());
                }
                "rotate" => {
                    let before = session
                        .client
                        .usable_tokens(now())
                        .and_then(|t| t.first().map(|t| t.value.clone()))
                        .ok_or("No token to rotate")?;
                    let token = session
                        .client
                        .rotate_token(None, now())
                        .map_err(|e| e.to_string())?;
                    if token.value == before {
                        return Err("Rotation did not replace token value".into());
                    }
                    session.retired_token = Some(before);
                    session.folder = None;
                    session.events.push("Signed management POST over HTTP: access and management token values rotated.".into());
                }
                "revoke" => {
                    let retiring = session
                        .client
                        .usable_tokens(now())
                        .and_then(|t| t.first().map(|t| t.value.clone()));
                    session
                        .client
                        .revoke_token(None, now())
                        .map_err(|e| e.to_string())?;
                    session.retired_token = retiring;
                    if !matches!(session.state, "pending" | "awaiting_callback" | "ready") {
                        session.state = "revoked";
                    }
                    session.folder = None;
                    session.events.push(
                        "Signed management DELETE over HTTP: AS confirmed revocation (204).".into(),
                    );
                }
                "revoke-grant" => {
                    let retiring = session
                        .client
                        .usable_tokens(now())
                        .and_then(|t| t.first().map(|t| t.value.clone()));
                    session
                        .client
                        .revoke_grant(now())
                        .map_err(|_| "Grant revocation refused or AS unavailable")?;
                    session.retired_token = retiring;
                    session.continuation_open = false;
                    session.state = "grant_revoked";
                    session.folder = None;
                    session.events.push("Signed DELETE on continuation revoked the grant and all its tokens atomically (204).".into());
                }
                "read" | "read-archive" | "check-retired" => {
                    let token = if command.action != "check-retired" {
                        session
                            .client
                            .usable_tokens(now())
                            .and_then(|t| t.first().map(|t| t.value.clone()))
                            .ok_or("No usable resource token")?
                    } else {
                        session
                            .retired_token
                            .clone()
                            .ok_or("Rotate or revoke a token first")?
                    };
                    let path = if command.action == "read-archive" {
                        "/resource/archive"
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
                    if command.action == "check-retired" {
                        if response.status != 401 {
                            return Err(format!(
                                "Retired token unexpectedly returned {}",
                                response.status
                            ));
                        }
                        session.events.push("A fresh valid signature with the retired token was rejected by the RS (401).".into());
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
                        session.events.push(format!("Signed GET {path} returned {} after the RS checked proof, token and the exact resource right.", response.status));
                    }
                }
                "start" | "status" => {}
                action if action.starts_with("interaction:") => {
                    if action[12..] != session.handle || session.state != "pending" {
                        return Err("Unknown interaction for this browser session".into());
                    }
                }
                _ => return Err("Unknown action".into()),
            }
            Ok(browser_view(session, &origin))
        })();
        if result.is_err() && command.action == "start" && !sessions.contains_key(&command.session)
        {
            decisions.lock().unwrap().clients.remove(&command.session);
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

/// Resource metadata is authoritative only in this same-deployment index; this
/// is NOT an implementation of the RFC 9767 introspection protocol.
#[derive(Debug)]
enum ResourceError {
    Denied,
    Storage(StoreError),
}
impl From<StoreError> for ResourceError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}
fn read_resource(app: &App, request: &HttpRequest) -> Result<Value, ResourceError> {
    read_resource_with_clock(app, request, now)
}

fn read_resource_with_clock(
    app: &App,
    request: &HttpRequest,
    clock: impl Fn() -> u64,
) -> Result<Value, ResourceError> {
    let right = match request.url.strip_prefix(&app.origin) {
        Some("/resource/folder") if request.method == "GET" => FOLDER_READ,
        Some("/resource/archive") if request.method == "GET" => ARCHIVE_READ,
        _ => return Err(ResourceError::Denied),
    };
    let auth: Vec<&str> = request
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .collect();
    if auth.len() != 1 {
        return Err(ResourceError::Denied);
    }
    let (scheme, token) = auth[0].split_once(' ').ok_or(ResourceError::Denied)?;
    let token = token.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("gnap")
        || token.is_empty()
        || token.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(ResourceError::Denied);
    }
    let snapshot = {
        let mut state = app.storage.lock()?;
        state.cleanup(clock())?;
        state
            .base
            .lookup(GrantSelector::AccessToken(token))?
            .ok_or(ResourceError::Denied)?
    };
    let record = snapshot
        .aggregate
        .tokens
        .values()
        .find(|record| record.token.value.as_str() == token)
        .ok_or(ResourceError::Denied)?;
    if !app
        .decisions
        .lock()
        .unwrap()
        .clients
        .contains(&client_id(&record.client))
    {
        return Err(ResourceError::Denied);
    }
    if !record
        .token
        .access
        .as_ref()
        .is_some_and(|a| a.contains(&AccessItem::Reference(right.into())))
    {
        return Err(ResourceError::Denied);
    }
    let signed = SignedRequest {
        method: &request.method,
        target_uri: &request.url,
        headers: &request.headers,
        body: request.body.as_deref(),
    };
    let nonce = |nonce: &str, time: u64| app.storage.resource_nonces.remember_nonce(nonce, time);
    let resolver = KnownKeys {
        signer: app.signer.clone(),
        decisions: app.decisions.clone(),
    };
    let verifier = resolver
        .resolve(&record.client)
        .ok_or(ResourceError::Denied)?;
    verify_request(
        &signed,
        verifier.as_ref(),
        &Expectations {
            now: clock(),
            max_clock_skew: 300,
            // The token's resolved verifier carries its own expected key ID.
            key_id: None,
        },
        &nonce,
    )
    .map_err(|_| ResourceError::Denied)?;
    // Crypto ran without the store lock. Recheck the exact revision and fresh
    // expiration under the same lock used by commits: rotation/revocation that
    // won in the meantime cannot authorize a read from this stale snapshot.
    let mut state = app.storage.lock()?;
    state.cleanup(clock())?;
    let current = state
        .base
        .lookup(GrantSelector::AccessToken(token))?
        .ok_or(ResourceError::Denied)?;
    if current.id != snapshot.id
        || current.revision != snapshot.revision
        || current.aggregate.revoked
    {
        return Err(ResourceError::Denied);
    }
    Ok(
        json!({"folder":if right == FOLDER_READ { "synthetic-project-orion" } else { "synthetic-archive" },"documents":[{"name":"readme.txt","content":"Synthetic documents only. This read was authorized by a live key-bound GNAP token."}],"granted_right":right}),
    )
}
async fn resource(
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
        Ok(Err(ResourceError::Storage(error))) => {
            eprintln!("Resource store failure: {error}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"storage_unavailable"})),
            )
                .into_response()
        }
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
        .try_send(Command {
            session,
            action,
            reply,
        })
        .map_err(|_| "Demo queue full; retry shortly".to_owned())?;
    receiver
        .await
        .map_err(|_| "Client worker unavailable".to_owned())?
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
        "revoke-grant",
    ]
    .contains(&action)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let session = if action == "start" {
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
    if action == "start" && response.status().is_success() {
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
        Ok::<_, StoreError>(app.server.handle(&request, now()))
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
    let decisions: Decisions = Arc::default();
    let storage = Arc::new(IndexedStorage::default());
    let server = AuthorizationServer::new(
        ConsentPolicy(decisions.clone()),
        KnownKeys {
            signer: signer.clone(),
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
    let server = Arc::new(if origin.starts_with("http:") {
        eprintln!("Development-only HTTP loopback discovery enabled; RFC 9635 §9 requires HTTPS in production.");
        server.with_development_http_discovery()
    } else {
        server
    });
    let (sender, receiver) = mpsc::sync_channel(32);
    let app = App {
        origin: origin.clone(),
        server: server.clone(),
        storage: storage.clone(),
        signer: signer.clone(),
        decisions: decisions.clone(),
        commands: sender,
        starts: Arc::default(),
        admission: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    let worker_storage = storage.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        if let Err(error) = storage.cleanup() {
            eprintln!("Background store maintenance failed: {error}");
        }
    });
    std::thread::spawn(move || {
        client_worker(origin, signer, server, worker_storage, decisions, receiver)
    });
    let listener = canonical.bind(port).await.expect("listener initialization");
    let router = application_router(app, canonical);
    eprintln!("GNAP delegation demo listening on PORT={port}; no credential values are logged.");
    axum::serve(listener, router).await.expect("HTTP server");
}

fn application_router(app: App, canonical: CanonicalOrigin) -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("../static/index.html")) }))
        .route("/health", get(|| async { Json(json!({"status":"ok", "profile":"GNAP HTTPSig client/AS demonstrator; not certification"})) }))
        .route("/api/status", get(status))
        .route("/api/{action}", post(action))
        .route("/callback", get(callback))
        .route("/interact/{handle}", get(interaction))
        .route("/gnap", post(protocol).options(protocol))
        .route("/continue", axum::routing::any(protocol))
        .route("/resource/folder", get(resource))
        .route("/resource/archive", get(resource))
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
        assert!(discovery.interaction_start_modes_supported.is_none());
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
        let signer = Arc::new(Ps256Signer::generate(2048, "test-client").unwrap());
        let storage = Arc::new(IndexedStorage::default());
        let decisions: Decisions = Arc::default();
        decisions
            .lock()
            .unwrap()
            .clients
            .insert("test-client".into());
        let server = Arc::new(AuthorizationServer::new(
            ConsentPolicy(decisions.clone()),
            KnownKeys {
                signer: signer.clone(),
                decisions: decisions.clone(),
            },
            storage.clone(),
            OsNonces,
            Endpoints {
                grant: "https://demo.example/gnap".into(),
                continuation: "https://demo.example/continue".into(),
                interaction: "https://demo.example/interact".into(),
                token_management: "https://demo.example/token".into(),
            },
        ));
        let (commands, _) = mpsc::sync_channel(1);
        App {
            origin: "https://demo.example".into(),
            server,
            storage,
            signer,
            decisions,
            commands,
            starts: Arc::default(),
            admission: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
    fn test_record(value: &str) -> TokenRecord {
        TokenRecord {
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
    fn test_aggregate(handle: &str, token: TokenRecord) -> GrantAggregate {
        let mut aggregate = GrantAggregate::new(GrantRecord {
            grant: Default::default(),
            request: serde_json::from_value(json!({"client":"test-client"})).unwrap(),
            continuation_token: None,
            as_nonce: None,
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
        assert!(app
            .storage
            .lookup(GrantSelector::Management("handle"))
            .unwrap()
            .is_none());
        assert!(app
            .storage
            .lookup(GrantSelector::AccessToken("access-one"))
            .unwrap()
            .is_none());
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
    fn rotation_and_revocation_between_snapshot_and_proof_cannot_authorize_stale_read() {
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
                    // Runs after snapshot lookup and before proof verification.
                    // This would deadlock if the RS held the store lock here.
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
            assert!(matches!(result, Err(ResourceError::Denied)));
            assert_eq!(calls.get(), 3);
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
                json!({"error":"storage_unavailable"})
            );
        }
    }
}

#[cfg(test)]
mod ongoing_tests;
