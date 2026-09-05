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
    AuthorizationServer, Decision, Endpoints, Finish, GrantRecord, GrantStore, KeyResolver,
    MemoryStorage, NonceStore, OsNonces, Policy, TokenRecord, TokenStore,
};
use gnap_client::{sign_request, HttpRequest, HttpResponse, HttpTransport, Session};
use gnap_crypto::{
    httpsig::fresh_nonce,
    proof::Verifier,
    ps256::Ps256Signer,
    verify::{verify_request, Expectations, SignedRequest},
};
use gnap_types::{
    access::AccessItem, client::Client, interact::InteractCallback, message::GrantRequest,
    token::TokenValue,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    io::Read,
    num::NonZeroU64,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_SESSIONS: usize = 64;
const SESSION_LIFETIME: Duration = Duration::from_secs(1200);
type Decisions = Arc<Mutex<HashMap<String, bool>>>;
type As = AuthorizationServer<ConsentPolicy, KnownKeys, Arc<IndexedStorage>, OsNonces>;

#[derive(Clone)]
struct CanonicalOrigin {
    value: String,
    scheme: String,
    authority: (String, u16),
}
impl CanonicalOrigin {
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

/// Application adapter: GNAP TokenStore is indexed by management handle; this
/// resource server also needs a token-value index. Both mutate under one lock.
#[derive(Default)]
struct TokenIndex {
    handles: HashMap<String, TokenRecord>,
    values: HashMap<String, String>,
}
#[derive(Default)]
struct IndexedStorage {
    base: MemoryStorage,
    grants: Mutex<HashMap<String, (GrantRecord, u64)>>,
    tokens: Mutex<TokenIndex>,
    resource_nonces: MemoryStorage,
}
impl IndexedStorage {
    fn cleanup(&self) {
        let now = now();
        self.grants
            .lock()
            .unwrap()
            .retain(|_, (_, until)| *until > now);
        let mut tokens = self.tokens.lock().unwrap();
        tokens.handles.retain(|_, record| record.is_valid_at(now));
        let valid: std::collections::HashSet<String> = tokens.handles.keys().cloned().collect();
        tokens.values.retain(|_, handle| valid.contains(handle));
    }
}
impl GrantStore for IndexedStorage {
    fn put(&self, key: &str, record: GrantRecord) {
        self.grants
            .lock()
            .unwrap()
            .insert(key.into(), (record, now() + 1200));
    }
    fn get(&self, key: &str) -> Option<GrantRecord> {
        self.grants
            .lock()
            .unwrap()
            .get(key)
            .filter(|(_, until)| *until > now())
            .map(|(r, _)| r.clone())
    }
    fn take(&self, key: &str) -> Option<GrantRecord> {
        self.grants
            .lock()
            .unwrap()
            .remove(key)
            .filter(|(_, until)| *until > now())
            .map(|(r, _)| r)
    }
    fn update_by_interaction(
        &self,
        handle: &str,
        update: &mut dyn FnMut(&mut GrantRecord) -> bool,
    ) -> bool {
        let mut grants = self.grants.lock().unwrap();
        let Some((record, _)) = grants
            .values_mut()
            .find(|(r, until)| r.interact_handle.as_deref() == Some(handle) && *until > now())
        else {
            return false;
        };
        let mut candidate = record.clone();
        if !update(&mut candidate) {
            return false;
        }
        *record = candidate;
        true
    }
}
impl NonceStore for IndexedStorage {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.base.remember_nonce(nonce, now)
    }
}
impl TokenStore for IndexedStorage {
    fn put_token(&self, handle: &str, record: TokenRecord) {
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(old) = tokens.handles.remove(handle) {
            tokens.values.remove(old.token.value.as_str());
        }
        tokens
            .values
            .insert(record.token.value.as_str().into(), handle.into());
        // Store the AS timestamp unchanged: restoring a refused rotation must
        // not restart its lifetime. Browser sessions have a separate deadline.
        tokens.handles.insert(handle.into(), record);
    }
    fn get_token(&self, handle: &str) -> Option<TokenRecord> {
        self.tokens.lock().unwrap().handles.get(handle).cloned()
    }
    fn take_token(&self, handle: &str) -> Option<TokenRecord> {
        let mut tokens = self.tokens.lock().unwrap();
        let record = tokens.handles.remove(handle)?;
        tokens.values.remove(record.token.value.as_str());
        Some(record)
    }
}

struct ConsentPolicy(Decisions);
impl Policy for ConsentPolicy {
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(1200)
    }
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::RequireInteraction
    }
    fn evaluate_after_interaction(&self, request: &GrantRequest) -> Decision {
        let id = client_id(&request.client);
        match self.0.lock().unwrap().get(&id) {
            Some(true) => Decision::Approve {
                access: vec![AccessItem::Reference("synthetic-folder:read".into())],
                subject: None,
            },
            _ => Decision::Deny(gnap_registry::ErrorCode::UserDenied),
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
            .contains_key(&client_id(client))
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
                || url.path() == "/resource/folder");
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
    handle: String,
    born: Instant,
    operations: usize,
    state: &'static str,
    events: Vec<String>,
    retired_token: Option<gnap_types::token::TokenValue>,
    folder: Option<Value>,
    next_continuation: u64,
}

fn now() -> u64 {
    gnap_types::unix_now()
}

fn client_worker(
    origin: String,
    signer: Arc<Ps256Signer>,
    server: Arc<As>,
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
                decisions.lock().unwrap().remove(id);
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
                    .insert(command.session.clone(), false);
                let mut client =
                    Session::new(&transport, signer.as_ref(), format!("{origin}/gnap"))
                        .supporting(&["redirect"]);
                let grant: GrantRequest = serde_json::from_value(json!({
                    "client": command.session,
                    "access_token": {"access": ["synthetic-folder:read"]},
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
                sessions.insert(
                    command.session.clone(),
                    BrowserSession {
                        client,
                        handle,
                        born: Instant::now(),
                        operations: 0,
                        state: "pending",
                        events: vec![
                            "Signed POST /gnap over HTTP: AS requests explicit consent.".into()
                        ],
                        retired_token: None,
                        folder: None,
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
                    decisions
                        .lock()
                        .unwrap()
                        .insert(command.session.clone(), command.action == "approve");
                    let Finish::Redirect { uri } = server
                        .complete_interaction(&session.handle, now())
                        .map_err(|e| format!("{e:?}"))?
                    else {
                        return Err("Unexpected completion method".into());
                    };
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
                    let step = match session.client.continue_grant(now()) {
                        Ok(s) => s,
                        Err(e) => {
                            if matches!(&e,gnap_client::ClientError::Server(e) if e.code == gnap_registry::ErrorCode::UserDenied)
                            {
                                session.state = "denied";
                                session.events.push("AS refused the delegation after explicit denial; no resource token was issued.".into());
                            } else {
                                return Err(e.to_string());
                            }
                            return Ok(
                                json!({"state":session.state,"events":session.events,"resource_available":true}),
                            );
                        }
                    };
                    session.state = if step.response().access_token.is_some() {
                        "approved"
                    } else {
                        "pending"
                    };
                    session.next_continuation = now()
                        + step
                            .response()
                            .r#continue
                            .as_ref()
                            .and_then(|c| c.wait)
                            .unwrap_or(0);
                    session.events.push("Signed continuation over HTTP; AS returned a key-bound token for synthetic-folder:read.".into());
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
                    session.retired_token = session
                        .client
                        .usable_tokens(now())
                        .and_then(|t| t.first().map(|t| t.value.clone()));
                    session
                        .client
                        .revoke_token(None, now())
                        .map_err(|e| e.to_string())?;
                    session.state = "revoked";
                    session.folder = None;
                    session.events.push(
                        "Signed management DELETE over HTTP: AS confirmed revocation (204).".into(),
                    );
                }
                "read" | "check-retired" => {
                    let token = if command.action == "read" {
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
                    let request = resource_request(&origin, token.as_str(), signer.as_ref())?;
                    let response = transport.send(request)?;
                    if command.action == "check-retired" {
                        if response.status != 401 {
                            return Err(format!(
                                "Retired token unexpectedly returned {}",
                                response.status
                            ));
                        }
                        session.events.push("A fresh valid signature with the retired token was rejected by the RS (401).".into());
                    } else {
                        if response.status != 200 {
                            return Err(format!(
                                "RS refused the resource request ({})",
                                response.status
                            ));
                        }
                        session.folder = Some(
                            serde_json::from_slice(&response.body).map_err(|e| e.to_string())?,
                        );
                        session.events.push("Signed GET /resource/folder over HTTP: RS verified proof, live token and read right, then returned synthetic documents.".into());
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
            Ok(
                json!({"state":session.state, "events":session.events, "rights":["synthetic-folder:read"], "token_present":session.client.usable_tokens(now()).is_some(), "resource_available":true, "retired_token_present":session.retired_token.is_some(), "folder":session.folder, "interaction_uri":format!("{origin}/interact/{}",session.handle),"continuation_wait_seconds":session.next_continuation.saturating_sub(now())}),
            )
        })();
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
fn read_resource(app: &App, request: &HttpRequest) -> Result<Value, ()> {
    read_resource_with_clock(app, request, now)
}

fn read_resource_with_clock(
    app: &App,
    request: &HttpRequest,
    clock: impl Fn() -> u64,
) -> Result<Value, ()> {
    let auth: Vec<&str> = request
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .collect();
    if auth.len() != 1 {
        return Err(());
    }
    let (scheme, token) = auth[0].split_once(' ').ok_or(())?;
    let token = token.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("gnap")
        || token.is_empty()
        || token.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(());
    }
    // Keep the index locked through verification and authorization: a revoke
    // cannot commit between checking a live token and authorizing this read.
    let mut tokens = app.storage.tokens.lock().unwrap();
    let handle = tokens.values.get(token).ok_or(())?.clone();
    let record = tokens.handles.get(&handle).ok_or(())?;
    if !record.is_valid_at(clock()) {
        tokens.handles.remove(&handle);
        tokens.values.remove(token);
        return Err(());
    }
    if !app
        .decisions
        .lock()
        .unwrap()
        .contains_key(&client_id(&record.client))
    {
        return Err(());
    }
    if !record
        .token
        .access
        .as_ref()
        .is_some_and(|a| a.contains(&AccessItem::Reference("synthetic-folder:read".into())))
    {
        return Err(());
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
    let verifier = resolver.resolve(&record.client).ok_or(())?;
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
    .map_err(|_| ())?;
    // Verification can take time. Decide on a fresh clock reading while still
    // holding the same index lock; an expired value cannot authorize this read.
    if !record.is_valid_at(clock()) {
        tokens.handles.remove(&handle);
        tokens.values.remove(token);
        return Err(());
    }
    Ok(
        json!({"folder":"synthetic-project-orion","documents":[{"name":"meeting-notes.txt","content":"Synthetic notes: review a GNAP delegation with explicit consent."},{"name":"readme.txt","content":"No personal data. This read was authorized by a live key-bound GNAP token."}],"granted_right":"synthetic-folder:read"}),
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
        _ => (
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
        app.storage.cleanup();
        app.server.handle(&request, now())
    })
    .await;
    let Ok(result) = result else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
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
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        storage.cleanup();
    });
    std::thread::spawn(move || client_worker(origin, signer, server, decisions, receiver));
    let router = application_router(app, canonical);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("listen PORT");
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
    use tower::ServiceExt;

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

    fn test_app() -> App {
        let signer = Arc::new(Ps256Signer::generate(2048, "test-client").unwrap());
        let storage = Arc::new(IndexedStorage::default());
        let decisions: Decisions = Arc::default();
        decisions.lock().unwrap().insert("test-client".into(), true);
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
            issued_at: now(),
            token: serde_json::from_value(
                json!({"value":value,"access":["synthetic-folder:read"],"expires_in":1200}),
            )
            .unwrap(),
            client: serde_json::from_value(json!("test-client")).unwrap(),
            management_token: "management-only".into(),
        }
    }
    #[test]
    fn resource_requires_live_bound_token_and_rejects_replays_and_management_tokens() {
        let app = test_app();
        let store = app.storage.clone();
        store.put_token("handle", test_record("access-one"));
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
            &resource_request(&app.origin, "management-only", &app.signer).unwrap()
        )
        .is_err());
        let other = Ps256Signer::generate(2048, "test-client").unwrap();
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-one", &other).unwrap()
        )
        .is_err());
        store.take_token("handle").unwrap();
        store.put_token("new-handle", test_record("access-two"));
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
        store.take_token("new-handle").unwrap();
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-two", &app.signer).unwrap()
        )
        .is_err());
        assert!(app.storage.tokens.lock().unwrap().values.is_empty());
    }
    #[test]
    fn expiry_is_enforced_before_background_cleanup_and_wrong_rights_fail() {
        let app = test_app();
        let store = app.storage.clone();
        store.put_token("expired", test_record("access-expired"));
        app.storage
            .tokens
            .lock()
            .unwrap()
            .handles
            .get_mut("expired")
            .unwrap()
            .issued_at = now().saturating_sub(1200);
        assert!(store.get_token("expired").is_some(), "no sweep has run");
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "access-expired", &app.signer).unwrap()
        )
        .is_err());
        assert!(store.take_token("expired").is_none());
        assert!(!app
            .storage
            .tokens
            .lock()
            .unwrap()
            .values
            .contains_key("access-expired"));
        let mut record = test_record("wrong-right");
        record.token.access = Some(vec![AccessItem::Reference("other:read".into())]);
        store.put_token("wrong", record);
        assert!(read_resource(
            &app,
            &resource_request(&app.origin, "wrong-right", &app.signer).unwrap()
        )
        .is_err());
    }
    #[test]
    fn concurrent_replay_has_one_winner() {
        let app = test_app();
        app.storage.put_token("h", test_record("access-one"));
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
        storage.put_token("handle", original.clone());
        let taken = storage.take_token("handle").unwrap();
        storage.put_token("handle", taken);
        let restored = storage.get_token("handle").unwrap();
        assert_eq!(restored.issued_at, original.issued_at);
        assert_eq!(restored.expires_at(), deadline);
        assert_eq!(restored.token, original.token);
        storage.cleanup();
        assert!(storage.get_token("handle").is_some());
        original.issued_at = now().saturating_sub(1200);
        storage.put_token("handle", original);
        storage.cleanup();
        assert!(storage.get_token("handle").is_none());
        assert!(storage.tokens.lock().unwrap().values.is_empty());
    }

    #[test]
    fn resource_rechecks_expiration_after_signature_verification() {
        let app = test_app();
        let record = test_record("access-one");
        let issued_at = record.issued_at;
        app.storage.put_token("handle", record);
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
        assert!(app.storage.get_token("handle").is_none());
        assert!(app.storage.tokens.lock().unwrap().values.is_empty());
    }
}
