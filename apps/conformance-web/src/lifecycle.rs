//! Operator-approved authenticated synthetic-resource scenarios.
//! Keys and grants stay in memory; public reports contain only static checks.
mod config;
mod network;
mod oracle;
#[cfg(test)]
mod tests;
mod worker;

use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gnap_crypto::Ps256Signer;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, Semaphore};

pub use config::Target;
const COOKIE: &str = "gnap_lifecycle";
const WORK_LIMIT: Duration = Duration::from_secs(300);
const REPORT_LIMIT: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct Lifecycle(Option<Arc<Inner>>);
struct Inner {
    origin: String,
    local: bool,
    targets: Vec<Target>,
    signer: Arc<Ps256Signer>,
    wrong_signer: Arc<Ps256Signer>,
    probes: crate::probe::Probes,
    workers: Arc<Semaphore>,
    sessions: Mutex<HashMap<String, Entry>>,
}
struct Entry {
    born: Instant,
    snapshot: Arc<Mutex<Snapshot>>,
    callback: mpsc::SyncSender<Callback>,
}
struct Callback {
    uri: String,
    accepted: oneshot::Sender<bool>,
}
struct Snapshot {
    status: &'static str,
    target: usize,
    redirect: Option<String>,
    checks: Vec<crate::Check>,
    observation: crate::Observation,
}

impl Lifecycle {
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Configuration is explicit operator authorization for the complete
    /// bounded synthetic scenario, including its negative resource probes.
    pub fn from_json(
        raw: &str,
        origin: &str,
        probes: crate::probe::Probes,
    ) -> Result<Self, &'static str> {
        if raw.trim() == "[]" {
            return Ok(Self::disabled());
        }
        let local = config::origin(origin)?;
        let targets = config::targets(raw, local)?;
        if targets.is_empty() {
            return Ok(Self::disabled());
        }
        let signer = Ps256Signer::generate(2048, "workbench-lifecycle")
            .map_err(|_| "Lifecycle client key generation failed")?;
        // A distinct key with the same public identifier exercises key binding,
        // not just rejection of an unrecognized kid.
        let wrong_signer = Ps256Signer::generate(2048, "workbench-lifecycle")
            .map_err(|_| "Lifecycle negative-test key generation failed")?;
        Ok(Self(Some(Arc::new(Inner {
            origin: origin.into(),
            local,
            targets,
            signer: Arc::new(signer),
            wrong_signer: Arc::new(wrong_signer),
            probes,
            workers: Arc::new(Semaphore::new(4)),
            sessions: Mutex::new(HashMap::new()),
        }))))
    }

    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/lifecycle",
                get(|| async { Html(include_str!("../static/lifecycle.html")) }),
            )
            .route(
                "/lifecycle.js",
                get(|| async {
                    (
                        [("content-type", "text/javascript; charset=utf-8")],
                        include_str!("../static/lifecycle.js"),
                    )
                }),
            )
            .route("/api/lifecycle/key", get(key))
            .route("/api/lifecycle/targets", get(targets))
            .route("/api/lifecycle/start", post(start))
            .route("/api/lifecycle/status", get(status))
            .route("/lifecycle/callback", get(callback))
            .with_state(self)
    }
}

fn origin_ok(inner: &Inner, headers: &HeaderMap, mutation: bool) -> bool {
    let expected = inner
        .origin
        .split_once("://")
        .map(|(_, host)| host)
        .unwrap_or("");
    let mut hosts = headers.get_all("host").iter();
    if hosts.next().and_then(|v| v.to_str().ok()) != Some(expected) || hosts.next().is_some() {
        return false;
    }
    if mutation {
        let mut origins = headers.get_all("origin").iter();
        if origins.next().and_then(|v| v.to_str().ok()) != Some(inner.origin.as_str())
            || origins.next().is_some()
        {
            return false;
        }
    }
    true
}

fn cookie(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().strip_prefix("gnap_lifecycle="));
    let value = values.next()?;
    (values.next().is_none()
        && value.len() == 22
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
    .then_some(value)
}

async fn key(State(state): State<Lifecycle>) -> Response {
    let Some(inner) = state.0 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(jwk) = inner.signer.public_jwk() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    Json(json!({"jwk":jwk, "thumbprint":inner.signer.thumbprint(), "callback":format!("{}/lifecycle/callback", inner.origin),
        "notice":"Public test-client key, generated at process startup. Restart requires explicit operator reapproval at the AS; this endpoint is not a standard GNAP discovery document."})).into_response()
}

async fn targets(State(state): State<Lifecycle>) -> Json<Value> {
    Json(state.0.as_ref().map_or_else(
        || json!([]),
        |inner| {
            json!(inner
                .targets
                .iter()
                .enumerate()
                .map(|(id, t)| json!({"id":id,"name":t.name,"grant":t.grant,"resource":t.resource}))
                .collect::<Vec<_>>())
        },
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    target_id: usize,
    consent: bool,
}

async fn start(
    State(state): State<Lifecycle>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(inner) = state.0 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !origin_ok(&inner, &headers, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if body.len() > 256
        || headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(input) = serde_json::from_slice::<Start>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !input.consent {
        return (
            StatusCode::BAD_REQUEST,
            "Explicit scenario consent is required.",
        )
            .into_response();
    }
    let Some(target) = inner.targets.get(input.target_id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(permit) = inner.workers.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "All lifecycle workers are occupied.",
        )
            .into_response();
    };
    let Ok(mut sessions) = inner.sessions.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    sessions.retain(|_, entry| entry.born.elapsed() < REPORT_LIMIT);
    if let Some(existing) = cookie(&headers).and_then(|id| sessions.get(id)) {
        if existing
            .snapshot
            .lock()
            .is_ok_and(|s| matches!(s.status, "running" | "pending"))
        {
            return (
                StatusCode::CONFLICT,
                "This browser already has an active scenario.",
            )
                .into_response();
        }
    }
    if sessions.len() >= 8 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Lifecycle report capacity reached; retry after expiry.",
        )
            .into_response();
    }
    if let Err(code) = inner.probes.admit() {
        return (code, "Shared live-test cooldown: wait 60 seconds.").into_response();
    }
    let Ok(id) = gnap_crypto::httpsig::fresh_nonce() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let snapshot = Arc::new(Mutex::new(Snapshot {
        status: "running",
        target: input.target_id,
        redirect: None,
        checks: Vec::new(),
        observation: crate::observation("live"),
    }));
    let (sender, receiver) = mpsc::sync_channel(1);
    sessions.insert(
        id.clone(),
        Entry {
            born: Instant::now(),
            snapshot: snapshot.clone(),
            callback: sender,
        },
    );
    drop(sessions);
    let runtime = tokio::runtime::Handle::current();
    let context = inner.clone();
    let started = std::thread::Builder::new()
        .name("gnap-lifecycle".into())
        .spawn(move || {
            let _permit = permit;
            worker::run(context, target, runtime, receiver, snapshot);
        });
    if started.is_err() {
        if let Ok(mut sessions) = inner.sessions.lock() {
            sessions.remove(&id);
        }
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let secure = if inner.local { "" } else { "; Secure" };
    let value = format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{secure}");
    (
        StatusCode::ACCEPTED,
        [("set-cookie", value)],
        Json(json!({"status":"running"})),
    )
        .into_response()
}

async fn status(State(state): State<Lifecycle>, headers: HeaderMap) -> Response {
    let Some(inner) = state.0 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !origin_ok(&inner, &headers, false) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    let Ok(sessions) = inner.sessions.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(entry) = cookie(&headers)
        .and_then(|id| sessions.get(id))
        .filter(|e| e.born.elapsed() < REPORT_LIMIT)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(snapshot) = entry.snapshot.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    Json(json!({"status":snapshot.status,"redirect":snapshot.redirect,"report":{
        "schema_version":1,"profile":"gnap-authenticated-lifecycle-v1","certification":false,
        "observation":snapshot.observation,"target_id":snapshot.target,"checks":snapshot.checks,
        "limitations":"Operator-approved synthetic PS256 scenario. SDK creates messages, verifies finish and manages client state; HTTP/JSON and lifecycle outcome assertions are separate. Not an independent protocol implementation, authenticated introspection test, browser rendering test or complete GNAP conformance verdict. Report excludes credentials and response bodies."}})).into_response()
}

async fn callback(
    State(state): State<Lifecycle>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let Some(inner) = state.0 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !origin_ok(&inner, &headers, false) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if uri.to_string().len() > 2048 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let sender = {
        let Ok(sessions) = inner.sessions.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let Some(entry) = cookie(&headers)
            .and_then(|id| sessions.get(id))
            .filter(|e| e.born.elapsed() < WORK_LIMIT)
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if !entry.snapshot.lock().is_ok_and(|s| s.status == "pending") {
            return StatusCode::NOT_FOUND.into_response();
        }
        entry.callback.clone()
    };
    let (accepted, result) = oneshot::channel();
    if sender
        .try_send(Callback {
            uri: format!("{}{uri}", inner.origin),
            accepted,
        })
        .is_err()
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    match tokio::time::timeout(Duration::from_secs(2), result).await {
        Ok(Ok(true)) => (StatusCode::SEE_OTHER, [("location", "/lifecycle")]).into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            "Invalid, expired or replayed callback.",
        )
            .into_response(),
    }
}
