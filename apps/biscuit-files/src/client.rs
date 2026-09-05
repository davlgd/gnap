//! Browser-facing client; private keys, GNAP tokens and session objects stay here.
use crate::{
    authorization::rights,
    config::Config,
    http::{self, Network, Origin},
    MAX_RECORDS, TTL,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use biscuit_auth::PublicKey;
use gnap_biscuit::VerifiedToken;
use gnap_client::{HttpRequest, HttpTransport, Session};
use gnap_crypto::{httpsig::fresh_nonce, Ps256Signer};
use gnap_types::{message::GrantRequest, token::TokenValue};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::mpsc::{self, SyncSender},
    time::{Duration, Instant},
};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub file: Option<String>,
    pub seconds: Option<u64>,
}
struct Command {
    id: String,
    action: String,
    args: Action,
    reply: tokio::sync::oneshot::Sender<Result<Value, String>>,
}
struct Browser<'a> {
    session: Session<'a, Network, Ps256Signer>,
    selected: Option<TokenValue>,
    retired: Option<TokenValue>,
    born: Instant,
    operations: u32,
}
pub fn grant(signer: &Ps256Signer, rs: &str) -> Result<GrantRequest, String> {
    let key = signer
        .public_jwk()
        .map_err(|_| "client public key unavailable")?;
    let access: Vec<_> = rights(rs)
        .iter()
        .map(gnap_types::access::AccessItem::from)
        .collect();
    serde_json::from_value(json!({
        "client": {"key": {"proof": "httpsig", "jwk": key}},
        "access_token": {"access": access}
    }))
    .map_err(|_| "grant encoding failed".into())
}
fn worker(
    config: Config,
    signer: Ps256Signer,
    roots: BTreeMap<u32, PublicKey>,
    commands: mpsc::Receiver<Command>,
) {
    let (Ok(as_network), Ok(rs_network)) = (
        Network::new(config.as_origin.clone()),
        Network::new(config.rs_origin.clone()),
    ) else {
        return;
    };
    let mut sessions: HashMap<String, Browser<'_>> = HashMap::new();
    loop {
        sessions.retain(|_, s| s.born.elapsed() < Duration::from_secs(TTL));
        let command = match commands.recv_timeout(Duration::from_secs(10)) {
            Ok(c) => c,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let result = (|| -> Result<Value, String> {
            let now = crate::now().ok_or("clock unavailable")?;
            if command.action == "start" {
                if sessions.len() >= MAX_RECORDS {
                    return Err("client busy; try later".into());
                }
                let mut session = Session::new(
                    &as_network,
                    &signer,
                    format!("{}/gnap", config.as_origin.value),
                );
                session
                    .start(&grant(&signer, &config.rs_origin.value)?, now)
                    .map_err(|_| "AS refused or unavailable")?;
                sessions.insert(
                    command.id.clone(),
                    Browser {
                        session,
                        selected: None,
                        retired: None,
                        born: Instant::now(),
                        operations: 0,
                    },
                );
                return Ok(
                    json!({"event":"Biscuit issued with read notes and write draft, valid for 1200 seconds."}),
                );
            }
            let s = sessions
                .get_mut(&command.id)
                .ok_or("session missing or expired")?;
            s.operations += 1;
            if s.operations > 80 {
                return Err("session action limit reached; start again".into());
            }
            if command.action == "status" {
                return Ok(
                    json!({"event":"Private session present.","attenuated":s.selected.is_some(),"retired_available":s.retired.is_some()}),
                );
            }
            let current = || {
                s.session
                    .usable_tokens(now)
                    .and_then(|t| t.first().map(|t| t.value.clone()))
            };
            match command.action.as_str() {
                "attenuate" => {
                    let file = command.args.file.as_deref().unwrap_or("notes");
                    if !matches!(file, "notes" | "draft") {
                        return Err("unknown file".into());
                    }
                    let seconds = command.args.seconds.unwrap_or(120);
                    if !(1..=600).contains(&seconds) {
                        return Err("attenuation must last 1 to 600 seconds".into());
                    }
                    let source = s
                        .selected
                        .clone()
                        .or_else(current)
                        .ok_or("no usable token")?;
                    let token = VerifiedToken::from_token(&source, &roots)
                        .map_err(|_| "token validation failed")?;
                    s.selected = Some(
                        token
                            .attenuate(
                                Some(&format!("{}/files/{file}", config.rs_origin.value)),
                                Some(now.checked_add(seconds).ok_or("clock overflow")?),
                            )
                            .map_err(|_| "attenuation refused")?,
                    );
                    Ok(
                        json!({"event":"Local restrictive block added; client key unchanged.","file":file,"seconds":seconds}),
                    )
                }
                "rotate" => {
                    let retiring = s.selected.clone().or_else(current);
                    s.session
                        .rotate_token(None, now)
                        .map_err(|_| "rotation refused or AS unavailable")?;
                    s.retired = retiring;
                    s.selected = None;
                    Ok(
                        json!({"event":"Authority rotated. Old tokens and their descendants should now be denied."}),
                    )
                }
                "revoke" => {
                    let retiring = s.selected.clone().or_else(current);
                    s.session
                        .revoke_token(None, now)
                        .map_err(|_| "revocation refused or AS unavailable")?;
                    s.retired = retiring;
                    s.selected = None;
                    Ok(
                        json!({"event":"Authority revoked. All its descendants should now be denied."}),
                    )
                }
                action @ ("read" | "write" | "read-draft" | "write-notes" | "check-retired") => {
                    let value = if action == "check-retired" {
                        s.retired.clone()
                    } else {
                        s.selected.clone().or_else(current)
                    }
                    .ok_or("no token for this operation")?;
                    let writing = matches!(action, "write" | "write-notes");
                    let file = if matches!(action, "write" | "read-draft") {
                        "draft"
                    } else {
                        "notes"
                    };
                    let mut request = HttpRequest::new(
                        if writing { "PUT" } else { "GET" },
                        format!("{}/files/{file}", config.rs_origin.value),
                    );
                    if writing {
                        request = request.header("content-type", "text/plain");
                        request.body =
                            Some(b"A synthetic draft updated by a proof-bound request.\n".to_vec());
                    }
                    let request = gnap_client::sign_request(request, &signer, Some(&value), now)
                        .map_err(|_| "resource signing failed")?;
                    let response = rs_network.send(request).map_err(|_| "RS unavailable")?;
                    let body = serde_json::from_slice::<Value>(&response.body)
                        .map_err(|_| "unexpected RS response")?;
                    Ok(
                        json!({"event":"A freshly signed request reached the RS.","status":response.status,"result":body}),
                    )
                }
                _ => Err("unknown action".into()),
            }
        })();
        let _ = command.reply.send(result);
    }
}
#[derive(Clone)]
pub struct App {
    origin: Origin,
    commands: SyncSender<Command>,
}
pub fn app(config: Config) -> Result<App, String> {
    let signer = config
        .signer("client")
        .map_err(|_| "client key unavailable")?;
    let roots = config.roots().map_err(|_| "root trust unavailable")?;
    let origin = config.client_origin.clone();
    let (commands, receiver) = mpsc::sync_channel(8);
    std::thread::spawn(move || worker(config, signer, roots, receiver));
    Ok(App { origin, commands })
}
fn cookie(headers: &HeaderMap) -> Option<String> {
    let mut matches = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().strip_prefix("biscuit_session="))
        .filter(|id| {
            id.len() == 22
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    let id = matches.next()?.to_owned();
    if matches.next().is_some() {
        None
    } else {
        Some(id)
    }
}
async fn action(
    State(app): State<App>,
    Path(action): Path<String>,
    headers: HeaderMap,
    args: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if headers.get_all("origin").iter().count() != 1
        || headers.get("origin").and_then(|v| v.to_str().ok()) != Some(&app.origin.value)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let args = match args {
        Ok(Json(args)) => args,
        Err(error) => return http::reply(http::denied(error.status().as_u16())),
    };
    let start = action == "start";
    let id = if start {
        match fresh_nonce() {
            Ok(n) => n,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        match cookie(&headers) {
            Some(id) => id,
            None => return StatusCode::UNAUTHORIZED.into_response(),
        }
    };
    let (reply, receive) = tokio::sync::oneshot::channel();
    if app
        .commands
        .try_send(Command {
            id: id.clone(),
            action,
            args,
            reply,
        })
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let response = match tokio::time::timeout(Duration::from_secs(5), receive).await {
        Ok(Ok(Ok(result))) => http::answer(200, result),
        Ok(Ok(Err(error))) => http::answer(400, json!({"error":error})),
        _ => http::denied(503),
    };
    let success = response.status == 200;
    let mut response = http::reply(response);
    if start && success {
        response.headers_mut().insert(
            "set-cookie",
            format!(
                "biscuit_session={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={TTL}{}",
                if app.origin.value.starts_with("https:") {
                    "; Secure"
                } else {
                    ""
                }
            )
            .parse()
            .unwrap(),
        );
    }
    response
}
pub fn router(app: App) -> Router {
    let origin = app.origin.clone();
    http::guarded(
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/", get(|| async { Html(include_str!("index.html")) }))
            .route(
                "/app.js",
                get(|| async {
                    (
                        [("content-type", "text/javascript")],
                        include_str!("app.js"),
                    )
                }),
            )
            .route(
                "/style.css",
                get(|| async { ([("content-type", "text/css")], include_str!("style.css")) }),
            )
            .route("/action/{action}", post(action))
            .layer(axum::extract::DefaultBodyLimit::max(512))
            .with_state(app),
        origin,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn malformed_json_never_reflects_field_names_or_values() {
        let (commands, _receiver) = mpsc::sync_channel(1);
        let app = App {
            origin: Origin::parse("https://client.example").unwrap(),
            commands,
        };
        let router = router(app);
        for body in [
            r#"{"secret-marker-field":"value"}"#,
            r#"{"seconds":"secret-marker-value"}"#,
            r#"{"file":{"secret-marker-nested":true}}"#,
            r#"{"secret-marker-syntax"#,
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/action/start")
                .header("host", "client.example")
                .header("origin", "https://client.example")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert!(response.status().is_client_error());
            assert!(response.headers().get("set-cookie").is_none());
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(body.as_ref(), b"{\"error\":\"request refused\"}");
            assert!(!String::from_utf8_lossy(&body).contains("secret-marker"));
        }
    }
}
