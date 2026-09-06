//! File service: proof, attenuation, and a fresh authority lookup per operation.
use crate::{
    http::{self, Origin},
    resource_check::{LiveCheck, Nonces},
    SKEW,
};
use axum::{
    extract::{Request, State},
    routing::any,
    Router,
};
use biscuit_auth::PublicKey;
use gnap_biscuit::{LiveDecision, RequestContext, VerifiedToken};
use gnap_client::{HttpRequest, HttpResponse};
use gnap_types::token::TokenValue;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;

pub struct Resources {
    pub origin: Origin,
    pub issuer: String,
    pub roots: BTreeMap<u32, PublicKey>,
    pub nonces: Nonces,
    files: Mutex<BTreeMap<&'static str, Vec<u8>>>,
}
impl Resources {
    pub fn new(origin: Origin, issuer: String, roots: BTreeMap<u32, PublicKey>) -> Self {
        Self {
            origin,
            issuer,
            roots,
            nonces: Nonces::default(),
            files: Mutex::new(BTreeMap::from([
                (
                    "notes",
                    b"Synthetic notes: local attenuation preserves the client's key.\n".to_vec(),
                ),
                ("draft", b"An empty synthetic draft.\n".to_vec()),
            ])),
        }
    }
    pub fn handle(
        &self,
        request: &HttpRequest,
        live: &mut impl FnMut(&[Vec<u8>], &gnap_crypto::ReceivedParams) -> LiveDecision,
    ) -> HttpResponse {
        let mut clock = crate::now;
        self.handle_with_clock(request, &mut clock, live)
    }
    pub fn handle_with_clock(
        &self,
        request: &HttpRequest,
        clock: &mut impl FnMut() -> Option<u64>,
        live: &mut impl FnMut(&[Vec<u8>], &gnap_crypto::ReceivedParams) -> LiveDecision,
    ) -> HttpResponse {
        if ![
            format!("{}/files/notes", self.origin.value),
            format!("{}/files/draft", self.origin.value),
        ]
        .contains(&request.url)
            || !matches!(request.method.as_str(), "GET" | "PUT")
        {
            return http::denied(404);
        }
        let mut authorization = request.header_values("authorization");
        let Some((scheme, value)) = authorization.next().and_then(|v| v.split_once(' ')) else {
            return http::denied(401);
        };
        if authorization.next().is_some() || !scheme.eq_ignore_ascii_case("GNAP") {
            return http::denied(401);
        }
        let Ok(value) = TokenValue::new(value.trim_start_matches(' ')) else {
            return http::denied(401);
        };
        let Ok(token) = VerifiedToken::from_token(&value, &self.roots) else {
            return http::denied(401);
        };
        let context = RequestContext {
            issuer: &self.issuer,
            audience: &self.origin.value,
            max_clock_skew: SKEW,
        };
        if let Err(error) =
            token.authorize(&http::signed(request), &context, &self.nonces, clock, live)
        {
            return http::denied(if error == gnap_biscuit::Error::Unavailable {
                503
            } else {
                403
            });
        }
        // No await or cached capability lies between authorize and this action.
        let name = request.url.rsplit('/').next().unwrap();
        let mut files = self.files.lock().unwrap();
        if request.method == "PUT" {
            let Some(body) = request.body.as_deref().filter(|b| b.len() <= 4096) else {
                return http::denied(400);
            };
            *files.get_mut(name).unwrap() = body.to_vec();
            http::answer(200, serde_json::json!({"written_bytes":body.len()}))
        } else {
            http::answer(
                200,
                serde_json::json!({"content":String::from_utf8_lossy(files.get(name).unwrap())}),
            )
        }
    }
}
#[derive(Clone)]
pub struct App {
    pub resources: Arc<Resources>,
    pub check: Arc<LiveCheck>,
    workers: Arc<Semaphore>,
}
impl App {
    pub fn new(resources: Resources, check: LiveCheck) -> Self {
        Self {
            resources: Arc::new(resources),
            check: Arc::new(check),
            workers: Arc::new(Semaphore::new(4)),
        }
    }
}
async fn file(State(app): State<App>, r: Request) -> axum::response::Response {
    let origin = app.resources.origin.clone();
    http::dispatch(r, &origin, app.workers.clone(), move |request| {
        app.resources.handle(&request, &mut |ids, accepted| {
            app.check.lookup(ids, accepted)
        })
    })
    .await
}
pub fn router(app: App) -> Router {
    let origin = app.resources.origin.clone();
    http::guarded(
        Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route("/files/{name}", any(file))
            .with_state(app),
        origin,
    )
}
