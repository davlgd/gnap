//! AS policy, trusted encoder, and one authoritative live-token store.
use crate::{
    http::{self, Origin},
    resource_check::CheckService,
    MAX_RECORDS, TTL,
};
use axum::{
    extract::{Request, State},
    routing::any,
    Router,
};
use biscuit_auth::{KeyPair, PublicKey};
use gnap_as::{
    nonce::OsNonces, AuthorizationServer, Decision, EncodedToken, Endpoints, GrantRecord,
    GrantStore, KeyResolver, MemoryStorage, NonceStore, Policy, TokenEncoder, TokenEncodingContext,
    TokenEncodingError, TokenRecord, TokenStore,
};
use gnap_biscuit::{FileAction, FileRight, Issuer, VerifiedToken};
use gnap_crypto::{Ps256Verifier, Verifier};
use gnap_types::{client::Client, key::Key, message::GrantRequest};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroU64,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;

pub fn client_jwk(client: &Client) -> Option<&Map<String, Value>> {
    let Client::ByValue(client) = client else {
        return None;
    };
    let Key::ByValue(key) = &client.key else {
        return None;
    };
    if key.validate().is_err() || key.proof.method().as_str() != "httpsig" {
        return None;
    }
    key.jwk.as_ref()
}
pub fn rights(origin: &str) -> Vec<FileRight> {
    vec![
        FileRight::new(format!("{origin}/files/notes"), FileAction::Read).unwrap(),
        FileRight::new(format!("{origin}/files/draft"), FileAction::Write).unwrap(),
    ]
}

pub struct Encoder {
    grant: String,
    issuer: Issuer,
    roots: BTreeMap<u32, PublicKey>,
}
impl Encoder {
    pub fn new(root: KeyPair, grant: String, audience: String) -> Result<Self, String> {
        let roots = BTreeMap::from([(1, root.public())]);
        Ok(Self {
            issuer: Issuer::new(root, 1, grant.clone(), audience)
                .map_err(|_| "issuer configuration failed")?,
            grant,
            roots,
        })
    }
}
impl TokenEncoder for Encoder {
    fn encode(&self, c: &TokenEncodingContext<'_>) -> Result<EncodedToken, TokenEncodingError> {
        if c.issuer != self.grant {
            return Err(TokenEncodingError);
        }
        let rights = c
            .access
            .iter()
            .map(FileRight::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TokenEncodingError)?;
        let deadline = c
            .issued_at
            .checked_add(c.expires_in.ok_or(TokenEncodingError)?)
            .ok_or(TokenEncodingError)?;
        let value = self
            .issuer
            .mint(
                &rights,
                client_jwk(c.client).ok_or(TokenEncodingError)?,
                c.issued_at,
                deadline,
            )
            .map_err(|_| TokenEncodingError)?;
        let verified =
            VerifiedToken::from_token(&value, &self.roots).map_err(|_| TokenEncodingError)?;
        let identifier = verified
            .revocation_identifiers()
            .first()
            .filter(|id| !id.is_empty())
            .cloned()
            .ok_or(TokenEncodingError)?;
        Ok(EncodedToken {
            value,
            identifier: Some(identifier),
        })
    }
}

#[derive(Default)]
pub struct Store {
    base: MemoryStorage,
    state: Mutex<LiveState>,
    nonces: crate::resource_check::Nonces,
}
#[derive(Default)]
struct LiveState {
    tokens: HashMap<String, TokenRecord>,
    requests: crate::replay::Reservations,
}
impl Store {
    pub fn live_count(&self, now: u64) -> usize {
        let mut state = self.state.lock().unwrap();
        state.tokens.retain(|_, t| t.is_valid_at(now));
        state.tokens.len()
    }
    /// Authority activity and a client-key-scoped nonce reservation are one
    /// critical section. Rotation never resets this key's request history.
    pub fn reserve_resource(
        &self,
        id: &[u8],
        nonce: &str,
        created: u64,
        clock: impl FnOnce() -> Option<u64>,
    ) -> gnap_biscuit::LiveDecision {
        use gnap_biscuit::LiveDecision;
        let mut state = self.state.lock().unwrap();
        let Some(now) = clock() else {
            state.requests.fail_clock();
            return LiveDecision::Unavailable;
        };
        let instant = std::time::Instant::now();
        if !state.requests.clock_ok(now, instant) {
            return LiveDecision::Unavailable;
        }
        let mut matches = state
            .tokens
            .values()
            .filter(|r| r.identifier.as_deref() == Some(id));
        let Some(record) = matches.next() else {
            return LiveDecision::Denied;
        };
        if matches.next().is_some() || !record.is_valid_at(now) {
            return LiveDecision::Denied;
        }
        let Some(key) = client_jwk(&record.client).and_then(crate::replay::key_identity) else {
            return LiveDecision::Denied;
        };
        state.requests.reserve(key, nonce, created, now, instant)
    }
}
impl GrantStore for Store {
    fn put(&self, k: &str, r: GrantRecord) {
        self.base.put(k, r)
    }
    fn get(&self, k: &str) -> Option<GrantRecord> {
        self.base.get(k)
    }
    fn take(&self, k: &str) -> Option<GrantRecord> {
        self.base.take(k)
    }
    fn update_by_interaction(&self, k: &str, f: &mut dyn FnMut(&mut GrantRecord) -> bool) -> bool {
        self.base.update_by_interaction(k, f)
    }
}
impl NonceStore for Store {
    fn remember_nonce(&self, n: &str, now: u64) -> bool {
        gnap_crypto::NonceMemory::remember_nonce(&self.nonces, n, now)
    }
}
impl TokenStore for Store {
    fn put_token(&self, k: &str, r: TokenRecord) {
        self.state.lock().unwrap().tokens.insert(k.into(), r);
    }
    fn get_token(&self, k: &str) -> Option<TokenRecord> {
        self.state.lock().unwrap().tokens.get(k).cloned()
    }
    fn take_token(&self, k: &str) -> Option<TokenRecord> {
        self.state.lock().unwrap().tokens.remove(k)
    }
}
pub struct FilePolicy {
    allowed: Vec<FileRight>,
    store: Arc<Store>,
}
impl Policy for FilePolicy {
    fn evaluate(&self, r: &GrantRequest) -> Decision {
        let deny = || Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        let Some(now) = crate::now() else {
            return deny();
        };
        if self.store.live_count(now) >= MAX_RECORDS {
            return deny();
        }
        let Some(request) = &r.access_token else {
            return deny();
        };
        if request.tokens.len() != 1 {
            return deny();
        }
        let access = &request.tokens[0].access;
        if access.is_empty()
            || access.len() > 2
            || access
                .iter()
                .any(|a| FileRight::try_from(a).map_or(true, |r| !self.allowed.contains(&r)))
        {
            return deny();
        }
        Decision::Approve {
            access: access.clone(),
            subject: None,
        }
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(TTL)
    }
}
pub struct KnownClient(Map<String, Value>);
impl KeyResolver for KnownClient {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        let jwk = client_jwk(client)?;
        if jwk != &self.0 {
            return None;
        }
        Some(Box::new(Ps256Verifier::from_public_jwk(jwk).ok()?))
    }
}
pub type Engine = AuthorizationServer<FilePolicy, KnownClient, Arc<Store>, OsNonces, Encoder>;
pub fn engine(
    origin: &Origin,
    rs: &Origin,
    root: KeyPair,
    client: Map<String, Value>,
    store: Arc<Store>,
) -> Result<Engine, String> {
    let grant = format!("{}/gnap", origin.value);
    let as_ = AuthorizationServer::new(
        FilePolicy {
            allowed: rights(&rs.value),
            store: store.clone(),
        },
        KnownClient(client),
        store,
        OsNonces,
        Endpoints {
            grant: grant.clone(),
            continuation: format!("{}/continue", origin.value),
            interaction: format!("{}/interact", origin.value),
            token_management: format!("{}/token", origin.value),
        },
    )
    .with_token_encoder(Encoder::new(root, grant, rs.value.clone())?);
    Ok(if origin.value.starts_with("http:") {
        as_.with_development_http_discovery()
    } else {
        as_
    })
}
#[derive(Clone)]
pub struct App {
    pub origin: Origin,
    pub engine: Arc<Mutex<Engine>>,
    pub check: Arc<CheckService>,
    workers: Arc<Semaphore>,
}
impl App {
    pub fn new(origin: Origin, engine: Engine, check: CheckService) -> Self {
        Self {
            origin,
            engine: Arc::new(Mutex::new(engine)),
            check: Arc::new(check),
            workers: Arc::new(Semaphore::new(4)),
        }
    }
}
async fn protocol(State(app): State<App>, request: Request) -> axum::response::Response {
    let origin = app.origin.clone();
    http::dispatch(request, &origin, app.workers.clone(), move |request| {
        if request.url == format!("{}/resource-check", app.origin.value) {
            app.check.handle(&request)
        } else {
            let engine = app.engine.lock().unwrap();
            match crate::now() {
                Some(now) => engine.handle(&request, now),
                None => http::denied(503),
            }
        }
    })
    .await
}
pub fn router(app: App) -> Router {
    let origin = app.origin.clone();
    http::guarded(
        Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route("/gnap", any(protocol))
            .route("/continue", any(protocol))
            .route("/token/{handle}", any(protocol))
            .route("/resource-check", any(protocol))
            .with_state(app),
        origin,
    )
}
