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
    nonce::OsNonces, AuthorizationServer, Decision, EncodedToken, Endpoints, GrantAggregate,
    GrantId, GrantSelector, GrantSnapshot, GrantStore, KeyResolver, MemoryStorage, NonceStore,
    Policy, Revision, StoreError, TokenEncoder, TokenEncodingContext, TokenEncodingError,
};
use gnap_biscuit::{FileAction, FileRight, Issuer, VerifiedToken};
use gnap_crypto::{Ps256Verifier, Verifier};
use gnap_types::{client::Client, key::Key, message::GrantRequest};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashSet},
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
        // This consumer has not enabled key rotation. Refuse an explicit
        // binding rather than silently minting claims for the grant's key.
        if c.issuer != self.grant || c.binding.is_some() {
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
    state: Mutex<LiveState>,
    nonces: crate::resource_check::Nonces,
}
#[derive(Default)]
struct LiveState {
    base: MemoryStorage,
    // Retention inventory only. The SDK owns every credential/native-id index.
    grants: HashSet<GrantId>,
    requests: crate::replay::Reservations,
}
impl LiveState {
    fn cleanup(&mut self, now: u64) -> Result<(), StoreError> {
        for id in self.grants.iter().copied().collect::<Vec<_>>() {
            let snapshot = self
                .base
                .lookup(GrantSelector::Id(id))?
                .ok_or(StoreError::Invalid)?;
            // This adapter retains at most one token per immediate grant.
            if snapshot.aggregate.revoked
                || snapshot
                    .aggregate
                    .tokens
                    .values()
                    .all(|t| !t.is_valid_at(now))
            {
                self.base.remove(id, snapshot.revision)?;
                self.grants.remove(&id);
            }
        }
        // Reservations outlive an individual authority: never clear them here.
        Ok(())
    }
}
impl Store {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, LiveState>, StoreError> {
        self.state.lock().map_err(|_| StoreError::Unavailable)
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
        let Ok(mut state) = self.lock() else {
            return LiveDecision::Unavailable;
        };
        let Some(now) = clock() else {
            state.requests.fail_clock();
            return LiveDecision::Unavailable;
        };
        let instant = std::time::Instant::now();
        if !state.requests.clock_ok(now, instant) {
            return LiveDecision::Unavailable;
        }
        if state.cleanup(now).is_err() {
            return LiveDecision::Unavailable;
        }
        let snapshot = match state.base.lookup(GrantSelector::TokenIdentifier(id)) {
            Ok(Some(snapshot)) if !snapshot.aggregate.revoked => snapshot,
            Ok(_) => return LiveDecision::Denied,
            Err(_) => return LiveDecision::Unavailable,
        };
        let mut matches = snapshot
            .aggregate
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
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        let mut state = self.lock()?;
        state.cleanup(crate::now().ok_or(StoreError::Unavailable)?)?;
        // This consumer issues one finite-lived authority, without continuation.
        if aggregate.tokens.len() != 1 || aggregate.record.continuation_token.is_some() {
            return Err(StoreError::Invalid);
        }
        if state.grants.len() >= MAX_RECORDS {
            return Err(StoreError::Unavailable);
        }
        let snapshot = state.base.create(aggregate)?;
        state.grants.insert(snapshot.id);
        Ok(snapshot)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        let mut state = self.lock()?;
        state.cleanup(crate::now().ok_or(StoreError::Unavailable)?)?;
        state.base.lookup(selector)
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        let mut state = self.lock()?;
        state.cleanup(crate::now().ok_or(StoreError::Unavailable)?)?;
        if replacement.tokens.len() > 1 || replacement.record.continuation_token.is_some() {
            return Err(StoreError::Invalid);
        }
        state.base.compare_exchange(id, revision, replacement)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        let mut state = self.lock()?;
        state.base.remove(id, revision)?;
        state.grants.remove(&id);
        Ok(())
    }
}
impl NonceStore for Store {
    fn remember_nonce(&self, n: &str, now: u64) -> bool {
        gnap_crypto::NonceMemory::remember_nonce(&self.nonces, n, now)
    }
}
pub struct FilePolicy {
    allowed: Vec<FileRight>,
}
impl Policy for FilePolicy {
    fn evaluate(&self, r: &GrantRequest) -> Decision {
        let deny = || Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
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
    pub engine: Arc<Engine>,
    pub check: Arc<CheckService>,
    workers: Arc<Semaphore>,
}
impl App {
    pub fn new(origin: Origin, engine: Engine, check: CheckService) -> Self {
        Self {
            origin,
            engine: Arc::new(engine),
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
            match crate::now() {
                Some(now) => app.engine.handle(&request, now),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_decision_holds_the_publication_lock_before_reading_time() {
        let store = Store::default();
        let called = std::cell::Cell::new(false);
        let result = store.reserve_resource(&[0; 64], "request", 1, || {
            called.set(true);
            assert!(matches!(
                store.state.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            Some(1)
        });
        assert!(called.get());
        assert_eq!(result, gnap_biscuit::LiveDecision::Denied);
        assert!(store.state.try_lock().is_ok());
    }

    #[test]
    fn unavailable_storage_is_not_reported_as_an_unknown_authority() {
        let store = Store::default();
        std::thread::scope(|scope| {
            assert!(scope
                .spawn(|| {
                    let _lock = store.state.lock().unwrap();
                    panic!("injected storage failure");
                })
                .join()
                .is_err());
        });
        assert_eq!(
            store
                .lookup(GrantSelector::TokenIdentifier(&[0; 64]))
                .unwrap_err(),
            StoreError::Unavailable
        );
        assert_eq!(
            store.reserve_resource(&[0; 64], "request", 1, || Some(1)),
            gnap_biscuit::LiveDecision::Unavailable
        );
    }
}
