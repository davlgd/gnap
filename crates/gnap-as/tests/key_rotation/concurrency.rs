//! A validated key change must not publish over a concurrent token revocation.

use super::*;
use gnap_as::{GrantAggregate, GrantId, NonceStore, Revision, RotationNonceStore, StoreError};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

struct PausedKeyChange {
    base: Arc<MemoryStorage>,
    entered: mpsc::SyncSender<gnap_types::token::TokenValue>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl GrantStore for PausedKeyChange {
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        self.base.create(aggregate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        self.base.lookup(selector)
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        if let Some(record) = replacement
            .tokens
            .values()
            .find(|record| record.token.key.is_some())
        {
            self.entered
                .send(record.token.value.clone())
                .map_err(|_| StoreError::Unavailable)?;
            self.resume
                .lock()
                .map_err(|_| StoreError::Unavailable)?
                .recv_timeout(WAIT)
                .map_err(|_| StoreError::Unavailable)?;
        }
        self.base.compare_exchange(id, revision, replacement)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.base.remove(id, revision)
    }
}

impl NonceStore for PausedKeyChange {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.base.remember_nonce(nonce, now)
    }
}

impl RotationNonceStore for PausedKeyChange {
    fn remember_nonce_pair(&self, old: Option<&str>, new: Option<&str>, now: u64) -> bool {
        self.base.remember_nonce_pair(old, new, now)
    }
}

#[test]
fn a_proven_key_change_cannot_restore_a_concurrently_revoked_token() {
    let server = server(true, true);
    let tokens = grant(&server);
    let before = snapshot(&server, &tokens[0]);
    let request = rotate_request(&tokens[0], &presented(new_key()), None);
    let nonces: Vec<String> = gnap_crypto::parse_signatures(
        &request.combined_header_value("signature-input").unwrap(),
        &request.combined_header_value("signature").unwrap(),
    )
    .into_iter()
    .map(|signature| {
        gnap_crypto::parse_signature_params(&signature.unwrap().raw_params)
            .unwrap()
            .nonce
            .unwrap()
    })
    .collect();
    assert_eq!(nonces.len(), 2);
    let manage = tokens[0].manage.as_ref().unwrap();
    let revoke = sign_request(
        HttpRequest::new("DELETE", &manage.uri),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 2,
    )
    .unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let waiting = AuthorizationServer::new(
        Approve {
            key_rotation: true,
            value_rotation: true,
        },
        Keys,
        PausedKeyChange {
            base: Arc::clone(server.storage()),
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
        },
        // Separate deterministic credentials, disjoint from the initial grant.
        Counted(Cell::new(1_000)),
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/manage".into(),
        },
    )
    .with_key_rotation(true);
    let (entered, released, deletion, rotation) = std::thread::scope(|scope| {
        let pending = scope.spawn(move || waiting.handle(&request, NOW + 1));
        let entered = entered_rx.recv_timeout(WAIT);
        let deletion = entered.is_ok().then(|| server.handle(&revoke, NOW + 2));
        // Release before asserting so a failed setup does not strand a worker.
        let released = resume_tx.send(());
        let rotation = pending.join().unwrap();
        (entered, released, deletion, rotation)
    });
    let candidate = entered.expect("key rotation did not reach the publication boundary");
    released.unwrap();
    assert_eq!(deletion.unwrap().status, 204);
    assert_eq!(error_code(&rotation), "invalid_rotation");
    assert!(rotation.has_no_store());
    let wire: Value = serde_json::from_slice(&rotation.body).unwrap();
    assert!(wire.get("access_token").is_none());
    let retained = snapshot(&server, &tokens[1]);
    assert_eq!(retained.id, before.id);
    assert_eq!(retained.aggregate.tokens.len(), 1);
    assert_eq!(
        retained.aggregate.tokens[handle(&tokens[1])].token,
        before.aggregate.tokens[handle(&tokens[1])].token
    );
    for selector in [
        GrantSelector::Management(handle(&tokens[0])),
        GrantSelector::AccessToken(tokens[0].value.as_str()),
        GrantSelector::AccessToken(candidate.as_str()),
    ] {
        assert!(server.storage().lookup(selector).unwrap().is_none());
    }
    for nonce in nonces {
        assert!(!server.storage().remember_nonce(&nonce, NOW + 2));
    }
}
