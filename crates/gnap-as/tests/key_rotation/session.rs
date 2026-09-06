//! Real SDK client and AS handlers, connected in memory without HTTP networking.

use super::*;
use gnap_client::{ClientError, HttpTransport, Session, Step};
use std::cell::RefCell;

struct OpenPolicy<'a>(&'a Cell<bool>);
impl Policy for OpenPolicy<'_> {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        Approve {
            key_rotation: true,
            value_rotation: true,
        }
        .evaluate(request)
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(60)
    }
    fn may_rotate_key(&self, _: &TokenRecord, _: &KeyObject) -> bool {
        self.0.get()
    }
}

type SessionServer<'a> = AuthorizationServer<OpenPolicy<'a>, Keys, Arc<MemoryStorage>, Counted>;

fn server(allowed: &Cell<bool>) -> SessionServer<'_> {
    AuthorizationServer::new(
        OpenPolicy(allowed),
        Keys,
        Arc::new(MemoryStorage::new()),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/manage".into(),
        },
    )
    .with_key_rotation(true)
}

struct Direct<'a> {
    server: &'a SessionServer<'a>,
    now: Cell<u64>,
    strip_replacement: Cell<bool>,
    exchanges: RefCell<Vec<(HttpRequest, HttpResponse)>>,
}
impl<'a> Direct<'a> {
    const fn new(server: &'a SessionServer<'a>) -> Self {
        Self {
            server,
            now: Cell::new(NOW),
            strip_replacement: Cell::new(false),
            exchanges: RefCell::new(Vec::new()),
        }
    }
}
impl HttpTransport for Direct<'_> {
    type Error = std::convert::Infallible;
    fn send(&self, mut request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        // Fault injection only: a conforming transport must preserve the signed
        // request. This mode exercises the AS's real missing-proof refusal.
        if self.strip_replacement.get() {
            request.headers.retain(|(name, value)| {
                !((name.eq_ignore_ascii_case("signature")
                    || name.eq_ignore_ascii_case("signature-input"))
                    && value.starts_with("replacement="))
            });
        }
        let response = self.server.handle(&request, self.now.get());
        self.exchanges
            .borrow_mut()
            .push((request, response.clone()));
        Ok(response)
    }
}

fn request() -> GrantRequest {
    serde_json::from_value(json!({
        "client": {"key": presented(old_key())},
        "access_token": [
            {"label": "documents", "access": ["documents:read"]},
            {"label": "reports", "access": ["reports:read"]}
        ]
    }))
    .unwrap()
}

fn held(client: &Session<'_, Direct<'_>, Ps256Signer>, now: u64) -> Vec<AccessToken> {
    client
        .usable_tokens(now)
        .unwrap()
        .into_iter()
        .cloned()
        .collect()
}

#[test]
fn client_and_server_keep_token_keys_separate_from_grant_continuation() {
    let allowed = Cell::new(true);
    let server = server(&allowed);
    let wire = Direct::new(&server);
    let third = Ps256Signer::generate(2048, "third-presentation-key").unwrap();
    let mut client = Session::new(&wire, old_key(), GRANT);
    assert!(matches!(
        client.start(&request(), NOW).unwrap(),
        Step::Approved(_)
    ));
    let original = held(&client, NOW);
    assert!(client.continuation().is_some());
    wire.now.set(NOW + 1);
    let key = Key::ByValue(Box::new(presented(new_key())));
    let changed = client
        .rotate_key(Some("documents"), new_key(), &key, NOW + 1)
        .unwrap();
    assert_ne!(changed.value, original[0].value);
    assert_eq!(changed.access, original[0].access);
    assert_eq!(changed.flags, original[0].flags);
    assert_eq!(changed.label, original[0].label);
    assert_eq!(changed.key, Some(key));
    assert_eq!(held(&client, NOW + 1)[1], original[1]);
    assert_eq!(
        client.signer_for(Some("documents")).unwrap().key_id(),
        new_key().key_id()
    );
    assert_eq!(
        client.signer_for(Some("reports")).unwrap().key_id(),
        old_key().key_id()
    );

    let poll_at = NOW + client.continuation().unwrap().wait.unwrap_or(0).max(2);
    wire.now.set(poll_at);
    assert!(matches!(
        client.continue_grant(poll_at).unwrap(),
        Step::Approved(_)
    ));
    assert_eq!(held(&client, poll_at)[0], changed);
    assert_eq!(
        client.signer_for(Some("documents")).unwrap().key_id(),
        new_key().key_id()
    );
    wire.now.set(poll_at + 1);
    client.rotate_token(Some("reports"), poll_at + 1).unwrap();
    assert_eq!(
        client.signer_for(Some("reports")).unwrap().key_id(),
        old_key().key_id()
    );

    wire.now.set(poll_at + 2);
    let third_key = Key::ByValue(Box::new(presented(&third)));
    let twice = client
        .rotate_key(Some("documents"), &third, &third_key, poll_at + 2)
        .unwrap();
    assert_eq!(twice.key, Some(third_key.clone()));
    assert_ne!(twice.value, changed.value);
    wire.now.set(poll_at + 3);
    let refreshed = client.rotate_token(Some("documents"), poll_at + 3).unwrap();
    assert_eq!(refreshed.key, Some(third_key));
    assert_eq!(
        client.signer_for(Some("documents")).unwrap().key_id(),
        third.key_id()
    );
    wire.now.set(poll_at + 4);
    client.revoke_token(Some("documents"), poll_at + 4).unwrap();
    assert_eq!(client.usable_tokens(poll_at + 4).unwrap().len(), 1);
    assert!(client.signer_for(Some("documents")).is_err());
    wire.now.set(poll_at + 5);
    client.revoke_grant(poll_at + 5).unwrap();
    assert!(client.usable_tokens(poll_at + 5).is_none());
    assert!(wire
        .exchanges
        .borrow()
        .iter()
        .all(|(_, response)| (200..300).contains(&response.status)));
}

#[test]
fn actual_as_refusals_keep_client_tokens_and_signers_unchanged() {
    for strip_proof in [false, true] {
        let allowed = Cell::new(strip_proof);
        let server = server(&allowed);
        let wire = Direct::new(&server);
        let mut client = Session::new(&wire, old_key(), GRANT);
        client.start(&request(), NOW).unwrap();
        let original = held(&client, NOW);
        let continuation = client.continuation().cloned();
        let state = client.state();
        wire.now.set(NOW + 1);
        wire.strip_replacement.set(strip_proof);
        let key = Key::ByValue(Box::new(presented(new_key())));
        let refused = client
            .rotate_key(Some("documents"), new_key(), &key, NOW + 1)
            .unwrap_err();
        let ClientError::Server(error) = refused else {
            panic!("expected a real GNAP error, got {refused:?}");
        };
        assert_eq!(
            error.code.as_str(),
            if strip_proof {
                "invalid_rotation"
            } else {
                "key_rotation_not_supported"
            }
        );
        assert_eq!(held(&client, NOW + 1), original);
        assert_eq!(client.continuation(), continuation.as_ref());
        assert_eq!(client.state(), state);
        for label in ["documents", "reports"] {
            assert_eq!(
                client.signer_for(Some(label)).unwrap().key_id(),
                old_key().key_id()
            );
        }

        // A fresh request succeeds after the denial or injected fault ends.
        allowed.set(true);
        wire.strip_replacement.set(false);
        wire.now.set(NOW + 2);
        client
            .rotate_key(Some("documents"), new_key(), &key, NOW + 2)
            .unwrap();
        assert_eq!(
            client.signer_for(Some("documents")).unwrap().key_id(),
            new_key().key_id()
        );
        assert_eq!(held(&client, NOW + 2)[1], original[1]);
    }
}
