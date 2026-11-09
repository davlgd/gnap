//! Every supported key type runs a grant from end to end over `httpsig`:
//! issuance, continuation, value rotation, a key change to another algorithm,
//! and revocation.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, KeyResolver, MemoryStorage, OsNonces, Policy,
    TokenApproval, TokenRecord,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session, SharedSigner, Step};
use gnap_crypto::{Ed25519Signer, Es256Signer, JwkSigner, Ps256Signer, PublicKey, Verifier};
use gnap_types::client::Client;
use gnap_types::key::{Key, KeyObject};
use gnap_types::message::GrantRequest;
use serde_json::json;
use std::cell::Cell;
use std::sync::Arc;

const GRANT: &str = "https://as.example/gnap";
const NOW: u64 = 1_700_000_000;

/// Accepts any public key by value that `httpsig` supports.
struct PresentedKey;
impl KeyResolver for PresentedKey {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        let key = client.as_value()?.key.as_value()?;
        Some(Box::new(PublicKey::for_httpsig(key.jwk.as_ref()?).ok()?))
    }
}

/// Approves the requested token, keeps the grant open, and allows rotation.
struct Approve;
impl Policy for Approve {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        let requested = &request.access_token.as_ref().unwrap().tokens[0];
        Decision::ApproveTokens {
            tokens: vec![TokenApproval {
                requested_label: requested.label.clone(),
                access: requested.access.clone(),
            }],
            subject: None,
        }
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
    fn may_rotate_key(&self, _: &TokenRecord, _: &KeyObject) -> bool {
        true
    }
}

type Server = AuthorizationServer<Approve, PresentedKey, MemoryStorage, OsNonces>;

struct Direct<'a> {
    server: &'a Server,
    now: Cell<u64>,
}
impl HttpTransport for Direct<'_> {
    type Error = std::convert::Infallible;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        Ok(self.server.handle(&request, self.now.get()))
    }
}

fn presented(signer: &dyn JwkSigner) -> KeyObject {
    serde_json::from_value(json!({"proof": "httpsig", "jwk": signer.public_jwk().unwrap()}))
        .unwrap()
}

type KeyPair = Arc<dyn JwkSigner + Send + Sync>;

/// One generated key of each supported algorithm.
fn keys() -> Vec<KeyPair> {
    vec![
        Arc::new(Ps256Signer::generate(2048, "ps256-key").unwrap()),
        Arc::new(Es256Signer::generate("es256-key").unwrap()),
        Arc::new(Ed25519Signer::generate("ed25519-key").unwrap()),
    ]
}

#[test]
fn every_key_type_runs_a_grant_and_changes_to_every_other() {
    let keys = keys();
    let jwk = |signer: &KeyPair| signer.key_id().to_owned();
    for original in &keys {
        for replacement in keys.iter().filter(|key| jwk(key) != jwk(original)) {
            let server = AuthorizationServer::new(
                Approve,
                PresentedKey,
                MemoryStorage::new(),
                OsNonces,
                Endpoints {
                    grant: GRANT.into(),
                    continuation: "https://as.example/continue".into(),
                    interaction: "https://as.example/interact".into(),
                    token_management: "https://as.example/manage".into(),
                },
            )
            .with_key_rotation(true);
            let wire = Direct {
                server: &server,
                now: Cell::new(NOW),
            };
            let original_key = presented(original.as_ref());
            let request: GrantRequest = serde_json::from_value(json!({
                "client": {"key": original_key},
                "access_token": {"access": ["read"]}
            }))
            .unwrap();
            let pair = format!("{} to {}", original.algorithm(), replacement.algorithm());
            let mut client = Session::new(&wire, Arc::clone(original), GRANT);
            assert!(
                matches!(client.start(&request, NOW).unwrap(), Step::Approved(_)),
                "{pair}"
            );

            // The continuation and the token management prove the original key.
            let poll = NOW + client.continuation().unwrap().wait.unwrap_or(0).max(1);
            wire.now.set(poll);
            assert!(matches!(
                client.continue_grant(poll).unwrap(),
                Step::Approved(_)
            ));
            wire.now.set(poll + 1);
            client.rotate_token(None, poll + 1).unwrap();

            // The token changes to a key of another algorithm, which then signs.
            wire.now.set(poll + 2);
            let new_key = Key::ByValue(Box::new(presented(replacement.as_ref())));
            let changed = client
                .rotate_key(
                    None,
                    Arc::clone(replacement) as SharedSigner,
                    &new_key,
                    poll + 2,
                )
                .unwrap_or_else(|error| panic!("{pair}: {error}"));
            assert_eq!(changed.key, Some(new_key), "{pair}");
            assert_eq!(client.signer_for(None).unwrap().key_id(), jwk(replacement));
            wire.now.set(poll + 3);
            client.rotate_token(None, poll + 3).unwrap();
            wire.now.set(poll + 4);
            client.revoke_token(None, poll + 4).unwrap();
        }
    }
}
