//! The JOSE proofs, `jws` and `jwsd` (RFC 9635 §7.3.3, §7.3.4), from end to
//! end: grant, continuation, and token management, for every algorithm they
//! take, and the boundaries of their activation.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, GrantAggregate, GrantId, GrantSelector,
    GrantSnapshot, GrantStore, JwsReplayStore, KeyResolver, MemoryStorage, NonceError, NonceStore,
    Nonces, OsNonces, Policy, Revision, StoreError, TokenApproval,
};
use gnap_crypto::jws::{sign_jws, JwsMethod, JwsParams, JwsProof, DETACHED_JWS_HEADER};
use gnap_crypto::{Ed25519Signer, Es256Signer, JwkSigner, PublicKey, Rs256Signer, Verifier};
use gnap_types::client::Client;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::message::{AsDiscovery, GrantRequest, GrantResponse};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

const GRANT: &str = "https://as.example/gnap";
const CONTINUE: &str = "https://as.example/continue";
const MANAGE: &str = "https://as.example/manage";
const NOW: u64 = 1_700_000_000;

/// Accepts a public key by value of either proof family, as a JWK.
struct PresentedKey;
impl KeyResolver for PresentedKey {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        let key = client.as_value()?.key.as_value()?;
        let jwk = key.jwk.as_ref()?;
        PublicKey::for_jws(jwk)
            .or_else(|_| PublicKey::for_httpsig(jwk))
            .ok()
            .map(|key| Box::new(key) as Box<dyn Verifier>)
    }
}

/// Approves the requested token, keeps the grant open, and counts its calls,
/// so that a test can tell whether an unproven request reached it.
#[derive(Default)]
struct Approve {
    calls: Arc<AtomicU32>,
}
impl Policy for Approve {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        self.calls.fetch_add(1, Ordering::Relaxed);
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
    fn recognises_user(&self, _: &str) -> bool {
        self.calls.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Counts the values it draws.
#[derive(Default)]
struct Counted(Arc<AtomicU32>);
impl Nonces for Counted {
    fn next(&self) -> Result<String, NonceError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        OsNonces.next()
    }
}

type Server<S> = AuthorizationServer<Approve, PresentedKey, S, Counted>;

/// A memory store that counts its writes, so that a test can tell whether an
/// unproven request changed anything. Reads and reservations pass through.
#[derive(Default)]
struct CountingStore {
    inner: MemoryStorage,
    writes: Arc<AtomicU32>,
}
impl CountingStore {
    fn write(&self) {
        self.writes.fetch_add(1, Ordering::Relaxed);
    }
}
impl GrantStore for CountingStore {
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        self.write();
        self.inner.create(aggregate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        self.inner.lookup(selector)
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        self.write();
        self.inner.compare_exchange(id, revision, replacement)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.write();
        self.inner.remove(id, revision)
    }
}
impl NonceStore for CountingStore {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.inner.remember_nonce(nonce, now)
    }
}
impl JwsReplayStore for CountingStore {
    fn reserve_jws_proofs(&self, ids: &[gnap_crypto::ReplayId], now: u64) -> bool {
        self.inner.reserve_jws_proofs(ids, now)
    }
}

fn endpoints() -> Endpoints {
    Endpoints {
        grant: GRANT.into(),
        continuation: CONTINUE.into(),
        interaction: "https://as.example/interact".into(),
        token_management: MANAGE.into(),
    }
}

fn server(jose: bool) -> Server<MemoryStorage> {
    AuthorizationServer::new(
        Approve::default(),
        PresentedKey,
        MemoryStorage::new(),
        Counted::default(),
        endpoints(),
    )
    .with_jose_proofs(jose)
}

type Signer = Arc<dyn JwkSigner + Send + Sync>;

/// One key of each algorithm the JOSE proofs take.
fn signers() -> &'static [Signer] {
    static KEYS: OnceLock<Vec<Signer>> = OnceLock::new();
    KEYS.get_or_init(|| {
        vec![
            Arc::new(Rs256Signer::generate(2048, "rs256-key").unwrap()),
            Arc::new(Es256Signer::generate("es256-key").unwrap()),
            Arc::new(Ed25519Signer::generate("ed25519-key").unwrap()),
        ]
    })
}

fn grant_body(signer: &dyn JwkSigner, proof: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "client": {"key": {"proof": proof, "jwk": signer.public_jwk().unwrap()}},
        "access_token": {"access": ["read"]}
    }))
    .unwrap()
}

/// A request proven with `method`: `content` is the JSON content, empty for
/// none, and `token` the access token the request presents.
struct Call<'a> {
    method: &'a str,
    uri: &'a str,
    content: &'a [u8],
    token: Option<&'a str>,
    created: u64,
}

impl Call<'_> {
    fn signed(&self, proof: JwsMethod, signer: &dyn JwkSigner) -> HttpRequest {
        let params = JwsParams {
            method: self.method,
            target_uri: self.uri,
            created: self.created,
            access_token: self.token,
        };
        let mut request = HttpRequest::new(self.method, self.uri);
        match sign_jws(proof, &params, self.content, signer).unwrap() {
            JwsProof::Detached(value) => {
                if !self.content.is_empty() {
                    request = request.json_body(self.content.to_vec());
                }
                request = request.header(DETACHED_JWS_HEADER, value);
            }
            JwsProof::Attached(value) => {
                request = request.header("Content-Type", "application/jose");
                request.body = Some(value.into_bytes());
            }
        }
        if let Some(token) = self.token {
            request = request.header("Authorization", format!("GNAP {token}"));
        }
        request
    }
}

const fn grant_call(body: &[u8]) -> Call<'_> {
    Call {
        method: "POST",
        uri: GRANT,
        content: body,
        token: None,
        created: NOW,
    }
}

fn granted(response: &HttpResponse) -> GrantResponse {
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}

fn error_code(response: &HttpResponse) -> String {
    let body: Value = serde_json::from_slice(&response.body).unwrap_or_default();
    body["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn method_name(method: JwsMethod) -> Value {
    json!(method.name())
}

/// Each algorithm and method runs a grant, polls its continuation, rotates the
/// token's value, and revokes it, every request proven with the client's key.
#[test]
fn every_algorithm_runs_a_grant_with_both_methods() {
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        for signer in signers() {
            let case = format!("{} {}", method.name(), signer.algorithm());
            let server = server(true);
            let body = grant_body(signer.as_ref(), &method_name(method));
            let response =
                granted(&server.handle(&grant_call(&body).signed(method, signer.as_ref()), NOW));
            let continuation = response.r#continue.expect("the grant stays open");
            let token = &response.access_token.expect("a token is issued").tokens[0];
            let manage = token.manage.as_ref().expect("the token is manageable");

            let poll = Call {
                method: "POST",
                uri: &continuation.uri,
                content: b"",
                token: Some(continuation.access_token.value.as_str()),
                created: NOW + 5,
            };
            granted(&server.handle(&poll.signed(method, signer.as_ref()), NOW + 5));

            let rotate = Call {
                method: "POST",
                uri: &manage.uri,
                content: b"",
                token: Some(manage.access_token.value.as_str()),
                created: NOW + 6,
            };
            let rotated = granted(&server.handle(&rotate.signed(method, signer.as_ref()), NOW + 6));
            let rotated = &rotated.access_token.unwrap().tokens[0];
            let manage = rotated.manage.as_ref().unwrap();

            let revoke = Call {
                method: "DELETE",
                uri: &manage.uri,
                content: b"",
                token: Some(manage.access_token.value.as_str()),
                created: NOW + 7,
            };
            let response = server.handle(&revoke.signed(method, signer.as_ref()), NOW + 7);
            assert_eq!(response.status, 204, "{case}");
        }
    }
}

/// Discovery announces the JOSE proofs exactly when the server accepts them.
#[test]
fn discovery_follows_the_activation() {
    for (jose, expected) in [
        (false, vec!["httpsig"]),
        (true, vec!["httpsig", "jws", "jwsd"]),
    ] {
        let response = server(jose).handle(&HttpRequest::new("OPTIONS", GRANT), NOW);
        let discovery: AsDiscovery = serde_json::from_slice(&response.body).unwrap();
        let proofs: Vec<String> = discovery
            .key_proofs_supported
            .unwrap()
            .iter()
            .map(|proof| proof.as_str().to_owned())
            .collect();
        assert_eq!(proofs, expected, "jose {jose}");
    }
    let disabled = server(true).with_jose_proofs(false);
    let response = disabled.handle(&HttpRequest::new("OPTIONS", GRANT), NOW);
    assert!(!String::from_utf8_lossy(&response.body).contains("jwsd"));
}

/// Without the activation, a JOSE key is refused as an unsupported proof
/// method, and an attached JWS as an unsupported media type.
#[test]
fn a_server_without_the_activation_refuses_the_jose_proofs() {
    let signer = &signers()[2];
    let server = server(false);
    let body = grant_body(signer.as_ref(), &json!("jwsd"));
    let response = server.handle(
        &grant_call(&body).signed(JwsMethod::Jwsd, signer.as_ref()),
        NOW,
    );
    assert_eq!(error_code(&response), "invalid_client");
    let body = grant_body(signer.as_ref(), &json!("jws"));
    let response = server.handle(
        &grant_call(&body).signed(JwsMethod::Jws, signer.as_ref()),
        NOW,
    );
    assert_eq!(response.status, 415);
}

/// A proof is accepted once, by every server sharing the store.
#[test]
fn a_proof_is_accepted_once_across_servers_sharing_a_store() {
    let signer = &signers()[1];
    let store = Arc::new(MemoryStorage::new());
    let servers: Vec<Server<Arc<MemoryStorage>>> = (0..2)
        .map(|_| {
            AuthorizationServer::new(
                Approve::default(),
                PresentedKey,
                Arc::clone(&store),
                Counted::default(),
                endpoints(),
            )
            .with_jose_proofs(true)
        })
        .collect();
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let body = grant_body(signer.as_ref(), &method_name(method));
        let request = grant_call(&body).signed(method, signer.as_ref());
        granted(&servers[0].handle(&request, NOW));
        let replay = servers[1].handle(&request, NOW + 1);
        assert_eq!(error_code(&replay), "invalid_client", "{}", method.name());
        assert!(String::from_utf8_lossy(&replay.body).contains("already used"));
    }
}

/// An unproven request reaches neither the policy, the nonce source, nor the
/// store, whatever it claims: here an unknown user reference too.
#[test]
fn an_unproven_request_reaches_no_policy_nonce_or_store() {
    let signer = &signers()[0];
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let (policy, nonces, store) = (
            Approve::default(),
            Counted::default(),
            CountingStore::default(),
        );
        let (calls, draws, writes) = (
            Arc::clone(&policy.calls),
            Arc::clone(&nonces.0),
            Arc::clone(&store.writes),
        );
        let server = AuthorizationServer::new(policy, PresentedKey, store, nonces, endpoints())
            .with_jose_proofs(true);
        let mut body: Value =
            serde_json::from_slice(&grant_body(signer.as_ref(), &method_name(method))).unwrap();
        body["user"] = json!("unknown-user");
        let body = serde_json::to_vec(&body).unwrap();
        let other = Es256Signer::generate("rs256-key").unwrap();
        let forged = grant_call(&body).signed(method, &other);
        let response = server.handle(&forged, NOW);
        assert_eq!(error_code(&response), "invalid_client", "{}", method.name());
        let counts = [&calls, &draws, &writes].map(|count| count.load(Ordering::Relaxed));
        assert_eq!(counts, [0, 0, 0], "{}", method.name());

        // Once proven, the same request meets the policy, which refuses the user.
        let response = server.handle(&grant_call(&body).signed(method, signer.as_ref()), NOW);
        assert_eq!(error_code(&response), "unknown_user", "{}", method.name());
        // The counter counts: an accepted grant writes once.
        let accepted = grant_body(signer.as_ref(), &method_name(method));
        granted(&server.handle(
            &grant_call(&accepted).signed(method, signer.as_ref()),
            NOW + 1,
        ));
        assert_eq!(writes.load(Ordering::Relaxed), 1, "{}", method.name());
    }
}

/// The proof has to verify under both the presented JWK and the key the
/// resolver approves: a resolver that answers with another key of the same
/// algorithm and `kid` lets neither that key sign for the JWK, nor a JWK it
/// didn't approve sign in the place of the key it trusts.
#[test]
fn the_proof_needs_the_presented_jwk_and_the_approved_key() {
    struct Trusted;
    impl KeyResolver for Trusted {
        fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
            Some(Box::new(trusted().verifier()))
        }
    }
    fn trusted() -> &'static Ed25519Signer {
        static KEY: OnceLock<Ed25519Signer> = OnceLock::new();
        KEY.get_or_init(|| Ed25519Signer::generate("ed25519-key").unwrap())
    }
    let server = AuthorizationServer::new(
        Approve::default(),
        Trusted,
        MemoryStorage::new(),
        Counted::default(),
        endpoints(),
    )
    .with_jose_proofs(true);
    // An attacker's key, presented under the trusted key's algorithm and `kid`.
    let attacker = &signers()[2];
    let body = grant_body(attacker.as_ref(), &json!("jwsd"));
    for signer in [attacker.as_ref() as &dyn JwkSigner, trusted()] {
        let response = server.handle(&grant_call(&body).signed(JwsMethod::Jwsd, signer), NOW);
        assert_eq!(
            error_code(&response),
            "invalid_client",
            "{}",
            signer.thumbprint()
        );
    }
    // The trusted key, presented and signing, is accepted.
    let body = grant_body(trusted(), &json!("jwsd"));
    granted(&server.handle(&grant_call(&body).signed(JwsMethod::Jwsd, trusted()), NOW));
}

/// What the profile refuses: proof parameters, a client named by reference
/// sending an attached JWS, a JOSE client switching to JSON content, and a
/// key change of a token bound to a JOSE key.
#[test]
fn the_profile_boundaries_are_refused() {
    let signer = &signers()[1];
    let server = server(true);

    let body = grant_body(signer.as_ref(), &json!({"method": "jwsd"}));
    granted(&server.handle(
        &grant_call(&body).signed(JwsMethod::Jwsd, signer.as_ref()),
        NOW,
    ));
    let body = grant_body(signer.as_ref(), &json!({"method": "jwsd", "extra": 1}));
    let response = server.handle(
        &grant_call(&body).signed(JwsMethod::Jwsd, signer.as_ref()),
        NOW,
    );
    assert_eq!(error_code(&response), "invalid_client");
    assert!(String::from_utf8_lossy(&response.body).contains("no parameters"));

    let reference = serde_json::to_vec(&json!({
        "client": "client-reference", "access_token": {"access": ["read"]}
    }))
    .unwrap();
    let response = server.handle(
        &grant_call(&reference).signed(JwsMethod::Jws, signer.as_ref()),
        NOW,
    );
    assert_eq!(error_code(&response), "invalid_client");

    let body = grant_body(signer.as_ref(), &json!("jws"));
    let response = granted(&server.handle(
        &grant_call(&body).signed(JwsMethod::Jws, signer.as_ref()),
        NOW,
    ));
    let continuation = response.r#continue.unwrap();
    let token = &response.access_token.unwrap().tokens[0];
    let modify = Call {
        method: "PATCH",
        uri: &continuation.uri,
        content: br#"{"access_token":{"access":["write"]}}"#,
        token: Some(continuation.access_token.value.as_str()),
        created: NOW + 1,
    };
    let response = server.handle(&modify.signed(JwsMethod::Jwsd, signer.as_ref()), NOW + 1);
    assert_eq!(
        error_code(&response),
        "invalid_client",
        "a jws client sends JSON content"
    );

    let manage = token.manage.as_ref().unwrap();
    let change = Call {
        method: "POST",
        uri: &manage.uri,
        content: br#"{"key":"another"}"#,
        token: Some(manage.access_token.value.as_str()),
        created: NOW + 2,
    };
    let response = server.handle(&change.signed(JwsMethod::Jws, signer.as_ref()), NOW + 2);
    assert_eq!(error_code(&response), "key_rotation_not_supported");
}

/// A detached proof binds the JSON content: content changed after signing is
/// refused, and nothing is stored.
#[test]
fn a_detached_proof_binds_the_content() {
    let signer = &signers()[0];
    let server = server(true);
    let body = grant_body(signer.as_ref(), &json!("jwsd"));
    let mut request = grant_call(&body).signed(JwsMethod::Jwsd, signer.as_ref());
    let mut tampered: Value = serde_json::from_slice(&body).unwrap();
    tampered["access_token"]["access"] = json!(["write"]);
    request.body = Some(serde_json::to_vec(&tampered).unwrap());
    let response = server.handle(&request, NOW);
    assert_eq!(error_code(&response), "invalid_client");
    assert_eq!(server.storage().len().unwrap(), 0);
}

/// The derivation handler leaves an attached JWS to the ordinary grant
/// handler, so a deployment that routes every grant through it still accepts
/// the JOSE proofs it announces.
#[test]
fn the_derivation_handler_serves_an_ordinary_attached_jws() {
    struct NoServers;
    impl gnap_as::ResourceServerResolver for NoServers {
        fn resolve(
            &self,
            _: &gnap_types::rs::ResourceServer,
        ) -> Option<gnap_as::ResolvedResourceServer> {
            None
        }
    }
    struct NoDerivation;
    impl gnap_as::DerivationPolicy for NoDerivation {
        fn evaluate(
            &self,
            _: &GrantRequest,
            _: &gnap_as::ResolvedResourceServer,
            _: &gnap_as::GrantSnapshot,
            _: &gnap_as::TokenRecord,
        ) -> Option<gnap_as::DerivedAccess> {
            None
        }
    }
    let signer = &signers()[1];
    let server = server(true);
    let body = grant_body(signer.as_ref(), &json!("jws"));
    let request = grant_call(&body).signed(JwsMethod::Jws, signer.as_ref());
    let nonces = MemoryStorage::new();
    let response =
        server.handle_grant_with_derivation(&request, &NoServers, &NoDerivation, &nonces, &|| NOW);
    granted(&response);

    // It bounds the body as it does any grant request's, before routing.
    let mut padded: Value = serde_json::from_slice(&body).unwrap();
    padded["padding"] = json!("x".repeat(gnap_as::MAX_GRANT_BODY_BYTES));
    let padded = serde_json::to_vec(&padded).unwrap();
    let request = grant_call(&padded).signed(JwsMethod::Jws, signer.as_ref());
    let response =
        server.handle_grant_with_derivation(&request, &NoServers, &NoDerivation, &nonces, &|| NOW);
    assert_eq!(error_code(&response), "invalid_request");
}
