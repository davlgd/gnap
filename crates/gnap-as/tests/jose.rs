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
    /// Refuses key changes, which it decides on only after their proofs.
    refuses_key_changes: bool,
}
impl Policy for Approve {
    /// Asks for interaction when a new request offers one, and approves
    /// otherwise, a modification included.
    fn evaluate_context(
        &self,
        request: &GrantRequest,
        context: gnap_as::EvaluationContext<'_>,
    ) -> Decision {
        match context {
            gnap_as::EvaluationContext::Initial => self.evaluate(request),
            _ => self.evaluate_after_interaction(request),
        }
    }
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if request.interact.is_some() {
            return Decision::RequireInteraction;
        }
        self.evaluate_after_interaction(request)
    }
    fn evaluate_after_interaction(&self, request: &GrantRequest) -> Decision {
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
    fn may_rotate_key(&self, _: &gnap_as::TokenRecord, _: &gnap_types::key::KeyObject) -> bool {
        !self.refuses_key_changes
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
    /// A key rotation: `previous` signs the request with the rotation `typ`,
    /// and `replacement` signs that JWS.
    fn rotation(
        &self,
        proof: JwsMethod,
        previous: &dyn JwkSigner,
        replacement: &dyn JwkSigner,
    ) -> HttpRequest {
        let params = JwsParams {
            method: self.method,
            target_uri: self.uri,
            created: self.created,
            access_token: self.token,
        };
        let signed = gnap_crypto::jws::sign_jws_rotation(
            proof,
            &params,
            self.content,
            previous,
            replacement,
        )
        .unwrap();
        self.place(signed)
    }

    fn place(&self, proof: JwsProof) -> HttpRequest {
        let mut request = HttpRequest::new(self.method, self.uri);
        match proof {
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

    fn signed(&self, proof: JwsMethod, signer: &dyn JwkSigner) -> HttpRequest {
        let params = JwsParams {
            method: self.method,
            target_uri: self.uri,
            created: self.created,
            access_token: self.token,
        };
        self.place(sign_jws(proof, &params, self.content, signer).unwrap())
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

    // The trusted key under another `kid` is refused: the resolver's key names
    // the `kid` the proof has to carry, as it does for `httpsig`.
    let alias = Alias(trusted());
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let body = grant_body(&alias, &method_name(method));
        let response = server.handle(&grant_call(&body).signed(method, &alias), NOW + 1);
        assert_eq!(error_code(&response), "invalid_client", "{}", method.name());
        assert!(String::from_utf8_lossy(&response.body).contains("kid"));
    }
}

/// A key presented under a `kid` of its own.
struct Alias<'a>(&'a Ed25519Signer);
impl gnap_crypto::Signer for Alias<'_> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, gnap_crypto::ProofError> {
        self.0.sign(data)
    }
    fn key_id(&self) -> &'static str {
        "alias-kid"
    }
    fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }
}
impl JwkSigner for Alias<'_> {
    fn public_jwk(&self) -> Result<serde_json::Map<String, Value>, gnap_crypto::ProofError> {
        let mut jwk = self.0.public_jwk()?;
        jwk.insert("kid".into(), json!("alias-kid"));
        Ok(jwk)
    }
    fn thumbprint(&self) -> String {
        self.0.thumbprint()
    }
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
    assert_eq!(
        error_code(&response),
        "invalid_rotation",
        "an ordinary proof is no nested rotation proof"
    );
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

/// A continuation reads the authenticated content: a modification sent as an
/// attached JWS, or with a detached one, changes the request it signs.
#[test]
fn a_modification_carries_its_authenticated_content() {
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let signer = &signers()[1];
        let server = server(true);
        let body = grant_body(signer.as_ref(), &method_name(method));
        let response =
            granted(&server.handle(&grant_call(&body).signed(method, signer.as_ref()), NOW));
        let continuation = response.r#continue.unwrap();
        let modify = Call {
            method: "PATCH",
            uri: &continuation.uri,
            content: br#"{"access_token":{"access":["write"]}}"#,
            token: Some(continuation.access_token.value.as_str()),
            created: NOW + 5,
        };
        let response = granted(&server.handle(&modify.signed(method, signer.as_ref()), NOW + 5));
        let token = &response
            .access_token
            .expect("the modified request is approved")
            .tokens[0];
        assert_eq!(
            serde_json::to_value(&token.access).unwrap(),
            json!(["write"]),
            "{}",
            method.name()
        );
    }
}

/// A transport that hands each request to the server and keeps what it sent.
struct Direct<'a> {
    server: &'a Server<MemoryStorage>,
    now: std::cell::Cell<u64>,
    sent: std::cell::RefCell<Vec<HttpRequest>>,
}
impl gnap_client::HttpTransport for Direct<'_> {
    type Error = std::convert::Infallible;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        self.sent.borrow_mut().push(request.clone());
        Ok(self.server.handle(&request, self.now.get()))
    }
}

impl<'a> Direct<'a> {
    const fn new(server: &'a Server<MemoryStorage>) -> Self {
        Self {
            server,
            now: std::cell::Cell::new(NOW),
            sent: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Checks that each request sent carries the JOSE proof of `method`, and
    /// nothing of `httpsig`.
    fn assert_jose(&self, method: JwsMethod) {
        for request in self.sent.borrow().iter() {
            let has = |name: &str| request.header_values(name).count();
            assert_eq!(
                has("signature") + has("signature-input") + has("content-digest"),
                0
            );
            let attached = request
                .header_values("content-type")
                .any(|value| value == "application/jose");
            let detached = has(DETACHED_JWS_HEADER);
            match method {
                JwsMethod::Jwsd => assert!(detached == 1 && !attached, "{request:?}"),
                JwsMethod::Jws => assert!(
                    (detached == 1) != attached && has("content-type") <= 1,
                    "{request:?}"
                ),
            }
        }
    }
}

fn session_request(signer: &dyn JwkSigner, method: JwsMethod) -> GrantRequest {
    serde_json::from_value(json!({
        "client": {"key": {"proof": method.name(), "jwk": signer.public_jwk().unwrap()}},
        "access_token": {"access": ["read"]},
        "interact": {"start": ["redirect"], "finish": {
            "method": "redirect", "uri": "https://client.example/cb", "nonce": "client-nonce"
        }}
    }))
    .unwrap()
}

/// A client session proves every request with the method its key declares:
/// the grant, the return from interaction, a modification, the management
/// of its token, and the revocation of the grant.
#[test]
fn a_session_drives_a_grant_with_either_jose_method() {
    use gnap_client::{Session, Step};
    use gnap_types::interact::InteractCallback;
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        for signer in signers() {
            let case = format!("{} {}", method.name(), signer.algorithm());
            let server = server(true);
            let wire = Direct::new(&server);
            let mut client = Session::new(&wire, Arc::clone(signer), GRANT);
            let pending = client
                .start(&session_request(signer.as_ref(), method), NOW)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            let Step::Pending(pending) = pending else {
                panic!("{case}: the policy asks for interaction");
            };
            let handle = pending
                .interact
                .as_ref()
                .unwrap()
                .redirect
                .as_ref()
                .unwrap();
            let handle = handle.rsplit('/').next().unwrap();
            let gnap_as::Finish::Redirect { uri } =
                server.complete_interaction(handle, NOW + 1).unwrap()
            else {
                panic!("{case}: a redirect finish");
            };
            client
                .accept_callback(&InteractCallback::from_redirect(&uri).unwrap(), NOW + 1)
                .unwrap();
            wire.now.set(NOW + 5);
            let approved = client
                .continue_grant(NOW + 5)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            assert!(matches!(approved, Step::Approved(_)), "{case}");

            let changes: gnap_types::message::ContinueRequest =
                serde_json::from_value(json!({"access_token": {"access": ["write"]}})).unwrap();
            wire.now.set(NOW + 10);
            let modified = client
                .modify_grant(&changes, NOW + 10)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            let token = &modified.response().access_token.as_ref().unwrap().tokens[0];
            assert_eq!(
                serde_json::to_value(&token.access).unwrap(),
                json!(["write"]),
                "{case}"
            );

            wire.now.set(NOW + 11);
            client
                .rotate_token(None, NOW + 11)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            wire.now.set(NOW + 12);
            client
                .revoke_token(None, NOW + 12)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            wire.now.set(NOW + 15);
            client
                .revoke_grant(NOW + 15)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            wire.assert_jose(method);
            assert_eq!(wire.sent.borrow().len(), 6, "{case}");
        }
    }
}

/// A session keeps the proof method of its first request: a second start
/// that declares another one is refused before anything is sent, and the
/// grant goes on with the first. A key change isn't supported with JOSE.
#[test]
fn a_session_keeps_its_jose_method() {
    use gnap_client::{ClientError, Session, SharedSigner};
    let signer = &signers()[1];
    let server = server(true);
    let wire = Direct::new(&server);
    let mut client = Session::new(&wire, Arc::clone(signer), GRANT);
    let mut approved = session_request(signer.as_ref(), JwsMethod::Jws);
    approved.interact = None;
    let step = client.start(&approved, NOW).unwrap();
    assert!(matches!(step, gnap_client::Step::Approved(_)), "{step:?}");
    // Another start is refused, with another method as with the same one: it
    // would replace the local state of a grant the AS still holds.
    for method in [JwsMethod::Jwsd, JwsMethod::Jws] {
        let refused = client.start(&session_request(signer.as_ref(), method), NOW + 1);
        assert!(matches!(refused, Err(ClientError::Usage(_))), "{refused:?}");
    }
    assert_eq!(wire.sent.borrow().len(), 1);
    assert_eq!(server.storage().len().unwrap(), 1);

    let first = wire.sent.borrow()[0].clone();
    assert!(first
        .header_values("content-type")
        .any(|v| v == "application/jose"));
    // A replacement the session could present over `httpsig`: only the
    // session's own JOSE proof stops the change.
    let replacement = Arc::new(Es256Signer::generate("replacement").unwrap());
    let key: gnap_types::key::Key = serde_json::from_value(json!({
        "proof": "httpsig", "jwk": replacement.public_jwk().unwrap()
    }))
    .unwrap();
    let refused = client.rotate_key(None, replacement as SharedSigner, &key, NOW + 2);
    assert!(matches!(refused, Err(ClientError::Usage(_))), "{refused:?}");
    assert_eq!(
        wire.sent.borrow().len(),
        1,
        "no request for a refused key change"
    );
}

/// The AS counts two proofs of the same request in the same second as one:
/// sending it again is fresh only from the next second.
#[test]
fn a_jose_retry_is_fresh_from_the_next_second() {
    use gnap_client::Session;
    let signer = &signers()[2];
    let server = server(true);
    let wire = Direct::new(&server);
    let request = session_request(signer.as_ref(), JwsMethod::Jwsd);
    Session::new(&wire, Arc::clone(signer), GRANT)
        .start(&request, NOW)
        .unwrap();
    let again = Session::new(&wire, Arc::clone(signer), GRANT).start(&request, NOW);
    assert!(again.is_err(), "the same second is the same proof");
    wire.now.set(NOW + 1);
    Session::new(&wire, Arc::clone(signer), GRANT)
        .start(&request, NOW + 1)
        .expect("the next second is a new proof");
}

/// An inconclusive start restores the session's local state, not the AS's:
/// when the AS created the grant and its answer was lost, a retry creates a
/// second one.
#[test]
fn a_retry_after_a_lost_answer_can_create_a_second_grant() {
    use gnap_client::{ClientError, HttpTransport, Session};
    struct LosesFirstAnswer<'a> {
        server: &'a Server<MemoryStorage>,
        calls: std::cell::Cell<u32>,
    }
    impl HttpTransport for LosesFirstAnswer<'_> {
        type Error = String;
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            let response = self.server.handle(&request, NOW + u64::from(call));
            if call == 0 {
                return Err("the answer was lost".into());
            }
            Ok(response)
        }
    }
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let signer = &signers()[2];
        let server = server(true);
        let wire = LosesFirstAnswer {
            server: &server,
            calls: std::cell::Cell::new(0),
        };
        let mut approved = session_request(signer.as_ref(), method);
        approved.interact = None;
        let mut client = Session::new(&wire, Arc::clone(signer), GRANT);
        assert!(matches!(
            client.start(&approved, NOW),
            Err(ClientError::Transport(_))
        ));
        assert_eq!(
            server.storage().len().unwrap(),
            1,
            "the AS created the grant"
        );
        client
            .start(&approved, NOW + 1)
            .expect("the session can try again");
        assert_eq!(server.storage().len().unwrap(), 2, "{}", method.name());
    }
}

fn rotating(jose: bool) -> Server<MemoryStorage> {
    server(jose).with_key_rotation(true)
}

fn presented_key(signer: &dyn JwkSigner, method: JwsMethod) -> gnap_types::key::Key {
    serde_json::from_value(json!({"proof": method.name(), "jwk": signer.public_jwk().unwrap()}))
        .unwrap()
}

/// A session changes its token's key to another algorithm, twice, for either
/// JOSE method, and manages the token with each new key; its continuation
/// keeps the grant's key.
#[test]
fn a_session_changes_a_jose_bound_key_twice() {
    use gnap_client::{Session, SharedSigner};
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let keys = signers();
        let server = rotating(true);
        let wire = Direct::new(&server);
        let mut approved = session_request(keys[0].as_ref(), method);
        approved.interact = None;
        let mut client = Session::new(&wire, Arc::clone(&keys[0]), GRANT);
        client.start(&approved, NOW).unwrap();
        for (step, replacement) in keys[1..].iter().enumerate() {
            let at = NOW + 1 + 2 * step as u64;
            let case = format!("{} to {}", method.name(), replacement.algorithm());
            wire.now.set(at);
            let key = presented_key(replacement.as_ref(), method);
            let changed = client
                .rotate_key(None, Arc::clone(replacement) as SharedSigner, &key, at)
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            assert_eq!(changed.key, Some(key), "{case}");
            wire.now.set(at + 1);
            client
                .rotate_token(None, at + 1)
                .unwrap_or_else(|e| panic!("{case}: the new key manages the token: {e}"));
        }
        wire.now.set(NOW + 10);
        client
            .continue_grant(NOW + 10)
            .expect("the grant's key continues it");
        client.revoke_token(None, NOW + 11).unwrap();
        wire.assert_jose(method);
    }
}

/// The token and the request that changes its key, signed by hand.
struct Change {
    server: Server<MemoryStorage>,
    uri: String,
    token: String,
}

impl Change {
    fn new(server: Server<MemoryStorage>, method: JwsMethod, signer: &dyn JwkSigner) -> Self {
        let body = grant_body(signer, &method_name(method));
        let response = granted(&server.handle(&grant_call(&body).signed(method, signer), NOW));
        let token = &response.access_token.unwrap().tokens[0];
        let manage = token.manage.clone().unwrap();
        Self {
            server,
            uri: manage.uri,
            token: manage.access_token.value.as_str().to_owned(),
        }
    }

    fn body(key: &gnap_types::key::Key) -> Vec<u8> {
        serde_json::to_vec(&json!({ "key": key })).unwrap()
    }

    fn call<'a>(&'a self, content: &'a [u8], created: u64) -> Call<'a> {
        Call {
            method: "POST",
            uri: &self.uri,
            content,
            token: Some(&self.token),
            created,
        }
    }
}

/// Each half of the nested proof, and every change of its shape, is refused
/// and leaves the token as it was.
#[test]
fn a_jose_key_change_needs_both_nested_proofs() {
    let (old, new, other) = (&signers()[0], &signers()[1], &signers()[2]);
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let case = method.name();
        let change = Change::new(rotating(true), method, old.as_ref());
        let body = Change::body(&presented_key(new.as_ref(), method));
        let call = change.call(&body, NOW + 1);

        // The new key's ordinary proof alone, the old key's alone, and the
        // nested proof with the keys swapped or with a third key outside.
        for request in [
            call.signed(method, new.as_ref()),
            call.signed(method, old.as_ref()),
            call.rotation(method, new.as_ref(), old.as_ref()),
            call.rotation(method, old.as_ref(), other.as_ref()),
        ] {
            let response = change.server.handle(&request, NOW + 1);
            assert_eq!(error_code(&response), "invalid_rotation", "{case}");
        }

        // Another method for the new key.
        let other_method = if method == JwsMethod::Jws {
            JwsMethod::Jwsd
        } else {
            JwsMethod::Jws
        };
        let switched = Change::body(&presented_key(new.as_ref(), other_method));
        let request = change
            .call(&switched, NOW + 1)
            .rotation(method, old.as_ref(), new.as_ref());
        assert_eq!(
            error_code(&change.server.handle(&request, NOW + 1)),
            "invalid_rotation",
            "{case}"
        );

        // Without content, the nested proof can't pass as a value rotation.
        let request = call.rotation(method, old.as_ref(), new.as_ref());
        let mut cut = HttpRequest::new("POST", &change.uri)
            .header("Authorization", format!("GNAP {}", change.token));
        let compact = match request.body.as_deref() {
            Some(body) if method == JwsMethod::Jws => String::from_utf8(body.to_vec()).unwrap(),
            _ => request
                .header_values(DETACHED_JWS_HEADER)
                .next()
                .unwrap()
                .to_owned(),
        };
        cut = cut.header(DETACHED_JWS_HEADER, compact);
        let response = change.server.handle(&cut, NOW + 1);
        assert_ne!(response.status, 200, "{case}: a cut proof rotates nothing");

        // The genuine one changes the key, once.
        let response = change.server.handle(&request, NOW + 1);
        let rotated = granted(&response);
        assert_eq!(
            rotated.access_token.unwrap().tokens[0].key,
            Some(presented_key(new.as_ref(), method)),
            "{case}"
        );
    }
}

/// A key change is a capability: without it, a valid nested proof is
/// refused as unsupported, and nothing is reserved or changed.
#[test]
fn a_jose_key_change_needs_the_capability() {
    let (old, new) = (&signers()[1], &signers()[2]);
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let change = Change::new(server(true), method, old.as_ref());
        let body = Change::body(&presented_key(new.as_ref(), method));
        let request = change
            .call(&body, NOW + 1)
            .rotation(method, old.as_ref(), new.as_ref());
        let response = change.server.handle(&request, NOW + 1);
        assert_eq!(
            error_code(&response),
            "key_rotation_not_supported",
            "{}",
            method.name()
        );
    }
}

/// The proof of a key change is accepted once, by every server sharing the
/// store; and a server sharing it that doesn't change keys still manages a
/// token bound to the new JOSE key.
#[test]
fn a_jose_key_change_is_single_use_and_its_token_stays_manageable() {
    let (old, new) = (&signers()[0], &signers()[2]);
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let store = Arc::new(MemoryStorage::new());
        let make = |rotation: bool| {
            AuthorizationServer::new(
                Approve::default(),
                PresentedKey,
                Arc::clone(&store),
                Counted::default(),
                endpoints(),
            )
            .with_jose_proofs(true)
            .with_key_rotation(rotation)
        };
        let (changing, managing) = (make(true), make(false));
        let body = grant_body(old.as_ref(), &method_name(method));
        let response =
            granted(&changing.handle(&grant_call(&body).signed(method, old.as_ref()), NOW));
        let manage = response.access_token.unwrap().tokens[0]
            .manage
            .clone()
            .unwrap();
        let content = Change::body(&presented_key(new.as_ref(), method));
        let call = Call {
            method: "POST",
            uri: &manage.uri,
            content: &content,
            token: Some(manage.access_token.value.as_str()),
            created: NOW + 1,
        };
        let request = call.rotation(method, old.as_ref(), new.as_ref());
        let rotated = granted(&changing.handle(&request, NOW + 1));
        let replay = make(true).handle(&request, NOW + 1);
        assert_ne!(replay.status, 200, "{}: the proof was spent", method.name());

        let manage = rotated.access_token.unwrap().tokens[0]
            .manage
            .clone()
            .unwrap();
        let value_rotation = Call {
            method: "POST",
            uri: &manage.uri,
            content: b"",
            token: Some(manage.access_token.value.as_str()),
            created: NOW + 2,
        };
        granted(&managing.handle(&value_rotation.signed(method, new.as_ref()), NOW + 2));
    }
}

/// A session checks both nested proofs under their JWKs before sending: a
/// replacement signer that doesn't hold the presented key is refused, and
/// nothing leaves.
#[test]
fn a_session_checks_its_nested_proofs_before_sending() {
    use gnap_client::{ClientError, Session, SharedSigner};
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let server = rotating(true);
        let wire = Direct::new(&server);
        let mut approved = session_request(signers()[1].as_ref(), method);
        approved.interact = None;
        let mut client = Session::new(&wire, Arc::clone(&signers()[1]), GRANT);
        client.start(&approved, NOW).unwrap();
        // The presented JWK is `ed25519-key`; the signer, another key under
        // that name and algorithm.
        let presented = presented_key(signers()[2].as_ref(), method);
        let impostor: SharedSigner = Arc::new(Ed25519Signer::generate("ed25519-key").unwrap());
        let refused = client.rotate_key(None, impostor, &presented, NOW + 1);
        assert!(matches!(refused, Err(ClientError::Usage(_))), "{refused:?}");
        assert_eq!(
            wire.sent.borrow().len(),
            1,
            "{}: nothing left",
            method.name()
        );
    }
}

/// A resolver may not substitute another key for the one a JOSE key change
/// presents by value.
#[test]
fn a_resolver_cannot_substitute_the_new_jose_key() {
    struct Substitutes;
    impl KeyResolver for Substitutes {
        fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
            PresentedKey.resolve(client)
        }
        fn resolve_token_key(
            &self,
            client: &Client,
            binding: Option<&gnap_types::key::Key>,
        ) -> Option<gnap_as::ResolvedTokenKey> {
            let Some(binding) = binding else {
                return PresentedKey.resolve_token_key(client, None);
            };
            let substitute = signers()[0].as_ref();
            let mut key = binding.as_value()?.clone();
            key.jwk = Some(substitute.public_jwk().unwrap());
            Some(gnap_as::ResolvedTokenKey {
                verifier: Box::new(PublicKey::for_jws(key.jwk.as_ref()?).ok()?),
                key,
            })
        }
    }
    let (old, new) = (&signers()[1], &signers()[2]);
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let server = AuthorizationServer::new(
            Approve::default(),
            Substitutes,
            MemoryStorage::new(),
            Counted::default(),
            endpoints(),
        )
        .with_jose_proofs(true)
        .with_key_rotation(true);
        let body = grant_body(old.as_ref(), &method_name(method));
        let response =
            granted(&server.handle(&grant_call(&body).signed(method, old.as_ref()), NOW));
        let manage = response.access_token.unwrap().tokens[0]
            .manage
            .clone()
            .unwrap();
        let content = Change::body(&presented_key(new.as_ref(), method));
        let call = Call {
            method: "POST",
            uri: &manage.uri,
            content: &content,
            token: Some(manage.access_token.value.as_str()),
            created: NOW + 1,
        };
        let response = server.handle(&call.rotation(method, old.as_ref(), new.as_ref()), NOW + 1);
        assert_eq!(response.status, 500, "{}", method.name());
    }
}

/// A key change's proofs are reserved before the policy decides: once a
/// server sharing the store verified them, they can't be used again, though
/// its policy refused the change and every credential is as it was. A fresh
/// proof then goes through.
#[test]
fn a_jose_key_change_reserves_its_proofs_before_the_policy() {
    let (old, new) = (&signers()[1], &signers()[0]);
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let store = Arc::new(MemoryStorage::new());
        let make = |refuses_key_changes: bool| {
            AuthorizationServer::new(
                Approve {
                    refuses_key_changes,
                    ..Approve::default()
                },
                PresentedKey,
                Arc::clone(&store),
                Counted::default(),
                endpoints(),
            )
            .with_jose_proofs(true)
            .with_key_rotation(true)
        };
        let (refusing, permitting) = (make(true), make(false));
        let body = grant_body(old.as_ref(), &method_name(method));
        let response =
            granted(&permitting.handle(&grant_call(&body).signed(method, old.as_ref()), NOW));
        let manage = response.access_token.unwrap().tokens[0]
            .manage
            .clone()
            .unwrap();
        let content = Change::body(&presented_key(new.as_ref(), method));
        let call = |created| Call {
            method: "POST",
            uri: &manage.uri,
            content: &content,
            token: Some(manage.access_token.value.as_str()),
            created,
        };
        let request = call(NOW + 1).rotation(method, old.as_ref(), new.as_ref());
        let case = method.name();
        assert_eq!(
            error_code(&refusing.handle(&request, NOW + 1)),
            "key_rotation_not_supported",
            "{case}: the policy refuses after the proofs"
        );
        let replay = permitting.handle(&request, NOW + 1);
        assert_eq!(
            error_code(&replay),
            "invalid_rotation",
            "{case}: the proofs are spent"
        );
        let fresh = call(NOW + 2).rotation(method, old.as_ref(), new.as_ref());
        granted(&permitting.handle(&fresh, NOW + 2));
    }
}
