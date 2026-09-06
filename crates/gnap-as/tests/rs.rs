//! Opaque introspection: separate RS proof, contextual rights and live revisions.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, GrantAggregate, GrantId, GrantSelector,
    GrantSnapshot, GrantStore, IntrospectionDecision, IntrospectionPolicy, KeyResolver,
    MemoryStorage, NonceStore, Nonces, Policy, ResolvedResourceServer, ResourceServerResolver,
    Revision, RsId, Storage, StoreError, TokenRecord,
};
use gnap_client::sign_request;
use gnap_crypto::{
    httpsig::{sign, Component, Message, SignatureInput, Tag},
    proof::{Signer, Verifier},
    ps256::Ps256Signer,
};
use gnap_types::{
    access::AccessItem,
    client::Client,
    http::{HttpRequest, HttpResponse},
    key::KeyObject,
    message::GrantRequest,
    rs::{IntrospectionResponse, ResourceServer},
};
use serde_json::{json, Value};
use std::{
    cell::Cell,
    num::NonZeroU64,
    sync::{Arc, OnceLock},
};

const GRANT: &str = "https://as.example/gnap";
const ENDPOINT: &str = "https://as.example/introspect";

fn client() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| {
        Ps256Signer::from_pkcs1_pem(
            include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
            "shared-kid",
        )
        .unwrap()
    })
}
fn resource_server() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    // Deliberately the same kid, but unrelated cryptographic material.
    KEY.get_or_init(|| Ps256Signer::generate(2048, "shared-kid").unwrap())
}
fn public(key: &Ps256Signer) -> KeyObject {
    serde_json::from_value(json!({"proof":"httpsig", "jwk":key.public_jwk().unwrap()})).unwrap()
}
fn right(name: &str) -> AccessItem {
    AccessItem::Reference(name.into())
}
struct GrantPolicy;
impl Policy for GrantPolicy {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::Approve {
            access: vec![right("read"), right("private")],
            subject: None,
        }
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(20)
    }
}
struct ClientKeys;
impl KeyResolver for ClientKeys {
    fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
        Some(Box::new(client().verifier()))
    }
}
struct RsKeys;
impl ResourceServerResolver for RsKeys {
    fn resolve(&self, rs: &ResourceServer) -> Option<ResolvedResourceServer> {
        (rs.as_reference() == Some("files") || rs.as_value().is_some()).then(|| {
            ResolvedResourceServer {
                id: RsId("files".into()),
                key: public(resource_server()),
            }
        })
    }
}
#[derive(Default)]
struct Counter(Cell<u64>);
impl Nonces for Counter {
    fn next(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("nonce{}", self.0.get())
    }
}
struct RsPolicy {
    calls: Cell<usize>,
    wrong_binding: bool,
    empty_disclosure: bool,
    revoke: Option<Arc<MemoryStorage>>,
    decision: Option<IntrospectionDecision>,
}
impl RsPolicy {
    const fn new() -> Self {
        Self {
            calls: Cell::new(0),
            wrong_binding: false,
            empty_disclosure: false,
            revoke: None,
            decision: None,
        }
    }
}
impl IntrospectionPolicy for RsPolicy {
    fn evaluate(
        &self,
        _: &ResourceServer,
        token: &TokenRecord,
        access: Option<&[AccessItem]>,
    ) -> IntrospectionDecision {
        self.calls.set(self.calls.get() + 1);
        if let Some(decision) = &self.decision {
            return decision.clone();
        }
        if access.is_some_and(|rights| rights.iter().any(|right| right != &self::right("read"))) {
            return IntrospectionDecision::Inactive;
        }
        if let Some(store) = &self.revoke {
            let mut snapshot = store
                .lookup(GrantSelector::AccessToken(token.token.value.as_str()))
                .unwrap()
                .unwrap();
            snapshot.aggregate.tokens.clear();
            snapshot.aggregate.revoked = true;
            snapshot.aggregate.record.continuation_token = None;
            store
                .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
                .unwrap();
        }
        IntrospectionDecision::Active {
            access: if self.empty_disclosure {
                Vec::new()
            } else {
                vec![right("read")]
            },
            key: Some(public(if self.wrong_binding {
                resource_server()
            } else {
                client()
            })),
        }
    }
}
type Server<S = Arc<MemoryStorage>> = AuthorizationServer<GrantPolicy, ClientKeys, S, Counter>;
fn server() -> Server {
    with_storage(Arc::new(MemoryStorage::new()))
}
fn with_storage<S: Storage>(storage: S) -> Server<S> {
    AuthorizationServer::new(
        GrantPolicy,
        ClientKeys,
        storage,
        Counter::default(),
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}
fn issue<S: Storage>(server: &Server<S>) -> Value {
    let body =
        json!({"client":{"key": public(client())}, "access_token":{"access":["read","private"]}});
    let request = sign_request(
        HttpRequest::new("POST", GRANT).json_body(serde_json::to_vec(&body).unwrap()),
        client(),
        None,
        1_000,
    )
    .unwrap();
    let response = server.handle(&request, 1_000);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}
fn query(value: &str, signer: &Ps256Signer, now: u64) -> HttpRequest {
    signed(
        &json!({"resource_server":"files", "access_token":value, "proof":"httpsig", "access":["read"]}),
        signer,
        now,
    )
}
fn signed(body: &Value, signer: &Ps256Signer, now: u64) -> HttpRequest {
    sign_request(
        HttpRequest::new("POST", ENDPOINT).json_body(serde_json::to_vec(body).unwrap()),
        signer,
        None,
        now,
    )
    .unwrap()
}
fn inactive(response: HttpResponse) {
    assert_eq!(response.status, 200);
    assert!(response.has_no_store());
    assert_eq!(
        String::from_utf8(response.body).unwrap(),
        r#"{"active":false}"#
    );
}
fn rs_error(response: HttpResponse, code: &str) {
    assert_eq!(response.status, 400);
    assert!(response.has_no_store());
    assert_eq!(
        serde_json::from_str::<Value>(&String::from_utf8(response.body).unwrap()).unwrap(),
        json!({"error":code})
    );
}

#[test]
fn opaque_issuance_introspection_returns_only_the_rs_view_and_client_binding() {
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    let value = grant["access_token"]["value"].as_str().unwrap();
    let response = api.handle(&query(value, resource_server(), 1_005), 1_005);
    assert_eq!(response.status, 200);
    let wire: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["active"], true);
    assert_eq!(wire["iss"], GRANT);
    assert_eq!(wire["access"], json!(["read"]));
    assert_eq!(wire["iat"], 1_000);
    assert_eq!(wire["exp"], 1_020);
    assert_eq!(wire["key"], serde_json::to_value(public(client())).unwrap());
    for forbidden in ["value", "manage", "continue", "expires_in"] {
        assert!(wire.get(forbidden).is_none());
    }
    assert!(matches!(
        serde_json::from_slice::<IntrospectionResponse>(&response.body).unwrap(),
        IntrospectionResponse::Active(_)
    ));
    assert_eq!(policy.calls.get(), 1);
}

#[test]
fn rs_key_and_client_key_are_not_interchangeable_even_with_the_same_kid() {
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    let value = grant["access_token"]["value"].as_str().unwrap();
    rs_error(
        api.handle(&query(value, client(), 1_005), 1_005),
        "invalid_resource_server",
    );
    assert_eq!(policy.calls.get(), 0);
    let request = query(value, resource_server(), 1_005);
    assert_eq!(
        serde_json::from_slice::<Value>(&api.handle(&request, 1_005).body).unwrap()["active"],
        true
    );
    rs_error(api.handle(&request, 1_005), "invalid_resource_server");
    assert_eq!(policy.calls.get(), 1);
}

#[test]
fn every_request_parameter_is_accounted_for_before_reporting_active() {
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    let base = json!({"resource_server":"files", "access_token":grant["access_token"]["value"]});
    for (name, value) in [
        ("proof", json!("mtls")),
        ("proof", json!("unknown")),
        ("access", json!(["private"])),
        ("access", json!([{"type":"unknown","secret":true}])),
        ("extension", json!(true)),
    ] {
        let mut body = base.clone();
        body[name] = value;
        inactive(api.handle(&signed(&body, resource_server(), 1_005), 1_005));
    }
    // proof is recommended, not required; access is optional.
    assert_eq!(
        serde_json::from_slice::<Value>(
            &api.handle(&signed(&base, resource_server(), 1_005), 1_005)
                .body
        )
        .unwrap()["active"],
        true
    );
}

#[test]
fn unknown_expired_future_and_as_specific_tokens_disclose_nothing() {
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    for value in [
        "unknown",
        grant["continue"]["access_token"]["value"].as_str().unwrap(),
        grant["access_token"]["manage"]["access_token"]["value"]
            .as_str()
            .unwrap(),
    ] {
        inactive(api.handle(&query(value, resource_server(), 1_005), 1_005));
    }
    let value = grant["access_token"]["value"].as_str().unwrap();
    for now in [999, 1_020, 2_000] {
        inactive(api.handle(&query(value, resource_server(), now), now));
    }
    assert_eq!(policy.calls.get(), 0);
}

#[test]
fn a_trusted_policy_cannot_replace_a_known_client_binding() {
    let server = server();
    let grant = issue(&server);
    let mut policy = RsPolicy::new();
    policy.wrong_binding = true;
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    inactive(api.handle(
        &query(
            grant["access_token"]["value"].as_str().unwrap(),
            resource_server(),
            1_005,
        ),
        1_005,
    ));
}

#[test]
fn an_empty_disclosure_still_carries_access_and_the_required_issuer() {
    let server = server();
    let grant = issue(&server);
    let mut policy = RsPolicy::new();
    policy.empty_disclosure = true;
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    let response = api.handle(
        &query(
            grant["access_token"]["value"].as_str().unwrap(),
            resource_server(),
            1_005,
        ),
        1_005,
    );
    let wire: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["active"], true);
    assert_eq!(wire["access"], json!([]));
    assert_eq!(wire["iss"], GRANT);
}

#[test]
fn revocation_between_the_snapshot_and_final_decision_is_not_reported_active() {
    let server = server();
    let grant = issue(&server);
    let mut policy = RsPolicy::new();
    policy.revoke = Some(Arc::clone(server.storage()));
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    inactive(api.handle(
        &query(
            grant["access_token"]["value"].as_str().unwrap(),
            resource_server(),
            1_005,
        ),
        1_005,
    ));
    assert_eq!(policy.calls.get(), 1);
}

#[test]
fn discovery_announces_only_implemented_registered_capabilities() {
    let server = server();
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    let response = api.handle(
        &HttpRequest::new("GET", "https://as.example/.well-known/gnap-as-rs"),
        1_005,
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({"grant_request_endpoint":GRANT,"introspection_endpoint":ENDPOINT,"key_proofs_supported":["httpsig"]})
    );
    assert!(server.storage().is_empty().unwrap());
    assert_eq!(
        api.handle(
            &HttpRequest::new("GET", "https://as.example/.well-known/gnap-as-rs?alias=1"),
            1_005
        )
        .status,
        404
    );
}

#[test]
fn malformed_requests_and_failed_rs_authentication_have_only_an_error_field() {
    let server = server();
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    for body in [
        json!({}),
        json!({"access_token":"test","client":"files"}),
        json!({"access_token":"test","resource_server":"files","proof":null}),
        json!({"access_token":"test","resource_server":"files","access":null}),
    ] {
        rs_error(
            api.handle(&signed(&body, resource_server(), 1_005), 1_005),
            "invalid_request",
        );
    }
    rs_error(
        api.handle(
            &signed(
                &json!({"access_token":"test","resource_server":"unknown"}),
                resource_server(),
                1_005,
            ),
            1_005,
        ),
        "invalid_resource_server",
    );
    let mut request = query("test", resource_server(), 1_005);
    request.body.as_mut().unwrap().push(b' ');
    rs_error(api.handle(&request, 1_005), "invalid_resource_server");
    let mut request = query("test", resource_server(), 1_005);
    request
        .headers
        .push(("Authorization".into(), "GNAP wrong-role".into()));
    rs_error(api.handle(&request, 1_005), "invalid_request");
    let mut request = query("test", resource_server(), 1_005);
    request
        .headers
        .push(("Content-Type".into(), "application/json".into()));
    rs_error(api.handle(&request, 1_005), "invalid_request");
    let oversized = json!({"resource_server":"files","access_token":"test","padding":"x".repeat(gnap_as::rs::MAX_INTROSPECTION_BYTES)});
    rs_error(
        api.handle(&signed(&oversized, resource_server(), 1_005), 1_005),
        "invalid_request",
    );
    assert_eq!(policy.calls.get(), 0);
}

struct FaultyStorage {
    base: MemoryStorage,
    fail_at: Cell<usize>,
    reads: Cell<usize>,
}
impl GrantStore for FaultyStorage {
    fn create_derived(
        &self,
        parent: GrantId,
        revision: Revision,
        value: &gnap_types::token::TokenValue,
        child: GrantAggregate,
        clock: &dyn Fn() -> u64,
    ) -> Result<GrantSnapshot, StoreError> {
        self.base
            .create_derived(parent, revision, value, child, clock)
    }
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        self.base.create(aggregate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        let read = self.reads.get() + 1;
        self.reads.set(read);
        if read == self.fail_at.get() {
            Err(StoreError::Unavailable)
        } else {
            self.base.lookup(selector)
        }
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        aggregate: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        self.base.compare_exchange(id, revision, aggregate)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.base.remove(id, revision)
    }
}
impl NonceStore for FaultyStorage {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.base.remember_nonce(nonce, now)
    }
}

#[test]
fn either_unavailable_snapshot_returns_an_indeterminate_inactive_response() {
    for fail_at in [1, 2] {
        let server = with_storage(FaultyStorage {
            base: MemoryStorage::new(),
            fail_at: Cell::new(usize::MAX),
            reads: Cell::new(0),
        });
        let grant = issue(&server);
        server.storage().reads.set(0);
        server.storage().fail_at.set(fail_at);
        let policy = RsPolicy::new();
        let nonces = MemoryStorage::new();
        let api = server
            .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
            .unwrap();
        inactive(api.handle(
            &query(
                grant["access_token"]["value"].as_str().unwrap(),
                resource_server(),
                1_005,
            ),
            1_005,
        ));
        assert_eq!(server.storage().reads.get(), fail_at);
        assert_eq!(policy.calls.get(), fail_at - 1);
    }
}

fn signature(
    request: &HttpRequest,
    key: &Ps256Signer,
    nonce: Option<&str>,
    label: &str,
) -> (String, String) {
    let message = Message {
        method: &request.method,
        target_uri: &request.url,
        content_digest: request.header_value("content-digest"),
        authorization: None,
        other: Vec::new(),
    };
    sign(
        &message,
        &SignatureInput {
            components: vec![
                Component::Method,
                Component::TargetUri,
                Component::ContentDigest,
            ],
            created: 1_005,
            keyid: key.key_id().into(),
            nonce: nonce.map(str::to_owned),
            tag: Tag::Gnap,
        },
        key,
        label,
    )
    .unwrap()
}

#[test]
fn nonce_less_or_forged_first_signatures_do_not_hide_a_later_valid_rs_proof() {
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    for forged in [false, true] {
        let mut request = query(
            grant["access_token"]["value"].as_str().unwrap(),
            resource_server(),
            1_005,
        );
        let nonce = if forged {
            "forged-first"
        } else {
            "nonce-less-first"
        };
        let first = signature(
            &request,
            if forged { client() } else { resource_server() },
            forged.then_some(nonce),
            "first",
        );
        request.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("signature") && !name.eq_ignore_ascii_case("signature-input")
        });
        request.headers.push(("Signature-Input".into(), first.0));
        request.headers.push(("Signature".into(), first.1));
        rs_error(api.handle(&request, 1_005), "invalid_resource_server");
        let valid = signature(&request, resource_server(), Some(nonce), "second");
        request.headers.push(("Signature-Input".into(), valid.0));
        request.headers.push(("Signature".into(), valid.1));
        assert_eq!(
            serde_json::from_slice::<Value>(&api.handle(&request, 1_005).body).unwrap()["active"],
            true
        );
        rs_error(api.handle(&request, 1_005), "invalid_resource_server");
    }
    assert_eq!(policy.calls.get(), 2);
}

#[test]
fn registration_by_value_is_pinned_to_the_complete_registered_rs_key() {
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    for valid in [false, true] {
        let body = json!({"resource_server":{"key":public(if valid { resource_server() } else { client() })}, "access_token":grant["access_token"]["value"], "proof":"httpsig"});
        let response = api.handle(&signed(&body, resource_server(), 1_005), 1_005);
        if valid {
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body).unwrap()["active"],
                true
            );
        } else {
            rs_error(response, "invalid_resource_server");
        }
    }
    assert_eq!(policy.calls.get(), 1);
}

#[test]
fn rotation_and_grant_delete_retire_the_introspected_values() {
    use gnap_types::token::TokenValue;
    let server = server();
    let grant = issue(&server);
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    let value = grant["access_token"]["value"].as_str().unwrap();
    let management = TokenValue::new(
        grant["access_token"]["manage"]["access_token"]["value"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let rotate = sign_request(
        HttpRequest::new(
            "POST",
            grant["access_token"]["manage"]["uri"].as_str().unwrap(),
        ),
        client(),
        Some(&management),
        1_005,
    )
    .unwrap();
    let response = server.handle(&rotate, 1_005);
    assert_eq!(response.status, 200);
    let rotated: Value = serde_json::from_slice(&response.body).unwrap();
    let new_value = rotated["access_token"]["value"].as_str().unwrap();
    inactive(api.handle(&query(value, resource_server(), 1_005), 1_005));
    assert_eq!(
        serde_json::from_slice::<Value>(
            &api.handle(&query(new_value, resource_server(), 1_005), 1_005)
                .body
        )
        .unwrap()["active"],
        true
    );
    let continuation =
        TokenValue::new(grant["continue"]["access_token"]["value"].as_str().unwrap()).unwrap();
    let revoke = sign_request(
        HttpRequest::new("DELETE", grant["continue"]["uri"].as_str().unwrap()),
        client(),
        Some(&continuation),
        1_006,
    )
    .unwrap();
    assert_eq!(server.handle(&revoke, 1_006).status, 204);
    inactive(api.handle(&query(new_value, resource_server(), 1_006), 1_006));
}

#[test]
fn policy_output_cannot_expand_rights_omit_binding_or_disclose_private_key_material() {
    let server = server();
    let grant = issue(&server);
    let mut private = public(client());
    // Invalid synthetic private material, not an actual secret.
    private
        .jwk
        .as_mut()
        .unwrap()
        .insert("d".into(), json!("AQ"));
    for decision in [
        IntrospectionDecision::Active {
            access: vec![right("expanded")],
            key: Some(public(client())),
        },
        IntrospectionDecision::Active {
            access: vec![right("read")],
            key: None,
        },
        IntrospectionDecision::Active {
            access: vec![right("read")],
            key: Some(private),
        },
        IntrospectionDecision::InvalidAccess,
    ] {
        let expected_error = matches!(decision, IntrospectionDecision::InvalidAccess);
        let mut policy = RsPolicy::new();
        policy.decision = Some(decision);
        let nonces = MemoryStorage::new();
        let api = server
            .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
            .unwrap();
        let response = api.handle(
            &query(
                grant["access_token"]["value"].as_str().unwrap(),
                resource_server(),
                1_005,
            ),
            1_005,
        );
        if expected_error {
            rs_error(response, "invalid_access");
        } else {
            inactive(response);
        }
    }
}

#[test]
fn token_bound_keys_override_the_client_key_and_native_identifiers_are_not_introspected() {
    let server = server();
    let grant = issue(&server);
    let value = grant["access_token"]["value"].as_str().unwrap();
    let mut snapshot = server
        .storage()
        .lookup(GrantSelector::AccessToken(value))
        .unwrap()
        .unwrap();
    snapshot
        .aggregate
        .tokens
        .values_mut()
        .next()
        .unwrap()
        .token
        .key = Some(gnap_types::key::Key::ByValue(Box::new(public(
        resource_server(),
    ))));
    server
        .storage()
        .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        .unwrap();
    let policy = RsPolicy::new(); // Returns client key, not explicit token binding.
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, ENDPOINT)
        .unwrap();
    inactive(api.handle(&query(value, resource_server(), 1_005), 1_005));
    let mut snapshot = server
        .storage()
        .lookup(GrantSelector::AccessToken(value))
        .unwrap()
        .unwrap();
    let record = snapshot.aggregate.tokens.values_mut().next().unwrap();
    record.token.key = None;
    record.identifier = Some(vec![1]);
    server
        .storage()
        .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        .unwrap();
    let before = policy.calls.get();
    inactive(api.handle(&query(value, resource_server(), 1_005), 1_005));
    assert_eq!(policy.calls.get(), before);
}

#[test]
fn discovery_inherits_only_the_explicit_loopback_development_option() {
    let endpoints = Endpoints {
        grant: "http://127.0.0.1:8080/gnap?tenant=1".into(),
        continuation: "http://127.0.0.1:8080/continue".into(),
        interaction: "http://127.0.0.1:8080/interact".into(),
        token_management: "http://127.0.0.1:8080/token".into(),
    };
    let server = AuthorizationServer::new(
        GrantPolicy,
        ClientKeys,
        MemoryStorage::new(),
        Counter::default(),
        endpoints,
    );
    let policy = RsPolicy::new();
    let nonces = MemoryStorage::new();
    let endpoint = "http://127.0.0.1:8080/introspect";
    assert!(server
        .resource_server_api(&RsKeys, &policy, &nonces, endpoint)
        .is_err());
    let server = server.with_development_http_discovery();
    let api = server
        .resource_server_api(&RsKeys, &policy, &nonces, endpoint)
        .unwrap();
    let response = api.handle(
        &HttpRequest::new("GET", "http://127.0.0.1:8080/.well-known/gnap-as-rs"),
        1_005,
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header_value("gnap-development-only"),
        Some("insecure-loopback-discovery")
    );
    assert!(server
        .resource_server_api(
            &RsKeys,
            &policy,
            &nonces,
            "http://remote.example/introspect"
        )
        .is_err());
}
