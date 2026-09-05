//! Authenticated resource registration, ownership, retries and bounded failures.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, IntrospectionDecision, IntrospectionPolicy,
    KeyResolver, MemoryResourceSetStore, MemoryStorage, Nonces, Policy, ResolvedResourceServer,
    ResourceRegistrationPolicy, ResourceServerApi, ResourceServerResolver, ResourceSet,
    ResourceSetError, ResourceSetLimits, ResourceSetStore, RsId, TokenRecord,
};
use gnap_client::sign_request;
use gnap_crypto::{proof::Verifier, ps256::Ps256Signer};
use gnap_types::{
    access::AccessItem,
    client::Client,
    http::{HttpRequest, HttpResponse},
    key::KeyObject,
    message::GrantRequest,
    rs::{ResourceRegistrationResponse, ResourceServer},
};
use serde_json::{json, Value};
use std::{cell::Cell, sync::OnceLock};

const GRANT: &str = "https://as.example/gnap";
const INTROSPECT: &str = "https://as.example/introspect";
const REGISTER: &str = "https://as.example/resources";
const DISCOVERY: &str = "https://as.example/.well-known/gnap-as-rs";

fn client() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| {
        Ps256Signer::from_pkcs1_pem(
            include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
            "same-kid",
        )
        .unwrap()
    })
}
fn rs_a() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "same-kid").unwrap())
}
fn rs_b() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "same-kid").unwrap())
}
fn public(key: &Ps256Signer) -> KeyObject {
    serde_json::from_value(json!({"proof":"httpsig","jwk":key.public_jwk().unwrap()})).unwrap()
}
struct Keys;
impl ResourceServerResolver for Keys {
    fn resolve(&self, rs: &ResourceServer) -> Option<ResolvedResourceServer> {
        let (id, key) = if rs.as_reference() == Some("b") {
            ("canonical-b", rs_b())
        } else if matches!(rs.as_reference(), Some("a" | "alias-a")) || rs.as_value().is_some() {
            ("canonical-a", rs_a())
        } else {
            return None;
        };
        Some(ResolvedResourceServer {
            id: RsId(id.into()),
            key: public(key),
        })
    }
}
struct NoClients;
impl KeyResolver for NoClients {
    fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
        None
    }
}
struct DenyGrants;
impl Policy for DenyGrants {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::Deny(gnap_registry::ErrorCode::RequestDenied)
    }
}
struct NoIntrospection;
impl IntrospectionPolicy for NoIntrospection {
    fn evaluate(
        &self,
        _: &ResourceServer,
        _: &TokenRecord,
        _: Option<&[AccessItem]>,
    ) -> IntrospectionDecision {
        // This fixture has no grants. The API is available to each registered RS.
        IntrospectionDecision::Inactive
    }
}
#[derive(Default)]
struct References(Cell<u64>);
impl Nonces for References {
    fn next(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("reference{}", self.0.get())
    }
}
#[derive(Default)]
struct Ownership {
    calls: Cell<usize>,
}
impl ResourceRegistrationPolicy for Ownership {
    fn authorize(&self, rs: &ResolvedResourceServer, access: &[AccessItem]) -> bool {
        self.calls.set(self.calls.get() + 1);
        let allowed: &[&str] = match rs.id.0.as_str() {
            "canonical-a" => &["folder", "archive"],
            "canonical-b" => &["other"],
            _ => return false,
        };
        access.iter().all(|right| matches!(right, AccessItem::Reference(name) if allowed.contains(&name.as_str())))
    }
}
type Server = AuthorizationServer<DenyGrants, NoClients, MemoryStorage, References>;
struct Fixture {
    server: Server,
    nonces: MemoryStorage,
    store: MemoryResourceSetStore,
    references: References,
    policy: Ownership,
}
impl Fixture {
    fn new() -> Self {
        Self {
            server: AuthorizationServer::new(
                DenyGrants,
                NoClients,
                MemoryStorage::new(),
                References::default(),
                Endpoints {
                    grant: GRANT.into(),
                    continuation: "https://as.example/continue".into(),
                    interaction: "https://as.example/interact".into(),
                    token_management: "https://as.example/token".into(),
                },
            ),
            nonces: MemoryStorage::new(),
            store: MemoryResourceSetStore::new(ResourceSetLimits::default()),
            references: References::default(),
            policy: Ownership::default(),
        }
    }
    fn api(&self) -> ResourceServerApi<'_, Keys, NoIntrospection, MemoryStorage> {
        self.server
            .resource_server_api(&Keys, &NoIntrospection, &self.nonces, INTROSPECT)
            .unwrap()
            .with_resource_registration(REGISTER, &self.policy, &self.store, &self.references)
            .unwrap()
    }
}
fn request(body: &Value, signer: &Ps256Signer) -> HttpRequest {
    sign_request(
        HttpRequest::new("POST", REGISTER).json_body(serde_json::to_vec(body).unwrap()),
        signer,
        None,
        1000,
    )
    .unwrap()
}
fn success(response: HttpResponse) -> ResourceRegistrationResponse {
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(response.has_no_store());
    serde_json::from_str(&String::from_utf8(response.body).unwrap()).unwrap()
}
fn error(response: HttpResponse, code: &str) {
    assert_eq!(response.status, 400);
    assert!(response.has_no_store());
    assert_eq!(
        serde_json::from_str::<Value>(&String::from_utf8(response.body).unwrap()).unwrap(),
        json!({"error":code})
    );
}

#[test]
fn registration_is_opt_in_and_discovery_never_advertises_unserved_capabilities() {
    let fixture = Fixture::new();
    let api = fixture
        .server
        .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
        .unwrap();
    assert_eq!(
        api.handle(&HttpRequest::new("POST", REGISTER), 1000).status,
        404
    );
    let metadata: Value =
        serde_json::from_slice(&api.handle(&HttpRequest::new("GET", DISCOVERY), 1000).body)
            .unwrap();
    assert!(metadata.get("resource_registration_endpoint").is_none());
    let metadata: Value = serde_json::from_slice(
        &fixture
            .api()
            .handle(&HttpRequest::new("GET", DISCOVERY), 1000)
            .body,
    )
    .unwrap();
    assert_eq!(metadata["resource_registration_endpoint"], REGISTER);
    assert!(metadata.get("token_formats_supported").is_none());
    for endpoint in [
        INTROSPECT,
        GRANT,
        DISCOVERY,
        "http://as.example/resources",
        "https://as.example/resources#fragment",
    ] {
        assert!(fixture
            .server
            .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
            .unwrap()
            .with_resource_registration(
                endpoint,
                &fixture.policy,
                &fixture.store,
                &fixture.references
            )
            .is_err());
    }
}

#[test]
fn response_loss_fresh_proof_and_owner_aliases_reuse_the_immutable_set() {
    let fixture = Fixture::new();
    let api = fixture.api();
    assert_eq!(fixture.store.lookup("rsr_reference1").unwrap(), None);
    let first_request = request(
        &json!({"resource_server":"a","access":["archive","folder"]}),
        rs_a(),
    );
    let first = success(api.handle(&first_request, 1000));
    assert_eq!(first.introspection_endpoint.as_deref(), Some(INTROSPECT));
    assert!(first.instance_id.is_none());
    let retry = request(
        &json!({"resource_server":"alias-a","access":["folder","archive","folder"],"token_introspection_required":true}),
        rs_a(),
    );
    assert_eq!(success(api.handle(&retry, 1000)), first);
    let by_value = request(
        &json!({"resource_server":{"key":public(rs_a())},"access":["archive","folder"],"token_introspection_required":false}),
        rs_a(),
    );
    assert_eq!(success(api.handle(&by_value, 1000)), first);
    let record = fixture
        .store
        .lookup(&first.resource_reference)
        .unwrap()
        .unwrap();
    assert_eq!(record.owner, RsId("canonical-a".into()));
    assert_eq!(record.access.len(), 2);
    error(api.handle(&first_request, 1000), "invalid_resource_server");
    assert_eq!(fixture.policy.calls.get(), 3);
}

#[test]
fn client_key_same_kid_wrong_owner_and_forged_body_never_register() {
    let fixture = Fixture::new();
    let api = fixture.api();
    for (body, key) in [
        (json!({"resource_server":"a","access":["folder"]}), client()),
        (json!({"resource_server":"b","access":["other"]}), rs_a()),
        (
            json!({"resource_server":"unknown","access":["folder"]}),
            rs_a(),
        ),
        (
            json!({"resource_server":{"key":public(client())},"access":["folder"]}),
            rs_a(),
        ),
    ] {
        error(
            api.handle(&request(&body, key), 1000),
            "invalid_resource_server",
        );
    }
    let mut forged = request(&json!({"resource_server":"a","access":["folder"]}), rs_a());
    forged.body =
        Some(serde_json::to_vec(&json!({"resource_server":"a","access":["archive"]})).unwrap());
    error(api.handle(&forged, 1000), "invalid_resource_server");
    assert_eq!(fixture.policy.calls.get(), 0);
    assert_eq!(fixture.references.0.get(), 0);
    error(
        api.handle(
            &request(&json!({"resource_server":"a","access":["other"]}), rs_a()),
            1000,
        ),
        "invalid_access",
    );
    let other = success(api.handle(
        &request(&json!({"resource_server":"b","access":["other"]}), rs_b()),
        1000,
    ));
    assert_eq!(
        fixture
            .store
            .lookup(&other.resource_reference)
            .unwrap()
            .unwrap()
            .owner,
        RsId("canonical-b".into())
    );
}

#[test]
fn opaque_registration_refuses_every_explicit_format_list_and_unknown_fields() {
    let fixture = Fixture::new();
    let api = fixture.api();
    for formats in [
        json!([]),
        json!(["jwt-signed"]),
        json!(["biscuit"]),
        json!(["opaque"]),
        json!(["unknown-format"]),
    ] {
        error(api.handle(&request(&json!({"resource_server":"a","access":["folder"],"token_formats_supported":formats}), rs_a()), 1000), "invalid_request");
    }
    for body in [
        json!({"resource_server":"a","access":["folder"],"extension":true}),
        json!({"resource_server":{"key":public(rs_a()),"extension":true},"access":["folder"]}),
        json!({"resource_server":"a","access":[]}),
        json!({"resource_server":"a","access":vec!["folder";65]}),
    ] {
        error(api.handle(&request(&body, rs_a()), 1000), "invalid_request");
    }
    assert_eq!(fixture.policy.calls.get(), 0);
    for access in [
        json!(["rsr_reference1"]),
        json!([{"type":"unknown","actions":["read"]}]),
        json!(["folder", "other"]),
    ] {
        error(
            api.handle(
                &request(&json!({"resource_server":"a","access":access}), rs_a()),
                1000,
            ),
            "invalid_access",
        );
    }
    assert_eq!(fixture.references.0.get(), 0);
}

#[test]
fn malformed_requests_are_bounded_before_policy_or_registration() {
    let fixture = Fixture::new();
    let api = fixture.api();
    for body in [
        b"not JSON".to_vec(),
        vec![b' '; 65 * 1024],
        br#"{"resource_server":"a"}"#.to_vec(),
    ] {
        error(
            api.handle(&HttpRequest::new("POST", REGISTER).json_body(body), 1000),
            "invalid_request",
        );
    }
    let signed = request(&json!({"resource_server":"a","access":["folder"]}), rs_a());
    let mut variants = Vec::new();
    let mut duplicate = signed.clone();
    duplicate
        .headers
        .push(("Content-Type".into(), "application/json".into()));
    variants.push(duplicate);
    let mut authorization = signed.clone();
    authorization
        .headers
        .push(("Authorization".into(), "GNAP secret".into()));
    variants.push(authorization);
    let mut wrong_method = signed;
    wrong_method.method = "PUT".into();
    variants.push(wrong_method);
    for request in variants {
        error(api.handle(&request, 1000), "invalid_request");
    }
    assert_eq!(fixture.policy.calls.get(), 0);
    assert_eq!(fixture.references.0.get(), 0);
}

struct FailingStore;
impl ResourceSetStore for FailingStore {
    fn lookup(&self, _: &str) -> Result<Option<ResourceSet>, ResourceSetError> {
        Err(ResourceSetError::Unavailable)
    }
    fn register_or_get(
        &self,
        _: &RsId,
        _: &str,
        _: &[AccessItem],
    ) -> Result<ResourceSet, ResourceSetError> {
        Err(ResourceSetError::Unavailable)
    }
}

fn unavailable(response: HttpResponse) {
    assert_eq!(response.status, 503);
    assert!(response.has_no_store());
    assert!(response
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
            && value == "text/plain; charset=utf-8"));
    assert!(serde_json::from_slice::<Value>(&response.body).is_err());
    assert_eq!(
        String::from_utf8(response.body).unwrap(),
        "resource registration unavailable"
    );
}

#[test]
fn unavailable_storage_and_reference_collision_never_publish_success() {
    let fixture = Fixture::new();
    let api = fixture
        .server
        .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
        .unwrap()
        .with_resource_registration(
            REGISTER,
            &fixture.policy,
            &FailingStore,
            &fixture.references,
        )
        .unwrap();
    unavailable(api.handle(
        &request(&json!({"resource_server":"a","access":["folder"]}), rs_a()),
        1000,
    ));
    let first = fixture
        .store
        .register_or_get(
            &RsId("canonical-b".into()),
            "rsr_reference2",
            &[AccessItem::Reference("other".into())],
        )
        .unwrap();
    unavailable(fixture.api().handle(
        &request(&json!({"resource_server":"a","access":["folder"]}), rs_a()),
        1000,
    ));
    assert_eq!(fixture.store.lookup("rsr_reference2").unwrap(), Some(first));
}

struct FailOnce {
    store: MemoryResourceSetStore,
    fail: Cell<bool>,
    after_commit: bool,
}
impl ResourceSetStore for FailOnce {
    fn lookup(&self, reference: &str) -> Result<Option<ResourceSet>, ResourceSetError> {
        self.store.lookup(reference)
    }
    fn register_or_get(
        &self,
        owner: &RsId,
        candidate: &str,
        access: &[AccessItem],
    ) -> Result<ResourceSet, ResourceSetError> {
        if self.fail.replace(false) {
            if self.after_commit {
                self.store.register_or_get(owner, candidate, access)?;
            }
            return Err(ResourceSetError::Unavailable);
        }
        self.store.register_or_get(owner, candidate, access)
    }
}

#[test]
fn fresh_proof_retry_handles_uncommitted_failure_and_lost_commit_acknowledgement() {
    for after_commit in [false, true] {
        let fixture = Fixture::new();
        let store = FailOnce {
            store: MemoryResourceSetStore::new(ResourceSetLimits::default()),
            fail: Cell::new(true),
            after_commit,
        };
        let api = fixture
            .server
            .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
            .unwrap()
            .with_resource_registration(REGISTER, &fixture.policy, &store, &fixture.references)
            .unwrap();
        let body = json!({"resource_server":"a","access":["folder"]});
        let first = request(&body, rs_a());
        unavailable(api.handle(&first, 1000));
        let committed = store.lookup("rsr_reference1").unwrap();
        assert_eq!(committed.is_some(), after_commit);
        error(api.handle(&first, 1000), "invalid_resource_server");
        let retry = request(&body, rs_a());
        assert_ne!(retry.headers, first.headers);
        let response = success(api.handle(&retry, 1000));
        assert_eq!(
            response.resource_reference,
            if after_commit {
                "rsr_reference1"
            } else {
                "rsr_reference2"
            }
        );
        if let Some(committed) = committed {
            assert_eq!(
                store.lookup(&response.resource_reference).unwrap(),
                Some(committed)
            );
            assert_eq!(store.lookup("rsr_reference2").unwrap(), None);
        }
    }
}

#[test]
fn exhausted_memory_budgets_are_unavailable_not_bad_rs_input() {
    for limits in [
        ResourceSetLimits {
            max_sets: 0,
            ..ResourceSetLimits::default()
        },
        ResourceSetLimits {
            max_record_bytes: 1,
            ..ResourceSetLimits::default()
        },
    ] {
        let fixture = Fixture::new();
        let store = MemoryResourceSetStore::new(limits);
        let api = fixture
            .server
            .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
            .unwrap()
            .with_resource_registration(REGISTER, &fixture.policy, &store, &fixture.references)
            .unwrap();
        unavailable(api.handle(
            &request(&json!({"resource_server":"a","access":["folder"]}), rs_a()),
            1000,
        ));
        assert_eq!(store.lookup("rsr_reference1").unwrap(), None);
    }
}

struct AcceptInput;
impl ResourceRegistrationPolicy for AcceptInput {
    fn authorize(&self, _: &ResolvedResourceServer, _: &[AccessItem]) -> bool {
        // Isolate store input budgets from the deployment's semantic checks.
        true
    }
}

#[test]
fn overdeep_resource_input_is_a_bad_request_not_retryable_unavailability() {
    let fixture = Fixture::new();
    let api = fixture
        .server
        .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
        .unwrap()
        .with_resource_registration(REGISTER, &AcceptInput, &fixture.store, &fixture.references)
        .unwrap();
    // Sixteen arrays plus their scalar leaf: depth 17, beyond the profile's 16.
    let nested = (1..17).fold(json!(true), |inner, _| json!([inner]));
    let signed = request(
        &json!({"resource_server":"a","access":[{"type":"files","nested":nested}]}),
        rs_a(),
    );
    assert!(signed.body.as_ref().unwrap().len() < gnap_as::rs::MAX_REGISTRATION_BYTES);
    error(api.handle(&signed, 1000), "invalid_request");
    assert_eq!(fixture.store.lookup("rsr_reference1").unwrap(), None);
    assert_eq!(fixture.references.0.get(), 1);
    error(api.handle(&signed, 1000), "invalid_resource_server");
}

struct InvalidOwner;
impl ResourceServerResolver for InvalidOwner {
    fn resolve(&self, identity: &ResourceServer) -> Option<ResolvedResourceServer> {
        let mut resolved = Keys.resolve(identity)?;
        resolved.id = RsId(String::new());
        Some(resolved)
    }
}

struct OversizedReference;
impl Nonces for OversizedReference {
    fn next(&self) -> String {
        "x".repeat(257)
    }
}

#[test]
fn invalid_as_owner_and_candidate_remain_redacted_unavailability() {
    let fixture = Fixture::new();
    let api = fixture
        .server
        .resource_server_api(&InvalidOwner, &NoIntrospection, &fixture.nonces, INTROSPECT)
        .unwrap()
        .with_resource_registration(REGISTER, &AcceptInput, &fixture.store, &fixture.references)
        .unwrap();
    let signed = request(&json!({"resource_server":"a","access":["folder"]}), rs_a());
    unavailable(api.handle(&signed, 1000));
    assert_eq!(fixture.store.lookup("rsr_reference1").unwrap(), None);
    let api = fixture
        .server
        .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
        .unwrap()
        .with_resource_registration(REGISTER, &AcceptInput, &fixture.store, &OversizedReference)
        .unwrap();
    unavailable(api.handle(
        &request(&json!({"resource_server":"a","access":["folder"]}), rs_a()),
        1000,
    ));
    assert_eq!(
        fixture
            .store
            .lookup(&format!("rsr_{}", "x".repeat(257)))
            .unwrap(),
        None
    );
}

#[test]
fn resource_node_count_item_count_and_serialized_input_budgets_are_bad_requests() {
    let cases = [
        (
            ResourceSetLimits::default(),
            json!([{"type":"files","nested":vec![true;4096]}]),
        ),
        (
            ResourceSetLimits {
                max_access_items: 1,
                ..ResourceSetLimits::default()
            },
            json!(["folder", "archive"]),
        ),
        (
            ResourceSetLimits {
                max_record_bytes: 64,
                ..ResourceSetLimits::default()
            },
            json!([{"type":"files","nested":"x".repeat(100)}]),
        ),
    ];
    for (limits, access) in cases {
        let fixture = Fixture::new();
        let store = MemoryResourceSetStore::new(limits);
        let api = fixture
            .server
            .resource_server_api(&Keys, &NoIntrospection, &fixture.nonces, INTROSPECT)
            .unwrap()
            .with_resource_registration(REGISTER, &AcceptInput, &store, &fixture.references)
            .unwrap();
        let signed = request(&json!({"resource_server":"a","access":access}), rs_a());
        assert!(signed.body.as_ref().unwrap().len() < gnap_as::rs::MAX_REGISTRATION_BYTES);
        error(api.handle(&signed, 1000), "invalid_request");
        assert_eq!(store.lookup("rsr_reference1").unwrap(), None);
    }
}
