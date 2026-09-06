//! Signed one-hop derivation, exact-token dependencies and bounded storage.

use gnap_as::{
    AuthorizationServer, Decision, DerivationPolicy, DerivedAccess, DerivedGrantStore, Endpoints,
    GrantSelector, GrantSnapshot, GrantStore, IntrospectionDecision, IntrospectionPolicy,
    KeyResolver, MemoryStorage, Nonces, Policy, ResolvedResourceServer, ResourceServerResolver,
    RsId, StoreError, TokenRecord,
};
use gnap_client::sign_request;
use gnap_crypto::{proof::Verifier, ps256::Ps256Signer};
use gnap_types::{
    access::AccessItem,
    client::Client,
    http::{HttpRequest, HttpResponse},
    key::KeyObject,
    message::{GrantRequest, GrantResponse},
    rs::ResourceServer,
    token::{AccessToken, TokenValue},
};
use serde_json::{json, Value};
use std::{
    cell::Cell,
    num::NonZeroU64,
    sync::{Arc, OnceLock},
};

const GRANT: &str = "https://as.example/gnap";
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
fn rs1() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "same-kid").unwrap())
}
fn public(key: &Ps256Signer) -> KeyObject {
    serde_json::from_value(json!({"proof":"httpsig", "jwk":key.public_jwk().unwrap()})).unwrap()
}
fn right(name: &str) -> AccessItem {
    AccessItem::Reference(name.into())
}
struct GrantPolicy;
impl Policy for GrantPolicy {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        let requested = request.access_token.as_ref().unwrap();
        if requested.cardinality == gnap_types::token::Cardinality::Multiple {
            return Decision::ApproveTokens {
                tokens: requested
                    .tokens
                    .iter()
                    .map(|token| gnap_as::TokenApproval {
                        requested_label: token.label.clone(),
                        access: token.access.clone(),
                    })
                    .collect(),
                subject: None,
            };
        }
        Decision::Approve {
            access: request.access_token.as_ref().unwrap().tokens[0]
                .access
                .clone(),
            subject: None,
        }
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(1200)
    }
}
#[derive(Clone, Copy)]
enum Management {
    Correct,
    Missing,
    Wrong,
}
struct Keys(Management);
impl KeyResolver for Keys {
    fn resolve(&self, identity: &Client) -> Option<Box<dyn Verifier>> {
        match identity.as_reference()? {
            "client" => Some(Box::new(client().verifier())),
            "rs1" | "rs2" => match self.0 {
                Management::Correct => Some(Box::new(rs1().verifier())),
                Management::Wrong => Some(Box::new(client().verifier())),
                Management::Missing => None,
            },
            _ => None,
        }
    }
}
struct RsKeys;
impl ResourceServerResolver for RsKeys {
    fn resolve(&self, identity: &ResourceServer) -> Option<ResolvedResourceServer> {
        let name = identity.as_reference()?;
        ["rs1", "rs2", "other"]
            .contains(&name)
            .then(|| ResolvedResourceServer {
                id: RsId(name.into()),
                key: public(rs1()),
            })
    }
}
#[derive(Default)]
struct Counter(Cell<u64>);
impl Nonces for Counter {
    fn next(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("opaque{}", self.0.get())
    }
}
type Server = AuthorizationServer<GrantPolicy, Keys, Arc<MemoryStorage>, Counter>;
fn server_with_keys(mode: Management) -> Server {
    AuthorizationServer::new(
        GrantPolicy,
        Keys(mode),
        Arc::new(MemoryStorage::new()),
        Counter::default(),
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}
fn server() -> Server {
    server_with_keys(Management::Correct)
}
struct Mapping;
impl DerivationPolicy for Mapping {
    fn evaluate(
        &self,
        request: &GrantRequest,
        rs: &ResolvedResourceServer,
        _: &GrantSnapshot,
        token: &TokenRecord,
    ) -> Option<DerivedAccess> {
        (rs.id.0 == "rs1"
            && token.token.access.as_deref() == Some(&[right("folder")])
            && request.access_token.as_ref()?.tokens[0].access == [right("metadata")])
        .then(|| DerivedAccess {
            access: vec![right("metadata")],
            audience: RsId("rs2".into()),
        })
    }
}
fn signed(body: &Value, signer: &Ps256Signer, now: u64) -> HttpRequest {
    sign_request(
        HttpRequest::new("POST", GRANT).json_body(serde_json::to_vec(body).unwrap()),
        signer,
        None,
        now,
    )
    .unwrap()
}
fn decoded(response: &HttpResponse) -> GrantResponse {
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}
fn token(response: &HttpResponse) -> AccessToken {
    decoded(response).access_token.unwrap().tokens.remove(0)
}
fn issue(server: &Server) -> GrantResponse {
    decoded(&server.handle(
        &signed(
            &json!({"client":"client","access_token":{"access":["folder"]}}),
            client(),
            1000,
        ),
        1000,
    ))
}
fn body(parent: &AccessToken) -> Value {
    json!({"client":"rs1", "existing_access_token":parent.value, "access_token":{"access":["metadata"]}})
}
fn derive(server: &Server, nonces: &MemoryStorage, parent: &AccessToken, now: u64) -> HttpResponse {
    server.handle_grant_with_derivation(
        &signed(&body(parent), rs1(), now),
        &RsKeys,
        &Mapping,
        nonces,
        &|| now,
    )
}
fn snapshot(server: &Server, value: &TokenValue) -> GrantSnapshot {
    server
        .storage()
        .lookup(GrantSelector::AccessToken(value.as_str()))
        .unwrap()
        .unwrap()
}
fn absent(server: &Server, token: &AccessToken) {
    assert!(server
        .storage()
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .is_none());
    assert!(server
        .storage()
        .lookup(GrantSelector::Management(
            token
                .manage
                .as_ref()
                .unwrap()
                .uri
                .rsplit('/')
                .next()
                .unwrap()
        ))
        .unwrap()
        .is_none());
}
fn manage(
    server: &Server,
    token: &AccessToken,
    method: &str,
    signer: &Ps256Signer,
    now: u64,
) -> HttpResponse {
    let manage = token.manage.as_ref().unwrap();
    server.handle(
        &sign_request(
            HttpRequest::new(method, &manage.uri),
            signer,
            Some(&manage.access_token.value),
            now,
        )
        .unwrap(),
        now,
    )
}

#[test]
fn distinct_child_is_bound_to_rs_and_does_not_store_parent_secret() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let response = derive(&server, &MemoryStorage::new(), &parent, 1000);
    let grant = decoded(&response);
    assert!(grant.r#continue.is_none() && grant.interact.is_none() && grant.subject.is_none());
    let child = token(&response);
    assert_eq!(child.expires_in, Some(60));
    assert_eq!(child.key.as_ref().unwrap().as_value(), Some(&public(rs1())));
    assert_eq!(child.access, Some(vec![right("metadata")]));
    let stored = snapshot(&server, &child.value);
    assert_ne!(stored.id, snapshot(&server, &parent.value).id);
    assert!(!format!("{:?}", stored.aggregate.record.request).contains(parent.value.as_str()));
    assert!(!serde_json::to_string(&stored.aggregate.record.request)
        .unwrap()
        .contains(parent.value.as_str()));
    assert!(stored
        .aggregate
        .record
        .request
        .existing_access_token
        .is_none());
    let metadata = stored
        .aggregate
        .tokens
        .values()
        .next()
        .unwrap()
        .derivation
        .as_ref()
        .unwrap();
    assert_eq!(
        metadata.parent,
        gnap_as::ParentToken::new(snapshot(&server, &parent.value).id, &parent.value)
    );
    assert!(!format!("{metadata:?}").contains(parent.value.as_str()));
}

#[test]
fn replay_does_not_create_another_child_but_fresh_proof_can() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let nonces = MemoryStorage::new();
    let request = signed(&body(&parent), rs1(), 1000);
    let first = server.handle_grant_with_derivation(&request, &RsKeys, &Mapping, &nonces, &|| 1000);
    assert_eq!(first.status, 200);
    assert_eq!(
        server
            .handle_grant_with_derivation(&request, &RsKeys, &Mapping, &nonces, &|| 1000)
            .status,
        400
    );
    assert_ne!(
        token(&first).value,
        token(&derive(&server, &nonces, &parent, 1000)).value
    );
}

#[test]
fn unsupported_parameters_and_explicit_null_never_fall_back_to_ordinary_grant() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let request = signed(&body(&parent), rs1(), 1000);
    assert_eq!(server.handle(&request, 1000).status, 400);
    for (field, value) in [
        ("existing_access_token", Value::Null),
        ("interact", json!({})),
        ("interact", Value::Null),
        ("user", Value::Null),
        ("subject", json!({})),
        ("unknown", json!(true)),
    ] {
        let mut malformed = body(&parent);
        malformed[field] = value;
        let response = server.handle_grant_with_derivation(
            &signed(&malformed, rs1(), 1000),
            &RsKeys,
            &Mapping,
            &MemoryStorage::new(),
            &|| 1000,
        );
        assert_eq!(response.status, 400, "{field}");
        assert!(!String::from_utf8_lossy(&response.body).contains(parent.value.as_str()));
    }
    let mut extension = body(&parent);
    extension["access_token"]["unknown"] = json!(true);
    let parsed: GrantRequest = serde_json::from_value(extension.clone()).unwrap();
    assert!(parsed.access_token.unwrap().tokens[0]
        .extra
        .contains_key("unknown"));
    assert_eq!(
        server
            .handle_grant_with_derivation(
                &signed(&extension, rs1(), 1000),
                &RsKeys,
                &Mapping,
                &MemoryStorage::new(),
                &|| 1000
            )
            .status,
        400
    );
}

#[test]
fn rs_identity_requires_its_key_not_a_client_key_with_same_kid() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    assert_eq!(
        server
            .handle_grant_with_derivation(
                &signed(&body(&parent), client(), 1000),
                &RsKeys,
                &Mapping,
                &MemoryStorage::new(),
                &|| 1000
            )
            .status,
        400
    );
}

#[test]
fn management_resolver_configuration_fails_before_parent_lookup() {
    for mode in [Management::Missing, Management::Wrong] {
        let server = server_with_keys(mode);
        let parent = issue(&server).access_token.unwrap().tokens.remove(0);
        let before = snapshot(&server, &parent.value);
        let response = derive(&server, &MemoryStorage::new(), &parent, 1000);
        assert_eq!(response.status, 500);
        assert!(response.has_no_store());
        assert!(serde_json::from_slice::<Value>(&response.body).is_err());
        let mut unknown = body(&parent);
        unknown["existing_access_token"] = json!("unknown");
        let other = server.handle_grant_with_derivation(
            &signed(&unknown, rs1(), 1000),
            &RsKeys,
            &Mapping,
            &MemoryStorage::new(),
            &|| 1000,
        );
        assert_eq!(response.body, other.body);
        assert_eq!(before.revision, snapshot(&server, &parent.value).revision);
    }
}

#[test]
fn two_different_valid_signatures_do_not_make_different_resolvers_coherent() {
    let server = server_with_keys(Management::Wrong);
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let mut request = signed(&body(&parent), rs1(), 1000);
    let other = signed(&body(&parent), client(), 1000);
    for (name, value) in other.headers {
        if name.eq_ignore_ascii_case("signature") || name.eq_ignore_ascii_case("signature-input") {
            let (_, value) = value.split_once('=').unwrap();
            request.headers.push((name, format!("management={value}")));
        }
    }
    let response = server.handle_grant_with_derivation(
        &request,
        &RsKeys,
        &Mapping,
        &MemoryStorage::new(),
        &|| 1000,
    );
    assert_eq!(response.status, 500);
    assert!(
        String::from_utf8_lossy(&response.body).contains("inconsistent downstream management key")
    );
}

#[test]
fn child_management_delete_does_not_touch_parent_and_rotation_is_refused() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let before = snapshot(&server, &child.value);
    let response = manage(&server, &child, "POST", rs1(), 1001);
    assert_eq!(response.status, 400);
    assert!(String::from_utf8_lossy(&response.body).contains("invalid_rotation"));
    assert_eq!(before.revision, snapshot(&server, &child.value).revision);
    assert_eq!(manage(&server, &child, "DELETE", rs1(), 1001).status, 204);
    absent(&server, &child);
    assert_eq!(
        snapshot(&server, &parent.value).revision,
        gnap_as::Revision(0)
    );
}

#[test]
fn a_sibling_lifecycle_does_not_revoke_another_tokens_child() {
    for method in ["POST", "DELETE"] {
        let server = server();
        let issued = decoded(&server.handle(
            &signed(
                &json!({"client":"client", "access_token":[
                    {"label":"documents", "access":["folder"]},
                    {"label":"reports", "access":["reports"]}
                ]}),
                client(),
                1000,
            ),
            1000,
        ));
        let tokens = issued.access_token.unwrap().tokens;
        let documents = &tokens[0];
        let reports = &tokens[1];
        let child = token(&derive(&server, &MemoryStorage::new(), documents, 1000));
        let child_before = snapshot(&server, &child.value);
        assert_eq!(
            manage(&server, reports, method, client(), 1001).status,
            if method == "POST" { 200 } else { 204 }
        );
        absent(&server, reports);
        snapshot(&server, &documents.value);
        assert_eq!(
            snapshot(&server, &child.value).revision,
            child_before.revision
        );
        assert_eq!(
            manage(&server, documents, "DELETE", client(), 1002).status,
            204
        );
        absent(&server, documents);
        absent(&server, &child);
        assert!(matches!(
            server.storage().compare_exchange(
                child_before.id,
                child_before.revision,
                child_before.aggregate
            ),
            Err(StoreError::Conflict)
        ));
    }
}

#[test]
fn reapproving_a_batch_cascades_old_children_but_keeps_new_parents_live() {
    let server = server();
    let wanted = json!([
        {"label":"documents", "access":["folder"]},
        {"label":"reports", "access":["reports"]}
    ]);
    let issued = decoded(&server.handle(
        &signed(
            &json!({"client":"client", "access_token":wanted}),
            client(),
            1000,
        ),
        1000,
    ));
    let old = issued.access_token.unwrap().tokens;
    let child = token(&derive(&server, &MemoryStorage::new(), &old[0], 1000));
    let continuation = issued.r#continue.unwrap();
    let patch = sign_request(
        HttpRequest::new("PATCH", &continuation.uri)
            .json_body(serde_json::to_vec(&json!({"access_token":wanted})).unwrap()),
        client(),
        Some(&continuation.access_token.value),
        1005,
    )
    .unwrap();
    let approved = decoded(&server.handle(&patch, 1005));
    absent(&server, &child);
    for previous in old {
        absent(&server, &previous);
    }
    let new = approved.access_token.unwrap().tokens;
    assert_eq!(new.len(), 2);
    for current in &new {
        snapshot(&server, &current.value);
    }
    let next_child = token(&derive(&server, &MemoryStorage::new(), &new[0], 1006));
    snapshot(&server, &next_child.value);
}

#[test]
fn token_rotation_and_parent_delete_cascade_without_stale_resurrection() {
    for method in ["POST", "DELETE"] {
        let server = server();
        let parent = issue(&server).access_token.unwrap().tokens.remove(0);
        let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
        let stale = snapshot(&server, &child.value);
        assert_eq!(
            manage(&server, &parent, method, client(), 1001).status,
            if method == "POST" { 200 } else { 204 }
        );
        absent(&server, &parent);
        absent(&server, &child);
        let current = server
            .storage()
            .lookup(GrantSelector::Id(stale.id))
            .unwrap()
            .unwrap();
        assert!(current.aggregate.revoked);
        assert!(matches!(
            server
                .storage()
                .compare_exchange(stale.id, stale.revision, stale.aggregate),
            Err(StoreError::Conflict)
        ));
    }
}

#[test]
fn continuation_only_preserves_children_but_delete_revokes_everything() {
    let server = server();
    let grant = issue(&server);
    let parent = grant
        .access_token
        .unwrap()
        .tokens
        .into_iter()
        .next()
        .unwrap();
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let continuation = grant.r#continue.unwrap();
    let poll = sign_request(
        HttpRequest::new("POST", &continuation.uri),
        client(),
        Some(&continuation.access_token.value),
        1005,
    )
    .unwrap();
    let response = decoded(&server.handle(&poll, 1005));
    assert!(response.access_token.is_none());
    snapshot(&server, &child.value);
    let continuation = response.r#continue.unwrap();
    let revoke = sign_request(
        HttpRequest::new("DELETE", &continuation.uri),
        client(),
        Some(&continuation.access_token.value),
        1010,
    )
    .unwrap();
    assert_eq!(server.handle(&revoke, 1010).status, 204);
    absent(&server, &parent);
    absent(&server, &child);
}

#[test]
fn maintenance_removal_cascades_and_ordinary_revision_change_preserves_child() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let mut before = snapshot(&server, &parent.value);
    before.aggregate.record.interact_handle = Some("new-interaction".into());
    let after = server
        .storage()
        .compare_exchange(before.id, before.revision, before.aggregate)
        .unwrap();
    snapshot(&server, &child.value);
    server.storage().remove(after.id, after.revision).unwrap();
    absent(&server, &child);
}

#[test]
fn eight_live_children_limit_does_not_count_expired_index_entries() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let nonces = MemoryStorage::new();
    let children: Vec<_> = (0..8)
        .map(|_| token(&derive(&server, &nonces, &parent, 1000)))
        .collect();
    let response = derive(&server, &nonces, &parent, 1000);
    assert_eq!(response.status, 400);
    assert!(String::from_utf8_lossy(&response.body).contains("request_denied"));
    let fresh = token(&derive(&server, &nonces, &parent, 1061));
    assert_eq!(fresh.expires_in, Some(60));
    for child in children {
        let retained = snapshot(&server, &child.value);
        assert!(!retained
            .aggregate
            .tokens
            .values()
            .next()
            .unwrap()
            .is_valid_at(1061));
    }
}

#[test]
fn parent_remaining_lifetime_and_commit_clock_are_enforced() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    assert_eq!(
        token(&derive(&server, &MemoryStorage::new(), &parent, 2190)).expires_in,
        Some(10)
    );
    let times = Cell::new(0);
    let response = server.handle_grant_with_derivation(
        &signed(&body(&parent), rs1(), 2190),
        &RsKeys,
        &Mapping,
        &MemoryStorage::new(),
        &|| {
            times.set(times.get() + 1);
            if times.get() < 3 {
                2190
            } else {
                2200
            }
        },
    );
    assert_eq!(response.status, 400);
    assert_eq!(times.get(), 3);
}

struct RacingPolicy(Arc<MemoryStorage>);
impl DerivationPolicy for RacingPolicy {
    fn evaluate(
        &self,
        request: &GrantRequest,
        rs: &ResolvedResourceServer,
        parent: &GrantSnapshot,
        token: &TokenRecord,
    ) -> Option<DerivedAccess> {
        let decision = Mapping.evaluate(request, rs, parent, token);
        let mut replacement = parent.aggregate.clone();
        replacement.tokens.clear();
        self.0
            .compare_exchange(parent.id, parent.revision, replacement)
            .unwrap();
        decision
    }
}
#[test]
fn parent_revoked_between_policy_and_commit_cannot_publish_child() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let response = server.handle_grant_with_derivation(
        &signed(&body(&parent), rs1(), 1000),
        &RsKeys,
        &RacingPolicy(server.storage().clone()),
        &MemoryStorage::new(),
        &|| 1000,
    );
    assert_eq!(response.status, 400);
    absent(&server, &parent);
}

struct Disclosure;
impl IntrospectionPolicy for Disclosure {
    fn evaluate(
        &self,
        _: &ResourceServer,
        token: &TokenRecord,
        _: Option<&[AccessItem]>,
    ) -> IntrospectionDecision {
        IntrospectionDecision::Active {
            access: token.token.access.clone().unwrap(),
            key: Some(public(rs1())),
        }
    }
}
#[test]
fn sdk_enforces_child_audience_before_a_permissive_introspection_policy() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let nonces = MemoryStorage::new();
    let api = server
        .resource_server_api(
            &RsKeys,
            &Disclosure,
            &nonces,
            "https://as.example/introspect",
        )
        .unwrap();
    for rs in ["rs1", "rs2", "other"] {
        let request = sign_request(HttpRequest::new("POST", "https://as.example/introspect")
            .json_body(serde_json::to_vec(&json!({"resource_server":rs,"access_token":child.value,"proof":"httpsig","access":["metadata"]})).unwrap()), rs1(), None, 1000).unwrap();
        let response = api.handle(&request, 1000);
        assert_eq!(response.status, 200);
        let decoded: Value = serde_json::from_slice(&response.body).unwrap();
        if rs == "rs2" {
            assert_eq!(decoded["key"], serde_json::to_value(public(rs1())).unwrap());
        } else {
            assert_eq!(decoded, json!({"active":false}));
        }
    }
}

struct SelfAudience;
impl DerivationPolicy for SelfAudience {
    fn evaluate(
        &self,
        _: &GrantRequest,
        rs: &ResolvedResourceServer,
        _: &GrantSnapshot,
        _: &TokenRecord,
    ) -> Option<DerivedAccess> {
        Some(DerivedAccess {
            access: vec![right("metadata")],
            audience: rs.id.clone(),
        })
    }
}
#[test]
fn unusable_parents_wrong_rs_and_second_hop_have_identical_denials() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let mut unknown = body(&parent);
    unknown["existing_access_token"] = json!("unknown");
    let baseline = server.handle_grant_with_derivation(
        &signed(&unknown, rs1(), 1000),
        &RsKeys,
        &Mapping,
        &MemoryStorage::new(),
        &|| 1000,
    );
    assert_eq!(baseline.status, 400);
    let mut wrong_rs = body(&parent);
    wrong_rs["client"] = json!("rs2");
    let mut unmapped = body(&parent);
    unmapped["access_token"]["access"] = json!(["admin"]);
    for body in [body(&child), wrong_rs, unmapped] {
        let response = server.handle_grant_with_derivation(
            &signed(&body, rs1(), 1000),
            &RsKeys,
            &Mapping,
            &MemoryStorage::new(),
            &|| 1000,
        );
        assert_eq!(response.status, baseline.status);
        assert_eq!(response.body, baseline.body);
    }
    let self_audience = server.handle_grant_with_derivation(
        &signed(&body(&parent), rs1(), 1000),
        &RsKeys,
        &SelfAudience,
        &MemoryStorage::new(),
        &|| 1000,
    );
    assert_eq!(self_audience.body, baseline.body);
    assert_eq!(
        derive(&server, &MemoryStorage::new(), &parent, 2200).body,
        baseline.body
    );
    assert_eq!(
        manage(&server, &parent, "DELETE", client(), 1001).status,
        204
    );
    assert_eq!(
        derive(&server, &MemoryStorage::new(), &parent, 1001).body,
        baseline.body
    );
}

#[test]
fn bearer_unlimited_and_overflowing_parent_lifetimes_are_refused() {
    for mode in 0..3 {
        let server = server();
        let parent = issue(&server).access_token.unwrap().tokens.remove(0);
        let mut stored = snapshot(&server, &parent.value);
        let record = stored.aggregate.tokens.values_mut().next().unwrap();
        match mode {
            0 => record
                .token
                .flags
                .push(gnap_registry::AccessTokenFlag::Bearer),
            1 => record.token.expires_in = None,
            _ => record.token.expires_in = Some(u64::MAX),
        }
        server
            .storage()
            .compare_exchange(stored.id, stored.revision, stored.aggregate)
            .unwrap();
        let response = derive(&server, &MemoryStorage::new(), &parent, 1000);
        assert_eq!(response.status, 400);
        assert!(String::from_utf8_lossy(&response.body).contains("request_denied"));
    }
}

fn fresh_candidate(
    template: &gnap_as::GrantAggregate,
    sequence: u64,
    now: u64,
) -> gnap_as::GrantAggregate {
    let mut candidate = template.clone();
    let (_, mut token) = candidate.tokens.drain().next().unwrap();
    token.issued_at = now;
    token.token.value = TokenValue::new(format!("candidate{sequence}")).unwrap();
    token.management_token = format!("management{sequence}");
    let manage = token.token.manage.as_mut().unwrap();
    manage.uri = format!("https://as.example/token/handle{sequence}");
    manage.access_token =
        gnap_types::token::BoundToken::new(TokenValue::new(&token.management_token).unwrap());
    candidate.tokens.insert(format!("handle{sequence}"), token);
    candidate
}

#[test]
fn store_rejects_cross_grant_collisions_invalid_ttl_and_reparenting() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let parent_snapshot = snapshot(&server, &parent.value);
    let stored = snapshot(&server, &child.value);
    for mutation in 0..5 {
        let mut candidate = fresh_candidate(&stored.aggregate, 100, 1000);
        let record = candidate.tokens.values_mut().next().unwrap();
        match mutation {
            0 => record.token.value = parent.value.clone(),
            1 => record.token.value = parent.manage.as_ref().unwrap().access_token.value.clone(),
            2 => record.token.expires_in = None,
            3 => record.token.expires_in = Some(u64::MAX),
            _ => record.derivation.as_mut().unwrap().parent.value_hash = [0; 32],
        }
        let result = server.storage().create_derived(
            parent_snapshot.id,
            parent_snapshot.revision,
            &parent.value,
            candidate,
            &|| 1000,
        );
        assert!(matches!(
            result,
            Err(StoreError::Collision | StoreError::Invalid)
        ));
        assert!(server
            .storage()
            .lookup(GrantSelector::AccessToken("candidate100"))
            .unwrap()
            .is_none());
        assert_eq!(
            snapshot(&server, &parent.value).revision,
            parent_snapshot.revision
        );
        assert_eq!(snapshot(&server, &child.value).revision, stored.revision);
    }
    let mut cleared = stored.aggregate.clone();
    cleared.tokens.values_mut().next().unwrap().derivation = None;
    assert!(matches!(
        server
            .storage()
            .compare_exchange(stored.id, stored.revision, cleared),
        Err(StoreError::Invalid)
    ));
    let mut grandchild = fresh_candidate(&stored.aggregate, 100, 1000);
    grandchild
        .tokens
        .values_mut()
        .next()
        .unwrap()
        .derivation
        .as_mut()
        .unwrap()
        .parent = gnap_as::ParentToken::new(stored.id, &child.value);
    assert!(matches!(
        server.storage().create_derived(
            stored.id,
            stored.revision,
            &child.value,
            grandchild,
            &|| 1000
        ),
        Err(StoreError::Invalid)
    ));
}

#[test]
fn total_retained_derived_grants_are_bounded_and_maintenance_releases_capacity() {
    let server = server();
    let parent = issue(&server).access_token.unwrap().tokens.remove(0);
    let mut original = snapshot(&server, &parent.value);
    original
        .aggregate
        .tokens
        .values_mut()
        .next()
        .unwrap()
        .token
        .expires_in = Some(100_000);
    let parent_snapshot = server
        .storage()
        .compare_exchange(original.id, original.revision, original.aggregate)
        .unwrap();
    let child = token(&derive(&server, &MemoryStorage::new(), &parent, 1000));
    let stored = snapshot(&server, &child.value);
    for sequence in 1..256 {
        let now = 1000 + (sequence / 8) * 61;
        server
            .storage()
            .create_derived(
                parent_snapshot.id,
                parent_snapshot.revision,
                &parent.value,
                fresh_candidate(&stored.aggregate, sequence, now),
                &|| now,
            )
            .unwrap();
    }
    let now = 4000;
    let candidate = fresh_candidate(&stored.aggregate, 257, now);
    assert!(matches!(
        server.storage().create_derived(
            parent_snapshot.id,
            parent_snapshot.revision,
            &parent.value,
            candidate.clone(),
            &|| now
        ),
        Err(StoreError::Exhausted)
    ));
    server.storage().remove(stored.id, stored.revision).unwrap();
    let created = server
        .storage()
        .create_derived(
            parent_snapshot.id,
            parent_snapshot.revision,
            &parent.value,
            candidate,
            &|| now,
        )
        .unwrap();
    assert!(server
        .storage()
        .lookup(GrantSelector::Id(stored.id))
        .unwrap()
        .is_none());
    assert!(server
        .storage()
        .lookup(GrantSelector::Id(created.id))
        .unwrap()
        .is_some());
    assert_eq!(server.storage().len().unwrap(), 1);
    assert!(server
        .storage()
        .lookup(GrantSelector::AccessToken("candidate257"))
        .unwrap()
        .is_some());
}
