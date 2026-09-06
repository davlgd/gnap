//! Actual GNAP Session → AS TokenEncoder → native Biscuit → RS authorization.
use biscuit_auth::KeyPair;
use gnap_as::{GrantAggregate, GrantSelector, GrantStore, StoreError};
use gnap_biscuit::{LiveDecision, VerifiedToken};
use gnap_biscuit_files::{
    authorization::{self, Engine, Store},
    client::grant,
    http::Origin,
    resource::Resources,
    resource_check::{self, CheckService, Nonces},
};
use gnap_client::{sign_request, HttpRequest, HttpResponse, HttpTransport, Session};
use gnap_crypto::Ps256Signer;
use std::{
    cell::Cell,
    collections::BTreeMap,
    sync::{mpsc, Arc, Barrier, OnceLock},
    time::Duration,
};

fn client() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| {
        Ps256Signer::from_pkcs1_pem(
            include_str!("../../../crates/gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
            "fixture-client",
        )
        .unwrap()
    })
}
fn rs_key() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "test-rs").unwrap())
}
struct Fixture {
    engine: Engine,
    store: Arc<Store>,
    rs: Resources,
    resource_check: CheckService,
    now: u64,
}
fn fixture() -> Fixture {
    let as_origin = Origin::parse("https://as.example").unwrap();
    let rs_origin = Origin::parse("https://rs.example").unwrap();
    let root = KeyPair::new();
    let roots = BTreeMap::from([(1, root.public())]);
    let store = Arc::new(Store::default());
    let engine = authorization::engine(
        &as_origin,
        &rs_origin,
        root,
        client().public_jwk().unwrap(),
        store.clone(),
    )
    .unwrap();
    let rs = Resources::new(rs_origin, "https://as.example/gnap".into(), roots);
    let resource_check = CheckService {
        endpoint: "https://as.example/resource-check".into(),
        key: rs_key().verifier(),
        store: store.clone(),
        nonces: Nonces::default(),
    };
    Fixture {
        engine,
        store,
        rs,
        resource_check,
        now: gnap_biscuit_files::now().unwrap(),
    }
}
struct Direct<'a>(&'a Engine, Cell<u64>);
impl HttpTransport for Direct<'_> {
    type Error = String;
    fn send(&self, r: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.handle(&r, self.1.get()))
    }
}
fn proof(token: &gnap_types::token::TokenValue, method: &str, file: &str, now: u64) -> HttpRequest {
    let mut r = HttpRequest::new(method, format!("https://rs.example/files/{file}"));
    if method == "PUT" {
        r = r.header("content-type", "text/plain");
        r.body = Some(b"revised draft".to_vec());
    }
    sign_request(r, client(), Some(token), now).unwrap()
}
fn lookup(
    f: &Fixture,
    ids: &[Vec<u8>],
    accepted: &gnap_crypto::ReceivedParams,
    now: u64,
) -> LiveDecision {
    let request = resource_check::check_request(
        &f.resource_check.endpoint,
        &ids[0],
        accepted.nonce.as_deref().unwrap(),
        accepted.created.unwrap(),
        rs_key(),
        now,
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 3);
    assert!(body.get("authority").is_some());
    assert_eq!(body["nonce"], accepted.nonce.as_deref().unwrap());
    assert_eq!(body["created"], accepted.created.unwrap());
    let response = f.resource_check.handle_at(&request, now);
    resource_check::check_response(
        &response,
        &request,
        &resource_check::request_nonce(&request).unwrap(),
    )
}

#[test]
fn native_issuance_attenuation_rotation_and_revocation_with_fresh_proofs() {
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let issued = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let parent = issued.response().access_token.as_ref().unwrap().tokens[0].clone();
    assert_eq!(parent.expires_in, Some(1200));
    let token = VerifiedToken::from_token(&parent.value, &f.rs.roots).unwrap();
    let descendant = token
        .attenuate(Some("https://rs.example/files/notes"), Some(f.now + 120))
        .unwrap();
    for (value, method, file, resource_check) in [
        (&parent.value, "GET", "notes", 200),
        (&parent.value, "PUT", "draft", 200),
        (&parent.value, "PUT", "notes", 403),
        (&parent.value, "GET", "draft", 403),
        (&descendant, "GET", "notes", 200),
        (&descendant, "PUT", "draft", 403),
    ] {
        assert_eq!(
            f.rs.handle_with_clock(
                &proof(value, method, file, f.now),
                &mut || Some(f.now),
                &mut |ids, params| lookup(&f, ids, params, f.now)
            )
            .status,
            resource_check
        );
    }
    let replay = proof(&descendant, "GET", "notes", f.now);
    assert_eq!(
        f.rs.handle_with_clock(&replay, &mut || Some(f.now), &mut |ids, params| lookup(
            &f, ids, params, f.now
        ))
        .status,
        200
    );
    assert_eq!(
        f.rs.handle_with_clock(&replay, &mut || Some(f.now), &mut |_, _| panic!(
            "replay reached live lookup"
        ))
        .status,
        403
    );
    let rotated = session.rotate_token(None, f.now).unwrap();
    for old in [&parent.value, &descendant] {
        assert_eq!(
            f.rs.handle_with_clock(
                &proof(old, "GET", "notes", f.now),
                &mut || Some(f.now),
                &mut |ids, params| lookup(&f, ids, params, f.now)
            )
            .status,
            403
        );
    }
    assert_eq!(
        f.rs.handle_with_clock(
            &proof(&rotated.value, "GET", "notes", f.now),
            &mut || Some(f.now),
            &mut |ids, params| lookup(&f, ids, params, f.now)
        )
        .status,
        200
    );
    let descendant = VerifiedToken::from_token(&rotated.value, &f.rs.roots)
        .unwrap()
        .attenuate(Some("https://rs.example/files/notes"), None)
        .unwrap();
    session.revoke_token(None, f.now).unwrap();
    assert_eq!(
        f.rs.handle_with_clock(
            &proof(&descendant, "GET", "notes", f.now),
            &mut || Some(f.now),
            &mut |ids, params| lookup(&f, ids, params, f.now)
        )
        .status,
        403
    );
}

#[test]
fn resource_check_authenticates_rs_and_correlates_the_exact_request() {
    let f = fixture();
    let id = vec![42; 64];
    let wrong = resource_check::check_request(
        &f.resource_check.endpoint,
        &id,
        "resource-nonce",
        f.now,
        client(),
        f.now,
    )
    .unwrap();
    assert_eq!(f.resource_check.handle_at(&wrong, f.now).status, 401);
    let request = resource_check::check_request(
        &f.resource_check.endpoint,
        &id,
        "resource-nonce",
        f.now,
        rs_key(),
        f.now,
    )
    .unwrap();
    let response = f.resource_check.handle_at(&request, f.now);
    let nonce = resource_check::request_nonce(&request).unwrap();
    assert_eq!(response.body, b"{\"request_allowed\":false}");
    assert_eq!(
        resource_check::check_response(&response, &request, &nonce),
        LiveDecision::Denied
    );
    assert_eq!(f.resource_check.handle_at(&request, f.now).status, 401);
    assert_eq!(
        resource_check::check_response(&response, &request, "another-request"),
        LiveDecision::Unavailable
    );
    let mut changed = request.clone();
    changed.body = Some(b"{}".to_vec());
    assert_eq!(
        resource_check::check_response(&response, &changed, &nonce),
        LiveDecision::Unavailable
    );
    for body in [
        b"{}".as_slice(),
        b"{\"request_allowed\":true,\"other\":1}",
        b"{\"request_allowed\":true,\"request_allowed\":false}",
    ] {
        let mut malformed = response.clone();
        malformed.body = body.to_vec();
        assert_eq!(
            resource_check::check_response(&malformed, &request, &nonce),
            LiveDecision::Unavailable
        );
    }
}

#[test]
fn colliding_expired_or_unavailable_authorities_fail_closed() {
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let issued = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let token = &issued.response().access_token.as_ref().unwrap().tokens[0];
    let handle = token
        .manage
        .as_ref()
        .unwrap()
        .uri
        .rsplit('/')
        .next()
        .unwrap();
    let snapshot = f
        .store
        .lookup(GrantSelector::Management(handle))
        .unwrap()
        .unwrap();
    let record = snapshot.aggregate.tokens[handle].clone();
    let id = record.identifier.clone().unwrap();
    assert_eq!(
        f.store
            .reserve_resource(&id, "first", f.now, || Some(f.now)),
        LiveDecision::Allowed
    );
    assert_eq!(
        f.store.create(snapshot.aggregate.clone()).unwrap_err(),
        StoreError::Collision
    );
    assert_eq!(
        f.store
            .reserve_resource(&id, "collision-did-not-remove-original", f.now, || Some(
                f.now
            )),
        LiveDecision::Allowed
    );
    let mut expired = snapshot.aggregate.clone();
    expired.tokens.get_mut(handle).unwrap().issued_at = f.now - 1200;
    let expired = f
        .store
        .compare_exchange(snapshot.id, snapshot.revision, expired)
        .unwrap();
    assert_eq!(
        f.store
            .reserve_resource(&id, "expired", f.now, || Some(f.now)),
        LiveDecision::Denied
    );
    assert!(f
        .store
        .lookup(GrantSelector::Id(snapshot.id))
        .unwrap()
        .is_none());
    assert_eq!(
        f.store
            .compare_exchange(snapshot.id, expired.revision, snapshot.aggregate)
            .unwrap_err(),
        StoreError::Conflict
    );
    assert_eq!(
        f.rs.handle_with_clock(
            &proof(&token.value, "GET", "notes", f.now),
            &mut || Some(f.now),
            &mut |_, _| LiveDecision::Unavailable
        )
        .status,
        503
    );
    let request = resource_check::check_request(
        &f.resource_check.endpoint,
        &id,
        "resource-nonce",
        f.now,
        rs_key(),
        f.now,
    )
    .unwrap();
    let mut times = [Some(f.now), None].into_iter();
    assert_eq!(
        f.resource_check
            .handle_with_clock(&request, &mut || times.next().unwrap())
            .status,
        503
    );
    let request = resource_check::check_request(
        &f.resource_check.endpoint,
        &id,
        "resource-nonce",
        f.now,
        rs_key(),
        f.now,
    )
    .unwrap();
    let mut times = [Some(f.now), Some(f.now - 1)].into_iter();
    assert_eq!(
        f.resource_check
            .handle_with_clock(&request, &mut || times.next().unwrap())
            .status,
        503
    );
}

#[test]
fn exact_attenuation_deadline_and_post_lookup_clock_are_enforced() {
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let issued = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let parent = &issued.response().access_token.as_ref().unwrap().tokens[0].value;
    let value = VerifiedToken::from_token(parent, &f.rs.roots)
        .unwrap()
        .attenuate(None, Some(f.now + 2))
        .unwrap();
    assert_eq!(
        f.rs.handle_with_clock(
            &proof(&value, "GET", "notes", f.now + 2),
            &mut || Some(f.now + 2),
            &mut |_, _| panic!("expired request reached resource_check")
        )
        .status,
        403
    );
    let mut times = [Some(f.now), Some(f.now + 2)].into_iter();
    assert_eq!(
        f.rs.handle_with_clock(
            &proof(&value, "GET", "notes", f.now),
            &mut || times.next().unwrap(),
            &mut |ids, params| lookup(&f, ids, params, f.now)
        )
        .status,
        403
    );
    let mut wrong = proof(parent, "GET", "notes", f.now);
    let auth = wrong
        .headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .unwrap();
    auth.1 = format!("GNAP {}", value.as_str());
    assert_eq!(
        f.rs.handle_with_clock(&wrong, &mut || Some(f.now), &mut |_, _| panic!(
            "wrong token signature reached resource_check"
        ))
        .status,
        403
    );
}

#[test]
fn encoder_refuses_unresolved_clients_wrong_issuer_or_missing_deadlines() {
    use gnap_as::{TokenEncoder, TokenEncodingContext};
    let encoder = authorization::Encoder::new(
        KeyPair::new(),
        "https://as.example/gnap".into(),
        "https://rs.example".into(),
    )
    .unwrap();
    let request = grant(client(), "https://rs.example").unwrap();
    let rights = &request.access_token.as_ref().unwrap().tokens[0].access;
    let mut context = TokenEncodingContext {
        issuer: "https://other.example/gnap",
        client: &request.client,
        access: rights,
        issued_at: 1_000,
        expires_in: Some(1200),
        candidate_nonce: "unused-opaque-candidate",
    };
    assert!(encoder.encode(&context).is_err());
    context.issuer = "https://as.example/gnap";
    context.expires_in = None;
    assert!(encoder.encode(&context).is_err());
    context.expires_in = Some(1200);
    let reference = serde_json::from_value(serde_json::json!("unresolved-client")).unwrap();
    context.client = &reference;
    assert!(encoder.encode(&context).is_err());
    context.client = &request.client;
    let encoded = encoder.encode(&context).unwrap();
    assert_eq!(encoded.identifier.unwrap().len(), 64);
}

#[test]
fn nonce_memories_fail_closed_on_capacity_rollback_and_overflow() {
    use gnap_crypto::NonceMemory;
    let memory = Nonces::default();
    for i in 0..4096 {
        assert!(memory.remember_nonce(&format!("nonce-{i}"), 100));
    }
    assert!(!memory.remember_nonce("overflow-capacity", 100));
    assert!(!memory.remember_nonce("rollback", 99));
    assert!(!memory.remember_nonce("still-retained-at-boundary", 700));
    assert!(memory.remember_nonce("after-retention", 701));
    assert!(!memory.remember_nonce("after-retention", 701));
    assert!(!memory.remember_nonce("clock-overflow", u64::MAX));
}

#[test]
fn resource_check_windows_and_nonce_scope_are_enforced_by_the_as_store() {
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut first = Session::new(&direct, client(), "https://as.example/gnap");
    let first = first
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let mut second = Session::new(&direct, client(), "https://as.example/gnap");
    let second = second
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let id = |step: &gnap_client::Step| {
        VerifiedToken::from_token(
            &step.response().access_token.as_ref().unwrap().tokens[0].value,
            &f.rs.roots,
        )
        .unwrap()
        .revocation_identifiers()[0]
            .clone()
    };
    let first = id(&first);
    let second = id(&second);
    assert_ne!(first, second);
    let check = |id: &[u8], nonce: &str, created: u64| {
        let request = resource_check::check_request(
            &f.resource_check.endpoint,
            id,
            nonce,
            created,
            rs_key(),
            f.now,
        )
        .unwrap();
        let response = f.resource_check.handle_at(&request, f.now);
        assert_eq!(response.status, 200);
        resource_check::check_response(
            &response,
            &request,
            &resource_check::request_nonce(&request).unwrap(),
        )
    };
    for (nonce, created, expected) in [
        ("old-boundary", f.now - 300, LiveDecision::Allowed),
        ("too-old", f.now - 301, LiveDecision::Denied),
        ("future-boundary", f.now + 90, LiveDecision::Allowed),
        ("too-future", f.now + 91, LiveDecision::Denied),
        ("outside-as", f.now + 301, LiveDecision::Denied),
    ] {
        assert_eq!(check(&first, nonce, created), expected);
    }
    assert_eq!(
        check(&[0; 64], "unknown-cannot-spend", f.now),
        LiveDecision::Denied
    );
    assert_eq!(
        check(&first, "unknown-cannot-spend", f.now),
        LiveDecision::Allowed
    );
    assert_eq!(
        check(&first, "shared-key-nonce", f.now),
        LiveDecision::Allowed
    );
    assert_eq!(
        check(&second, "shared-key-nonce", f.now),
        LiveDecision::Denied
    );
    let outcomes = std::thread::scope(|scope| {
        let threads = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    f.store
                        .reserve_resource(&first, "concurrent", f.now, || Some(f.now))
                })
            })
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|d| **d == LiveDecision::Allowed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|d| **d == LiveDecision::Denied)
            .count(),
        3
    );
}

#[test]
fn resource_reservation_and_rotation_share_one_publication_lock() {
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let issued = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let token = &issued.response().access_token.as_ref().unwrap().tokens[0];
    let before = f
        .store
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .unwrap();
    let old_id = before
        .aggregate
        .tokens
        .values()
        .next()
        .unwrap()
        .identifier
        .clone()
        .unwrap();
    let manage = token.manage.as_ref().unwrap();
    let rotation = sign_request(
        HttpRequest::new("POST", &manage.uri),
        client(),
        Some(&manage.access_token.value),
        f.now,
    )
    .unwrap();
    let (entered, in_check) = mpsc::channel();
    let (release, proceed) = mpsc::channel();
    let (finished, completion) = mpsc::channel();
    std::thread::scope(|scope| {
        let store = &f.store;
        let id = &old_id;
        let now = f.now;
        let reading = scope.spawn(move || {
            store.reserve_resource(id, "spent-before-rotation", now, || {
                entered.send(()).unwrap();
                proceed.recv_timeout(Duration::from_secs(5)).unwrap();
                Some(now)
            })
        });
        in_check.recv_timeout(Duration::from_secs(5)).unwrap();
        let rotating = scope.spawn(|| {
            let response = f.engine.handle(&rotation, f.now);
            finished.send(response).unwrap();
        });
        // This bounded wait observes the concurrent schedule; it is not a
        // timing-independent proof of lock ownership. A separate unit test
        // checks ownership directly with try_lock inside the clock callback.
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release.send(()).unwrap();
        assert_eq!(reading.join().unwrap(), LiveDecision::Allowed);
        rotating.join().unwrap();
        assert_eq!(completion.recv().unwrap().status, 200);
    });
    let after = f
        .store
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    let replacement = after.aggregate.tokens.values().next().unwrap();
    let new_id = replacement.identifier.as_ref().unwrap();
    assert_ne!(&old_id, new_id);
    assert!(f
        .store
        .lookup(GrantSelector::TokenIdentifier(&old_id))
        .unwrap()
        .is_none());
    assert!(f
        .store
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .is_none());
    assert!(f
        .store
        .lookup(GrantSelector::Management(
            manage.uri.rsplit('/').next().unwrap()
        ))
        .unwrap()
        .is_none());
    assert_eq!(
        f.store
            .reserve_resource(&old_id, "fresh-old", f.now, || Some(f.now)),
        LiveDecision::Denied
    );
    assert_eq!(
        f.store
            .reserve_resource(new_id, "spent-before-rotation", f.now, || Some(f.now)),
        LiveDecision::Denied
    );
    assert_eq!(
        f.store
            .reserve_resource(new_id, "fresh-new", f.now, || Some(f.now)),
        LiveDecision::Allowed
    );
    assert_eq!(
        f.store
            .compare_exchange(before.id, before.revision, before.aggregate)
            .unwrap_err(),
        StoreError::Conflict
    );

    // Reverse ordering: revocation wins before a resource check starts. Even
    // a previously valid snapshot cannot bring that authority back afterwards.
    let mut revoked = after.aggregate.clone();
    revoked.tokens.clear();
    revoked.revoked = true;
    f.store
        .compare_exchange(after.id, after.revision, revoked)
        .unwrap();
    assert_eq!(
        f.store
            .reserve_resource(new_id, "after-revoke", f.now, || Some(f.now)),
        LiveDecision::Denied
    );
    assert_eq!(
        f.store
            .compare_exchange(after.id, after.revision, after.aggregate.clone())
            .unwrap_err(),
        StoreError::Conflict
    );
    assert!(f
        .store
        .lookup(GrantSelector::TokenIdentifier(new_id))
        .unwrap()
        .is_none());
}

#[test]
fn concurrent_create_enforces_capacity_and_removal_keeps_resource_reservations() {
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let issued = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let token = &issued.response().access_token.as_ref().unwrap().tokens[0];
    let original = f
        .store
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .unwrap();
    let native_id = original
        .aggregate
        .tokens
        .values()
        .next()
        .unwrap()
        .identifier
        .as_ref()
        .unwrap();
    assert_eq!(
        f.store
            .reserve_resource(native_id, "survives-removal", f.now, || Some(f.now)),
        LiveDecision::Allowed
    );
    // These candidates exercise storage publication, not Biscuit verification;
    // the native-token lifecycle test above covers the actual encoder.
    let candidate = |n: u64| -> GrantAggregate {
        let mut candidate = original.aggregate.clone();
        let mut record = candidate.tokens.drain().next().unwrap().1;
        record.token.value =
            gnap_types::token::TokenValue::new(format!("capacity-value-{n}")).unwrap();
        // Separate grants must not share management credentials either.
        record.management_token = format!("capacity-management-{n}");
        let handle = format!("capacity-handle-{n}");
        let manage = record.token.manage.as_mut().unwrap();
        manage.access_token.value =
            gnap_types::token::TokenValue::new(record.management_token.clone()).unwrap();
        manage.uri = format!("https://as.example/token/{handle}");
        let mut id = vec![0; 64];
        id[..8].copy_from_slice(&n.to_be_bytes());
        record.identifier = Some(id);
        candidate.tokens.insert(handle, record);
        candidate
    };
    for n in 1..gnap_biscuit_files::MAX_RECORDS as u64 - 1 {
        f.store.create(candidate(n)).unwrap();
    }
    let barrier = Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        [100, 101]
            .map(|n| {
                scope.spawn({
                    let candidate = &candidate;
                    let barrier = &barrier;
                    let store = &f.store;
                    move || {
                        let aggregate = candidate(n);
                        barrier.wait();
                        store.create(aggregate)
                    }
                })
            })
            .map(|thread| thread.join().unwrap())
    });
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Unavailable)))
            .count(),
        1
    );
    f.store.remove(original.id, original.revision).unwrap();
    assert_eq!(
        f.store
            .compare_exchange(original.id, original.revision, original.aggregate.clone())
            .unwrap_err(),
        StoreError::Conflict
    );
    let next = f.store.create(candidate(102)).unwrap();
    assert_ne!(next.id, original.id);
    let next_id = next
        .aggregate
        .tokens
        .values()
        .next()
        .unwrap()
        .identifier
        .as_ref()
        .unwrap();
    assert_eq!(
        f.store
            .reserve_resource(next_id, "survives-removal", f.now, || Some(f.now)),
        LiveDecision::Denied
    );
    assert_eq!(
        f.store
            .reserve_resource(next_id, "new-request", f.now, || Some(f.now)),
        LiveDecision::Allowed
    );
}

#[tokio::test]
async fn signed_empty_put_keeps_an_explicit_body_through_http_dispatch() {
    let f = Arc::new(fixture());
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let step = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let token = &step.response().access_token.as_ref().unwrap().tokens[0].value;
    let mut request = HttpRequest::new("PUT", "https://rs.example/files/draft")
        .header("content-type", "text/plain");
    request.body = Some(Vec::new());
    let signed = gnap_client::sign_request(request, client(), Some(token), f.now).unwrap();
    assert!(signed.header_value("content-digest").is_some());
    let mut wire = axum::http::Request::builder()
        .method("PUT")
        .uri("/files/draft")
        .header("host", "rs.example")
        .header("content-length", "0");
    for (name, value) in &signed.headers {
        wire = wire.header(name, value);
    }
    let worker = f.clone();
    let response = gnap_biscuit_files::http::dispatch(
        wire.body(axum::body::Body::empty()).unwrap(),
        &Origin::parse("https://rs.example").unwrap(),
        Arc::new(tokio::sync::Semaphore::new(1)),
        move |request| {
            assert_eq!(request.body, Some(Vec::new()));
            worker
                .rs
                .handle_with_clock(&request, &mut || Some(worker.now), &mut |ids, accepted| {
                    lookup(&worker, ids, accepted, worker.now)
                })
        },
    )
    .await;
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["written_bytes"],
        0
    );
    let response = gnap_biscuit_files::http::dispatch(
        axum::http::Request::builder()
            .method("POST")
            .uri("/token/example")
            .header("content-length", "0")
            .body(axum::body::Body::empty())
            .unwrap(),
        &Origin::parse("https://rs.example").unwrap(),
        Arc::new(tokio::sync::Semaphore::new(1)),
        |request| {
            assert_eq!(request.body, None);
            gnap_biscuit_files::http::answer(200, serde_json::json!({}))
        },
    )
    .await;
    assert_eq!(response.status(), 200);
}
