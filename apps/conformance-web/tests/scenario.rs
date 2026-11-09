//! The `lifecycle` scenario against a real authorization server, in memory:
//! a virtual clock, and a transport that enforces the scenario's admissions.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, GrantSelector, GrantStore, KeyResolver,
    MemoryStorage, OsNonces, Policy, TokenApproval,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport};
use gnap_conformance_web::cli::Outcome;
use gnap_conformance_web::net::{Admitted, Destinations};
use gnap_conformance_web::scenario::{self, Admission, Clock, Plan};
use gnap_crypto::{PublicKey, Verifier};
use gnap_types::client::Client;
use gnap_types::message::GrantRequest;
use std::cell::{Cell, RefCell};

const GRANT: &str = "https://as.example/gnap";
const RESOURCE: &str = "https://rs.example/files";

/// Accepts a client key by value, for its proof method.
struct PresentedKey;
impl KeyResolver for PresentedKey {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        let key = client.as_value()?.key.as_value()?;
        let jwk = key.jwk.as_ref()?;
        let verifier = match key.proof.method().as_str() {
            "httpsig" => PublicKey::for_httpsig(jwk),
            _ => PublicKey::for_jws(jwk),
        };
        verifier.ok().map(|key| Box::new(key) as Box<dyn Verifier>)
    }
}

/// Approves the requested rights, after interaction when `interact` is set.
struct Approve {
    interact: bool,
    deny: bool,
}
impl Policy for Approve {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        if self.interact {
            return Decision::RequireInteraction;
        }
        self.evaluate_after_interaction(request)
    }
    fn evaluate_after_interaction(&self, request: &GrantRequest) -> Decision {
        if self.deny {
            return Decision::Deny(gnap_registry::ErrorCode::UserDenied);
        }
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
        true
    }
}

type Server = AuthorizationServer<Approve, PresentedKey, MemoryStorage, OsNonces>;

fn server(interact: bool, deny: bool) -> Server {
    AuthorizationServer::new(
        Approve { interact, deny },
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
    .with_jose_proofs(true)
    .with_key_rotation(true)
}

/// A clock the scenario moves forward by waiting.
struct Virtual(Cell<u64>);
impl Clock for Virtual {
    fn now(&self) -> u64 {
        self.0.get()
    }
    fn sleep_until(&self, at: u64) -> bool {
        self.0.set(self.0.get().max(at));
        true
    }
    fn interrupted(&self) -> bool {
        false
    }
    fn pause(&self, at: u64) {
        self.0.set(self.0.get().max(at));
    }
}

/// Sends what the admissions permit to the AS, or to a resource that
/// accepts a token the AS still holds. The resource doesn't verify proofs:
/// the scenario's own logic is under test here.
struct InMemory<'a> {
    server: &'a Server,
    clock: &'a Virtual,
    admitted: &'a Admitted,
    sent: RefCell<Vec<(String, String, u64)>>,
}
impl HttpTransport for InMemory<'_> {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        if !self.admitted.permits(&request.method, &request.url) {
            return Err("not admitted");
        }
        self.sent.borrow_mut().push((
            request.method.clone(),
            request.url.clone(),
            self.clock.now(),
        ));
        if request.url == RESOURCE {
            let token = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .and_then(|(_, value)| value.strip_prefix("GNAP "))
                .unwrap_or_default()
                .to_owned();
            let live = self
                .server
                .storage()
                .lookup(GrantSelector::AccessToken(&token))
                .ok()
                .flatten()
                .is_some();
            return Ok(HttpResponse {
                status: if live { 200 } else { 401 },
                headers: vec![],
                body: vec![],
            });
        }
        Ok(self.server.handle(&request, self.clock.now()))
    }
}

struct Admit<'a>(&'a Admitted);
impl Admission for Admit<'_> {
    fn admit(&self, method: &'static str, url: &str) -> bool {
        self.0.admit_same_origin(method, url)
    }
    fn clean_up(&self) {}
}

fn run(
    server: &Server,
    plan: &Plan,
    notify: &dyn Fn(&str),
) -> (
    gnap_conformance_web::cli::Report,
    Vec<(String, String, u64)>,
) {
    let clock = Virtual(Cell::new(1_700_000_000));
    let admitted = Admitted::new(GRANT, false).unwrap();
    admitted.allow("POST", GRANT);
    admitted.allow("OPTIONS", GRANT);
    if let Some(resource) = &plan.resource {
        admitted.allow("GET", resource);
    }
    let transport = InMemory {
        server,
        clock: &clock,
        admitted: &admitted,
        sent: RefCell::new(Vec::new()),
    };
    let report = scenario::lifecycle(&transport, &Admit(&admitted), &clock, notify, plan, false);
    let sent = transport.sent.into_inner();
    (report, sent)
}

fn plan(proof: &str, alg: &str, resource: bool, rotate_key: bool) -> Plan {
    Plan::new(
        GRANT,
        proof,
        alg,
        &["read".into()],
        resource.then_some(RESOURCE),
        rotate_key,
        30,
    )
    .unwrap()
}

fn outcome(report: &gnap_conformance_web::cli::Report, id: &str) -> Option<Outcome> {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .map(|f| f.outcome)
}

/// Every method and algorithm runs the whole scenario to a success, with
/// the resource read before and refused after revocation.
#[test]
fn the_whole_lifecycle_passes_for_every_method() {
    for (proof, alg) in [
        ("httpsig", "ES256"),
        ("httpsig", "EdDSA"),
        ("jws", "RS256"),
        ("jwsd", "EdDSA"),
    ] {
        let server = server(false, false);
        let (report, _) = run(&server, &plan(proof, alg, true, true), &|_| {});
        for id in [
            "grant-request",
            "token-issued",
            "resource-access",
            "token-rotation",
            "key-rotation",
            "token-revocation",
            "revoked-token-refused",
            "grant-revocation",
        ] {
            assert_eq!(
                outcome(&report, id),
                Some(Outcome::Passed),
                "{proof} {alg} {id}: {}",
                report.text()
            );
        }
        assert_eq!(report.exit_code(), 0, "{proof} {alg}");
    }
}

/// The scenario polls a pending grant: it shows the link, which the test
/// follows as an operator would, and the grant then goes through.
#[test]
fn a_pending_grant_is_polled_until_the_operator_approves() {
    let server = server(true, false);
    let notify = |message: &str| {
        let link = message.rsplit(' ').next().unwrap();
        let handle = link.rsplit('/').next().unwrap();
        server.complete_interaction(handle, 1_700_000_000).unwrap();
    };
    let (report, _) = run(&server, &plan("jwsd", "ES256", false, false), &notify);
    assert_eq!(
        outcome(&report, "token-issued"),
        Some(Outcome::Passed),
        "{}",
        report.text()
    );
    assert_eq!(report.exit_code(), 0);
}

/// An operator who never answers leaves the scenario inconclusive, and a
/// denial is a result of the scenario, not a deviation; both clean up.
#[test]
fn an_unanswered_or_denied_interaction_is_not_a_deviation() {
    let server = server(true, false);
    let (report, _) = run(&server, &plan("httpsig", "ES256", false, false), &|_| {});
    assert_eq!(
        outcome(&report, "interaction-outcome"),
        Some(Outcome::Inconclusive)
    );
    assert_eq!(
        outcome(&report, "grant-revocation"),
        Some(Outcome::Passed),
        "{}",
        report.text()
    );
    assert_eq!(report.exit_code(), 2);

    let server = server_denying();
    let notify = |message: &str| {
        let handle = message.rsplit('/').next().unwrap();
        server.complete_interaction(handle, 1_700_000_000).unwrap();
    };
    let (report, _) = run(&server, &plan("httpsig", "ES256", false, false), &notify);
    assert_eq!(
        outcome(&report, "interaction-outcome"),
        Some(Outcome::NotApplicable),
        "{}",
        report.text()
    );
    assert_ne!(report.exit_code(), 1, "a denial is no deviation");
}

fn server_denying() -> Server {
    server(true, true)
}

/// An unknown client is the AS's policy: inconclusive, never a failure.
#[test]
fn a_refused_client_leaves_the_scenario_inconclusive() {
    struct Nobody;
    impl KeyResolver for Nobody {
        fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
            None
        }
    }
    let server = AuthorizationServer::new(
        Approve {
            interact: false,
            deny: false,
        },
        Nobody,
        MemoryStorage::new(),
        OsNonces,
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/manage".into(),
        },
    );
    let clock = Virtual(Cell::new(1_700_000_000));
    let admitted = Admitted::new(GRANT, false).unwrap();
    admitted.allow("POST", GRANT);
    struct Plain<'a, P: Policy, K: KeyResolver>(
        &'a AuthorizationServer<P, K, MemoryStorage, OsNonces>,
        &'a Admitted,
    );
    impl<P: Policy, K: KeyResolver> HttpTransport for Plain<'_, P, K> {
        type Error = &'static str;
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            if !self.1.permits(&request.method, &request.url) {
                return Err("not admitted");
            }
            Ok(self.0.handle(&request, 1_700_000_000))
        }
    }
    let report = scenario::lifecycle(
        &Plain(&server, &admitted),
        &Admit(&admitted),
        &clock,
        &|_| {},
        &plan("httpsig", "ES256", false, false),
        false,
    );
    assert_eq!(
        outcome(&report, "grant-request"),
        Some(Outcome::Inconclusive)
    );
    assert_eq!(report.exit_code(), 2);
}

/// A plan is refused before any network work for a pair the method doesn't
/// take, too many or malformed rights, or too long a wait.
#[test]
fn a_plan_is_validated_before_the_network() {
    let entries = |n: usize| vec!["read".to_owned(); n];
    for (proof, alg, access, wait) in [
        ("httpsig", "RS256", entries(1), 30),
        ("jws", "PS256", entries(1), 30),
        ("mtls", "ES256", entries(1), 30),
        ("httpsig", "ES384", entries(1), 30),
        ("httpsig", "ES256", entries(0), 30),
        ("httpsig", "ES256", entries(9), 30),
        ("httpsig", "ES256", vec!["{\"type\":".into()], 30),
        ("httpsig", "ES256", vec!["{\"no\":\"type\"}".into()], 30),
        ("httpsig", "ES256", entries(1), 601),
    ] {
        assert!(
            Plan::new(GRANT, proof, alg, &access, None, false, wait).is_err(),
            "{proof} {alg} {access:?} {wait}"
        );
    }
}

/// The scenario only sends what it was given or what the AS's accepted
/// answers pointed to.
#[test]
fn the_scenario_stays_within_its_admissions() {
    let server = server(false, false);
    let (_, sent) = run(&server, &plan("jws", "ES256", true, false), &|_| {});
    for (method, url, _) in &sent {
        assert!(
            url == GRANT || url == RESOURCE || url.starts_with("https://as.example/"),
            "{method} {url}"
        );
    }
    assert!(sent
        .iter()
        .any(|(m, u, _)| m == "DELETE" && u.starts_with("https://as.example/continue")));
    // The resource reads each prove at their own second: the check after
    // revocation is a fresh proof, never one the resource saw before.
    let reads: Vec<u64> = sent
        .iter()
        .filter(|(_, url, _)| url == RESOURCE)
        .map(|(_, _, at)| *at)
        .collect();
    assert_eq!(reads.len(), 2);
    assert!(reads[1] > reads[0], "{reads:?}");
}

/// A continuation on another origin is outside the scenario's profile: it
/// is reported, and nothing goes there.
#[test]
fn another_origin_is_never_followed() {
    let server = AuthorizationServer::new(
        Approve {
            interact: false,
            deny: false,
        },
        PresentedKey,
        MemoryStorage::new(),
        OsNonces,
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://elsewhere.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://elsewhere.example/manage".into(),
        },
    )
    .with_jose_proofs(true);
    let (report, sent) = run(&server, &plan("httpsig", "ES256", false, false), &|_| {});
    assert_eq!(
        outcome(&report, "destination-profile"),
        Some(Outcome::Inconclusive),
        "{}",
        report.text()
    );
    assert!(
        sent.iter().all(|(_, url, _)| !url.contains("elsewhere")),
        "{sent:?}"
    );
    assert_eq!(report.exit_code(), 2);
}
