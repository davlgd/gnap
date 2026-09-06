//! Several access tokens in one grant, seen from the client side.
//!
//! The AS answers from a script, so each response can be shaped exactly as
//! the rule under test needs. Nothing here says what an AS should issue: the
//! tests establish what the client accepts, refuses and keeps.

use gnap_client::{ClientError, HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_crypto::proof::Signer;
use gnap_crypto::ps256::Ps256Signer;
use gnap_types::message::{ContinueRequest, GrantRequest};
use std::cell::RefCell;

const RSA_PKCS1: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem");
const ENDPOINT: &str = "https://server.example.com/gnap";

/// An AS that replies from a script, and records what it was sent.
struct FakeAs {
    replies: RefCell<Vec<HttpResponse>>,
    seen: RefCell<Vec<HttpRequest>>,
}

impl FakeAs {
    fn with(bodies: Vec<&str>) -> Self {
        Self {
            replies: RefCell::new(
                bodies
                    .into_iter()
                    .map(|b| HttpResponse {
                        status: if b.is_empty() { 204 } else { 200 },
                        headers: vec![("Cache-Control".into(), "no-store".into())],
                        body: b.as_bytes().to_vec(),
                    })
                    .rev()
                    .collect(),
            ),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn sent(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl HttpTransport for FakeAs {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.seen.borrow_mut().push(request);
        self.replies
            .borrow_mut()
            .pop()
            .ok_or_else(|| "the fake AS ran out of scripted replies".to_owned())
    }
}

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap()
}

/// A request for three labelled tokens (§2.1.2).
fn three() -> GrantRequest {
    serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":[{"label":"documents","access":["documents:read"]},
                            {"label":"reports","access":["reports:read"]},
                            {"label":"calendar","access":["calendar:read"]}]}"#,
    )
    .unwrap()
}

/// A request for one token, labelled or not (§2.1.1).
fn single(label: Option<&str>) -> GrantRequest {
    let label = label.map_or(String::new(), |l| format!(r#""label":"{l}","#));
    serde_json::from_str(&format!(
        r#"{{"client":"client-541-ab","access_token":{{{label}"access":["documents:read"]}}}}"#
    ))
    .unwrap()
}

/// One issued token object, with a management API when `handle` is given.
fn issued(label: Option<&str>, value: &str, access: &str, handle: Option<&str>) -> String {
    let label = label.map_or(String::new(), |l| format!(r#""label":"{l}","#));
    let manage = handle.map_or(String::new(), |h| {
        format!(
            r#","manage":{{"uri":"https://as.example/token/{h}",
                          "access_token":{{"value":"manage-{h}"}}}}"#
        )
    });
    format!(r#"{{{label}"value":"{value}","access":["{access}"],"expires_in":100{manage}}}"#)
}

const DOCUMENTS: &str = "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0";
const REPORTS: &str = "B8CDFONP21-4TB8N6.BW7ONM";
const CALENDAR: &str = "FP6A8H6HY37MH13CK76LBZ6Y1UADG6VEUPEER5H2";
const ROTATED: &str = "4TB8N6-B8CDFONP21.BW7ONM.ROTATED";

/// The lot the scripted AS issues for [`three`]: two of the three tokens.
fn two_of_three() -> String {
    format!(
        r#"{{"access_token":[{},{}]}}"#,
        issued(Some("documents"), DOCUMENTS, "documents:read", Some("D")),
        issued(Some("reports"), REPORTS, "reports:read", Some("R")),
    )
}

fn labels(session: &Session<'_, FakeAs, Ps256Signer>, now: u64) -> Vec<Option<String>> {
    session
        .usable_tokens(now)
        .unwrap_or_default()
        .iter()
        .map(|t| t.label.clone())
        .collect()
}

/// GNAP-9635-§3.2.2-M01 — "The AS MAY refuse to issue one or more of the
/// requested access tokens for any reason. In such cases, the refused token is
/// omitted from the response, and all of the other issued access tokens are
/// included in the response under their respective requested labels."
///
/// A missing label is a refusal, not a protocol error; the ones that came
/// back are held under the labels the request chose.
#[test]
fn a_partial_lot_is_held_under_the_labels_that_were_asked_for() {
    let sk = signer();
    let as_ = FakeAs::with(vec![&two_of_three()]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);

    let step = s.start(&three(), 1_000).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
    assert_eq!(
        labels(&s, 1_000),
        vec![Some("documents".to_owned()), Some("reports".to_owned())]
    );
    let held = s.usable_tokens(1_000).unwrap();
    assert_eq!(held[0].value.as_str(), DOCUMENTS);
    assert_eq!(held[1].value.as_str(), REPORTS);
}

/// GNAP-9635-§3.2.2-M02 — "Each object MUST have a unique label field,
/// corresponding to the token labels chosen by the client instance in the
/// request for multiple access tokens."
///
/// Presence and uniqueness are enforced when the array is read; the
/// correspondence needs the request, which only the session has. Either way,
/// nothing from such a response is adopted.
#[test]
fn a_label_that_was_never_requested_or_repeats_is_refused_without_adoption() {
    let sk = signer();
    let stranger = format!(
        r#"{{"access_token":[{},{}]}}"#,
        issued(Some("documents"), DOCUMENTS, "documents:read", None),
        issued(Some("payroll"), REPORTS, "reports:read", None),
    );
    let twice = format!(
        r#"{{"access_token":[{},{}]}}"#,
        issued(Some("documents"), DOCUMENTS, "documents:read", None),
        issued(Some("documents"), REPORTS, "documents:read", None),
    );
    let unlabelled = format!(
        r#"{{"access_token":[{}]}}"#,
        issued(None, DOCUMENTS, "documents:read", None),
    );
    // §3.2.2 — "the AS MUST NOT respond with a single access token structure,
    // even if only a single access token is granted."
    let collapsed = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("documents"), DOCUMENTS, "documents:read", None),
    );

    for (body, expected) in [
        (stranger.as_str(), "did not ask for"),
        (twice.as_str(), "duplicate label"),
        (unlabelled.as_str(), "label"),
        (collapsed.as_str(), "shape"),
    ] {
        let as_ = FakeAs::with(vec![body]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        let e = s.start(&three(), 1_000).unwrap_err();
        assert!(
            matches!(e, ClientError::Protocol(_) | ClientError::Parse(_)),
            "{e}"
        );
        assert!(e.to_string().contains(expected), "{e}");
        assert!(s.usable_tokens(1_000).is_none(), "nothing was adopted");
        assert_eq!(as_.sent(), 1);
    }
}

/// GNAP-9635-§3.2.1-M02 — `label` is "REQUIRED for multiple access tokens or
/// if a label was included in the single access token request; OPTIONAL for a
/// single access token where no label was included in the request."
#[test]
fn a_single_token_echoes_a_requested_label_and_may_carry_an_unrequested_one() {
    let sk = signer();

    // Requested with a label: it has to come back, and come back unchanged.
    for (body, expected) in [
        (
            issued(None, DOCUMENTS, "documents:read", None),
            "came back labelled None",
        ),
        (
            issued(Some("other"), DOCUMENTS, "documents:read", None),
            "came back labelled Some(\"other\")",
        ),
    ] {
        let as_ = FakeAs::with(vec![&format!(r#"{{"access_token":{body}}}"#)]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        let e = s.start(&single(Some("only")), 1_000).unwrap_err();
        assert!(matches!(e, ClientError::Protocol(_)), "{e}");
        assert!(e.to_string().contains(expected), "{e}");
        assert!(s.usable_tokens(1_000).is_none());
    }
    let echoed = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("only"), DOCUMENTS, "documents:read", None)
    );
    let as_ = FakeAs::with(vec![&echoed]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(Some("only")), 1_000).unwrap();
    assert_eq!(labels(&s, 1_000), vec![Some("only".to_owned())]);

    // Requested without a label: the AS may add one, and `None` still names
    // the only token held when it comes to managing it.
    let volunteered = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("volunteered"), DOCUMENTS, "documents:read", Some("V"))
    );
    let rotated = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("volunteered"), ROTATED, "documents:read", Some("V2"))
    );
    let as_ = FakeAs::with(vec![&volunteered, &rotated]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(None), 1_000).unwrap();
    assert_eq!(labels(&s, 1_000), vec![Some("volunteered".to_owned())]);
    let token = s.rotate_token(None, 1_050).unwrap();
    assert_eq!(token.value.as_str(), ROTATED);
    assert_eq!(token.label.as_deref(), Some("volunteered"));
}

/// GNAP-9635-§6.1-M01 — a rotation issues a token "with the same rights and
/// properties as the original token, apart from an updated token value and
/// expiration time", answered "in the access_token field described in
/// Section 3.2.1".
///
/// Rotating one token of a lot touches that token alone. The answer is one
/// token object; a label it omits is kept, a label it changes is refused, and
/// so are a repeated value, changed flags or a changed key.
#[test]
fn rotating_one_token_of_a_lot_replaces_it_alone_and_keeps_its_label() {
    let sk = signer();
    let kept = format!(
        r#"{{"access_token":{}}}"#,
        issued(None, ROTATED, "reports:read", Some("R2"))
    );
    let as_ = FakeAs::with(vec![&two_of_three(), &kept]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&three(), 1_000).unwrap();
    let documents = s.usable_tokens(1_000).unwrap()[0].clone();

    let rotated = s.rotate_token(Some("reports"), 1_050).unwrap();
    assert_eq!(rotated.value.as_str(), ROTATED);
    assert_eq!(
        rotated.label.as_deref(),
        Some("reports"),
        "the omitted label is kept"
    );
    assert_eq!(
        rotated.manage.as_ref().map(|m| m.uri.as_str()),
        Some("https://as.example/token/R2")
    );
    let held = s.usable_tokens(1_050).unwrap();
    assert_eq!(held[0], &documents, "the other token is untouched");
    assert_eq!(held[1].value.as_str(), ROTATED);
    // The rotated token's clock starts at the rotation; its neighbour's did
    // not move.
    assert_eq!(labels(&s, 1_100), vec![Some("reports".to_owned())]);

    let mislabelled = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("documents"), ROTATED, "reports:read", Some("R3"))
    );
    let as_array = format!(
        r#"{{"access_token":[{}]}}"#,
        issued(Some("reports"), ROTATED, "reports:read", Some("R3"))
    );
    let same_value = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("reports"), REPORTS, "reports:read", Some("R3"))
    );
    let previous_management_value = format!(
        r#"{{"access_token":{}}}"#,
        issued(Some("reports"), "manage-R", "reports:read", Some("R3"))
    );
    let reflagged = format!(
        r#"{{"access_token":{{"label":"reports","value":"{ROTATED}","access":["reports:read"],
            "flags":["durable"],
            "manage":{{"uri":"https://as.example/token/R3","access_token":{{"value":"manage-R3"}}}}}}}}"#
    );
    let rekeyed = format!(
        r#"{{"access_token":{{"label":"reports","value":"{ROTATED}","access":["reports:read"],
            "key":"other-key",
            "manage":{{"uri":"https://as.example/token/R3","access_token":{{"value":"manage-R3"}}}}}}}}"#
    );
    for (body, expected) in [
        (mislabelled.as_str(), "changes the label"),
        (as_array.as_str(), "several access tokens"),
        (same_value.as_str(), "repeats the value"),
        (
            previous_management_value.as_str(),
            "previous management credential",
        ),
        (reflagged.as_str(), "changes the flags"),
        (rekeyed.as_str(), "key binding"),
    ] {
        let as_ = FakeAs::with(vec![&two_of_three(), body]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&three(), 1_000).unwrap();
        let before: Vec<_> = s
            .usable_tokens(1_000)
            .unwrap()
            .into_iter()
            .cloned()
            .collect();
        let e = s.rotate_token(Some("reports"), 1_050).unwrap_err();
        assert!(matches!(e, ClientError::Protocol(_)), "{e}");
        assert!(e.to_string().contains(expected), "{e}");
        let after: Vec<_> = s
            .usable_tokens(1_050)
            .unwrap()
            .into_iter()
            .cloned()
            .collect();
        assert_eq!(before, after, "a refused rotation changes nothing");
    }
}

/// GNAP-9635-§3.2.2 — the labels are what tells the tokens of a lot apart, so
/// managing one of several needs its label; §6.2 revokes that token and no
/// other.
#[test]
fn managing_one_of_several_needs_its_label_and_revokes_it_alone() {
    let sk = signer();
    let as_ = FakeAs::with(vec![&two_of_three(), ""]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&three(), 1_000).unwrap();

    let e = s.rotate_token(None, 1_010).unwrap_err();
    assert!(matches!(e, ClientError::Usage(_)), "{e}");
    assert!(e.to_string().contains("2 access tokens are held"), "{e}");
    let e = s.revoke_token(Some("calendar"), 1_010).unwrap_err();
    assert!(matches!(e, ClientError::Usage(_)), "{e}");
    assert!(e.to_string().contains("calendar"), "{e}");
    assert_eq!(as_.sent(), 1, "neither ambiguous call left the client");

    s.revoke_token(Some("documents"), 1_020).unwrap();
    assert_eq!(labels(&s, 1_020), vec![Some("reports".to_owned())]);
    let sent = as_.seen.borrow();
    assert_eq!(sent[1].method, "DELETE");
    assert_eq!(sent[1].url, "https://as.example/token/D");
}

/// GNAP-9635-§5.3 — a modification amends the request, and the response to
/// it is checked against the amended request, not the original one; the new
/// lot replaces what was held.
#[test]
fn a_modification_moves_the_expected_labels_with_the_request() {
    let sk = signer();
    let opened = format!(
        r#"{{"access_token":{},
            "continue":{{"uri":"https://as.example/continue",
                        "access_token":{{"value":"80UPRY5NM33OMUKMKSKU"}},"wait":0}}}}"#,
        issued(Some("documents"), DOCUMENTS, "documents:read", Some("D"))
    );
    let amended: ContinueRequest = serde_json::from_str(
        r#"{"access_token":[{"label":"reports","access":["reports:read"]},
                            {"label":"calendar","access":["calendar:read"]}]}"#,
    )
    .unwrap();
    let stale = format!(
        r#"{{"access_token":[{}],
            "continue":{{"uri":"https://as.example/continue",
                        "access_token":{{"value":"NEXT"}},"wait":0}}}}"#,
        issued(Some("documents"), DOCUMENTS, "documents:read", Some("D"))
    );
    let fresh = format!(
        r#"{{"access_token":[{}],
            "continue":{{"uri":"https://as.example/continue",
                        "access_token":{{"value":"NEXT"}},"wait":0}}}}"#,
        issued(Some("calendar"), CALENDAR, "calendar:read", Some("C"))
    );

    // The old label is no longer part of the request once it is amended.
    let as_ = FakeAs::with(vec![&opened, &stale]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(Some("documents")), 1_000).unwrap();
    let e = s.modify_grant(&amended, 1_010).unwrap_err();
    assert!(e.to_string().contains("did not ask for"), "{e}");
    assert_eq!(
        labels(&s, 1_010),
        vec![Some("documents".to_owned())],
        "an unusable response leaves the held token alone"
    );

    // A lot answering the amended request replaces what was held.
    let as_ = FakeAs::with(vec![&opened, &fresh]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(Some("documents")), 1_000).unwrap();
    let step = s.modify_grant(&amended, 1_010).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
    assert_eq!(labels(&s, 1_010), vec![Some("calendar".to_owned())]);
}

/// GNAP-9635-§6.1-M01 — the rotated token keeps "the same rights and
/// properties as the original token". Flags are a set (§3.2.1 forbids
/// repeating one), so their order does not matter. A `key` field the session
/// cannot compare is another matter: it holds no key material, and a `kid` is
/// a name that two different keys can share, so a key that appears where the
/// original omitted it is refused even when it is, in fact, the session's own.
#[test]
fn a_rotation_is_compared_by_meaning_not_by_bytes() {
    let sk = signer();
    let manage = |handle: &str| {
        format!(
            r#""manage":{{"uri":"https://as.example/token/{handle}",
                        "access_token":{{"value":"manage-{handle}"}}}}"#
        )
    };
    let held = format!(
        r#"{{"access_token":{{"value":"{DOCUMENTS}","access":["documents:read"],
            "flags":["durable","x-demo"],{}}}}}"#,
        manage("H")
    );
    let reordered = format!(
        r#"{{"access_token":{{"value":"{ROTATED}","access":["documents:read"],
            "flags":["x-demo","durable"],{}}}}}"#,
        manage("H2")
    );
    let as_ = FakeAs::with(vec![&held, &reordered]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(None), 1_000).unwrap();
    let rotated = s.rotate_token(None, 1_050).unwrap();
    assert_eq!(rotated.value.as_str(), ROTATED);

    let spelled_out = |jwk: &serde_json::Map<String, serde_json::Value>| {
        format!(
            r#"{{"access_token":{{"value":"{ROTATED}","access":["documents:read"],
                "key":{{"proof":"httpsig","jwk":{}}},{}}}}}"#,
            serde_json::Value::Object(jwk.clone()),
            manage("H2")
        )
    };
    let unbound = format!(
        r#"{{"access_token":{{"value":"{DOCUMENTS}","access":["documents:read"],{}}}}}"#,
        manage("H")
    );
    // A different RSA key under the very `kid` the session signs with: the
    // name matches, the key does not.
    let impostor = Ps256Signer::generate(2048, "gnap-demo").unwrap();
    assert_eq!(impostor.key_id(), sk.key_id());
    assert_ne!(
        impostor.public_jwk().unwrap()["n"],
        sk.public_jwk().unwrap()["n"]
    );

    for (jwk, why) in [
        (
            impostor.public_jwk().unwrap(),
            "another key with the same kid",
        ),
        (
            sk.public_jwk().unwrap(),
            "the session's own key, which it cannot recognise",
        ),
    ] {
        let as_ = FakeAs::with(vec![&unbound, &spelled_out(&jwk)]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&single(None), 1_000).unwrap();
        let e = s.rotate_token(None, 1_050).unwrap_err();
        assert!(e.to_string().contains("key binding"), "{why}: {e}");
        assert_eq!(
            s.usable_tokens(1_050).unwrap()[0].value.as_str(),
            DOCUMENTS,
            "{why}: the held token is unchanged"
        );
    }

    // Two explicit keys have to match as written.
    let bound = format!(
        r#"{{"access_token":{{"value":"{DOCUMENTS}","access":["documents:read"],
            "key":{{"proof":"httpsig","jwk":{}}},{}}}}}"#,
        serde_json::Value::Object(sk.public_jwk().unwrap()),
        manage("H")
    );
    let as_ = FakeAs::with(vec![&bound, &spelled_out(&sk.public_jwk().unwrap())]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(None), 1_000).unwrap();
    assert_eq!(s.rotate_token(None, 1_050).unwrap().value.as_str(), ROTATED);
    let as_ = FakeAs::with(vec![&bound, &spelled_out(&impostor.public_jwk().unwrap())]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&single(None), 1_000).unwrap();
    let e = s.rotate_token(None, 1_050).unwrap_err();
    assert!(e.to_string().contains("key binding"), "{e}");
}
