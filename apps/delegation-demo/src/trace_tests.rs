use super::*;
use gnap_client::{sign_jose_request, sign_request};
use gnap_crypto::jws::JwsMethod;
use gnap_crypto::Ed25519Signer;
use gnap_types::token::TokenValue;
use std::cell::Cell;

/// The budget a full trace serializes within, in bytes: chosen, then checked
/// against the largest record the bounds allow.
const MAX_TRACE_BYTES: usize = 128 * 1024;

const ORIGIN: &str = "https://demo.example";
const CANARY: &str = "canary7XQ";

fn request(method: &str, path: &str) -> HttpRequest {
    HttpRequest::new(method, format!("{ORIGIN}{path}"))
}

fn response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

fn json(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn only_the_labs_own_origin_and_exact_paths_are_classified() {
    for (path, to, route) in [
        ("/gnap", Party::AuthorizationServer, Route::Grant),
        ("/continue", Party::AuthorizationServer, Route::Continue),
        (
            "/token/AbC-1_2",
            Party::AuthorizationServer,
            Route::TokenManagement,
        ),
        ("/resource/folder", Party::DocumentsServer, Route::Folder),
        ("/resource/archive", Party::DocumentsServer, Route::Archive),
        (
            crate::derivation::RS1_PATH,
            Party::DocumentsServer,
            Route::FolderMetadata,
        ),
        (
            crate::multiple::REPORTS_PATH,
            Party::ReportsServer,
            Route::Reports,
        ),
    ] {
        let summary = summarize_request(&request("GET", path), ORIGIN);
        assert_eq!((summary.to, summary.route), (to, route), "{path}");
    }
    for url in [
        "https://evil.example/gnap",
        "https://demo.example.evil/gnap",
        "https://demo.example/gnap?x=1",
        "https://demo.example/gnap#f",
        "https://demo.example/gnap/",
        "https://demo.example/token/",
        "https://demo.example/token/a/b",
        "https://demo.example/token/a.b",
        "https://demo.example/resource/archive-metadata",
    ] {
        let summary = summarize_request(&HttpRequest::new("GET", url), ORIGIN);
        assert_eq!(
            (summary.to, summary.route),
            (Party::Unknown, Route::Unknown),
            "{url}"
        );
    }
}

#[test]
fn the_gnap_scheme_is_matched_exactly() {
    assert!(gnap_scheme("GNAP abc"));
    for value in [
        "GNAPevil abc",
        "GNAP",
        "GNAP ",
        "gnap abc",
        "Bearer abc",
        "Basic GNAP",
    ] {
        assert!(!gnap_scheme(value), "{value}");
    }
}

/// A request and a response in which every value the record could see holds
/// the canary, with the lab's real paths and GNAP field names kept, so that
/// every branch that reads them runs.
fn loaded(slot: Option<usize>) -> (HttpRequest, HttpResponse) {
    let canary = |n: usize| {
        if slot.is_none_or(|s| s == n) {
            CANARY
        } else {
            "plain"
        }
    };
    let body = serde_json::json!({
        "access_token": [{"label": canary(0), "access": [canary(1), {"type": canary(2)}, crate::FOLDER_READ], "value": canary(3)}],
        "client": {"key": {"jwk": {"kid": canary(4)}}},
        "interact": {"start": [canary(5)], "finish": {"nonce": canary(6), "uri": canary(7)}},
        "interact_ref": canary(8),
        "subject": {"sub_ids": [{"id": canary(9)}]},
        canary(10): canary(11),
        "error": {"code": canary(12), "description": canary(13)},
        "instance_id": canary(14),
    });
    let mut request = request("POST", &format!("/token/{}", canary(15)));
    request.url.push_str(&format!("?q={}", canary(16)));
    request.headers = vec![
        ("authorization".into(), format!("GNAP {}", canary(17))),
        (
            "signature-input".into(),
            format!(
                "{}=(\"@method\" \"{}\");keyid=\"{}\";nonce=\"{}\";alg=\"{}\"",
                canary(18),
                canary(19),
                canary(20),
                canary(21),
                canary(22)
            ),
        ),
        (
            "signature".into(),
            format!("{}=:{}:", canary(18), canary(23)),
        ),
        (
            "content-digest".into(),
            format!("{}=:{}:", canary(24), canary(25)),
        ),
        (canary(26).into(), canary(27).into()),
        (
            "content-type".into(),
            format!("application/json; {}", canary(28)),
        ),
    ];
    request.body = Some(serde_json::to_vec(&body).unwrap());
    let mut answer = response(
        400,
        &[
            ("content-type", "application/json"),
            ("x-extra", canary(29)),
        ],
        &serde_json::to_string(&body).unwrap(),
    );
    answer.headers.push((canary(30).into(), canary(31).into()));
    (request, answer)
}

/// The canary in each value in turn, then in all of them, never reaches the
/// record: neither in a request summary nor in a response's.
#[test]
fn no_value_from_an_exchange_reaches_the_record() {
    for slot in (0..=31).map(Some).chain([None]) {
        let (request, answer) = loaded(slot);
        let summaries = format!(
            "{}{}",
            json(&summarize_request(&request, ORIGIN)),
            json(&summarize_response(&answer))
        );
        assert!(!summaries.contains(CANARY), "slot {slot:?}: {summaries}");
    }
}

/// A registered error code is named from the registry's list; an unregistered
/// one, or a description, isn't.
#[test]
fn only_a_registered_error_code_is_named() {
    let named = |body: &str| match summarize_response(&response(
        400,
        &[("content-type", "application/json")],
        body,
    )) {
        Outcome::Response { body, .. } => body.error,
        Outcome::NoResponse => unreachable!(),
    };
    assert_eq!(
        named(r#"{"error":"invalid_request"}"#),
        Some("invalid_request")
    );
    assert_eq!(
        named(r#"{"error":{"code":"user_denied","description":"x"}}"#),
        Some("user_denied")
    );
    assert_eq!(named(r#"{"error":"invalid_request_canary7XQ"}"#), None);
    assert_eq!(
        named(r#"{"error":{"description":"invalid_request"}}"#),
        None
    );
}

#[test]
fn the_announced_proof_comes_from_the_fields_and_their_parse() {
    let signer = Ed25519Signer::generate("k").unwrap();
    let token = TokenValue::new("t0k3n").unwrap();
    let httpsig = sign_request(
        request("GET", "/resource/folder"),
        &signer,
        Some(&token),
        1_700_000_000,
    )
    .unwrap();
    let summary = summarize_request(&httpsig, ORIGIN);
    assert_eq!(summary.proof, AnnouncedProof::Httpsig);
    assert!(summary.covered.contains(&Covered::Method));
    assert!(summary.covered.contains(&Covered::TargetUri));
    assert!(summary.covered.contains(&Covered::Authorization));
    assert!(summary.gnap_authorization);

    let jwsd = sign_jose_request(
        request("GET", "/resource/folder"),
        JwsMethod::Jwsd,
        &signer,
        Some(&token),
        1_700_000_000,
    )
    .unwrap();
    assert_eq!(summarize_request(&jwsd, ORIGIN).proof, AnnouncedProof::Jwsd);
    let jws = sign_jose_request(
        request("POST", "/gnap").json_body(br#"{"client":"c"}"#.to_vec()),
        JwsMethod::Jws,
        &signer,
        None,
        1_700_000_000,
    )
    .unwrap();
    let summary = summarize_request(&jws, ORIGIN);
    assert_eq!(summary.proof, AnnouncedProof::Jws);
    assert_eq!(
        summary.body.kind,
        BodyKind::Jose,
        "an attached JWS isn't decoded"
    );

    let mut both = httpsig.clone();
    both.headers.push(("detached-jws".into(), "a..b".into()));
    assert_eq!(
        summarize_request(&both, ORIGIN).proof,
        AnnouncedProof::Ambiguous
    );
    let mut twice = httpsig.clone();
    let input = twice
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("signature-input"))
        .unwrap()
        .clone();
    twice.headers.push(input);
    assert_eq!(
        summarize_request(&twice, ORIGIN).proof,
        AnnouncedProof::Ambiguous
    );
    let mut broken = request("GET", "/resource/folder");
    broken.headers = vec![
        ("signature-input".into(), "sig=not-a-list".into()),
        ("signature".into(), "sig=:AAAA:".into()),
    ];
    assert_eq!(
        summarize_request(&broken, ORIGIN).proof,
        AnnouncedProof::Unparsable
    );
    let mut crowded = httpsig;
    crowded
        .headers
        .extend((0..MAX_HEADERS).map(|i| (format!("x-{i}"), String::new())));
    assert_eq!(
        summarize_request(&crowded, ORIGIN).proof,
        AnnouncedProof::Unparsable
    );
    assert_eq!(
        summarize_request(&request("GET", "/gnap"), ORIGIN).proof,
        AnnouncedProof::None
    );
}

#[test]
fn bodies_are_described_within_their_bounds() {
    let kind = |body: &[u8]| shape(Some(body), false).kind;
    assert_eq!(kind(b""), BodyKind::Empty);
    assert_eq!(kind(b"not json"), BodyKind::NotJson);
    assert_eq!(kind(b"[1]"), BodyKind::Array);
    assert_eq!(kind(b"true"), BodyKind::Scalar);
    assert_eq!(kind(&vec![b' '; MAX_PARSED_BODY + 1]), BodyKind::TooLarge);
    let deep = format!(
        "{}{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    assert_eq!(kind(deep.as_bytes()), BodyKind::TooDeep);

    let many = serde_json::json!({"access_token": (0..10).map(|_| serde_json::json!({
        "label": "documents",
        "access": [crate::FOLDER_READ, crate::FOLDER_READ, crate::ARCHIVE_READ, crate::multiple::REPORTS_READ,
                   crate::derivation::METADATA_READ, "other", {"type": "x"}],
    })).collect::<Vec<_>>(), "unknown": 1});
    let described = shape(Some(&serde_json::to_vec(&many).unwrap()), false);
    assert_eq!(described.tokens.len(), MAX_TOKENS_SHOWN);
    assert_eq!(described.more_tokens, 8);
    assert_eq!(described.other_fields, 1);
    let token = &described.tokens[0];
    assert_eq!(token.label, Some(Label::Documents));
    assert_eq!(
        token.rights,
        [
            Right::Folder,
            Right::Archive,
            Right::Reports,
            Right::Metadata
        ]
    );
    assert_eq!(
        token.other_rights, 3,
        "the repeated right, the unknown string, and the object"
    );
}

/// The rights the record names are the lab's, written out here rather than
/// read from the constants under test.
#[test]
fn the_right_catalogue_is_the_labs() {
    for (name, right) in [
        ("synthetic-folder:read", Right::Folder),
        ("synthetic-archive:read", Right::Archive),
        ("synthetic-reports:read", Right::Reports),
        ("archive-metadata:read", Right::Metadata),
    ] {
        assert_eq!(Right::named(name), Some(right));
        assert_eq!(json(&right), format!("\"{name}\""));
    }
    assert_eq!(Right::named("synthetic-metadata:read"), None);
}

/// A transport that answers from a script, and counts its calls.
struct Scripted {
    calls: Cell<usize>,
    fail: bool,
}

impl HttpTransport for Scripted {
    type Error = &'static str;
    fn send(&self, _: HttpRequest) -> Result<HttpResponse, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            Err("down")
        } else {
            Ok(response(204, &[], ""))
        }
    }
}

#[test]
fn recording_keeps_the_transports_result_and_bounds_the_trace() {
    let trace = SharedTrace::default();
    let ok = Recording::new(
        Scripted {
            calls: Cell::new(0),
            fail: false,
        },
        ORIGIN.into(),
        trace.clone(),
    );
    for _ in 0..MAX_TRACE + 6 {
        assert_eq!(ok.send(request("DELETE", "/continue")).unwrap().status, 204);
    }
    assert_eq!(
        ok.inner.calls.get(),
        MAX_TRACE + 6,
        "every request still goes out"
    );
    {
        let trace = trace.lock().unwrap();
        assert_eq!(trace.attempts.len(), MAX_TRACE);
        assert_eq!(trace.dropped, 6);
    }

    let fresh = SharedTrace::default();
    let failing = Recording::new(
        Scripted {
            calls: Cell::new(0),
            fail: true,
        },
        ORIGIN.into(),
        fresh.clone(),
    );
    assert_eq!(failing.send(request("POST", "/gnap")).unwrap_err(), "down");
    assert_eq!(
        fresh.lock().unwrap().attempts[0].outcome,
        Outcome::NoResponse
    );

    // A poisoned trace loses the entry, never the exchange.
    let poisoned = SharedTrace::default();
    let clone = poisoned.clone();
    let _ = std::thread::spawn(move || {
        let _guard = clone.lock().unwrap();
        panic!("poison the trace");
    })
    .join();
    let recording = Recording::new(
        Scripted {
            calls: Cell::new(0),
            fail: false,
        },
        ORIGIN.into(),
        poisoned,
    );
    assert_eq!(
        recording
            .send(request("GET", "/resource/folder"))
            .unwrap()
            .status,
        204
    );
}

/// Sixty-four attempts with every list and counter at its bound, and the
/// longest registered error code, stay within the chosen budget.
#[test]
fn a_full_trace_at_every_bound_stays_within_its_budget() {
    let longest = ErrorCode::REGISTERED
        .iter()
        .copied()
        .max_by_key(|code| code.len());
    let body = Shape {
        kind: BodyKind::TooDeep,
        fields: [
            FieldName::AccessToken,
            FieldName::Client,
            FieldName::Continue,
            FieldName::Error,
            FieldName::InstanceId,
            FieldName::Interact,
            FieldName::InteractRef,
            FieldName::Subject,
            FieldName::User,
        ]
        .into_iter()
        .map(|name| Field {
            name,
            kind: JsonKind::Object,
        })
        .collect(),
        other_fields: u16::MAX,
        tokens: vec![
            TokenShape {
                label: Some(Label::Documents),
                other_label: true,
                rights: vec![
                    Right::Folder,
                    Right::Archive,
                    Right::Reports,
                    Right::Metadata
                ],
                other_rights: u16::MAX,
            };
            MAX_TOKENS_SHOWN
        ],
        more_tokens: u16::MAX,
        error: longest,
    };
    let attempt = Attempt {
        seq: u16::MAX,
        request: RequestSummary {
            to: Party::AuthorizationServer,
            route: Route::TokenManagement,
            method: Method::Options,
            proof: AnnouncedProof::Unparsable,
            covered: vec![
                Covered::Method,
                Covered::TargetUri,
                Covered::ContentDigest,
                Covered::ContentType,
                Covered::ContentLength,
                Covered::Authorization,
            ],
            other_components: u16::MAX,
            alg: Some(SignatureAlg::EcdsaP256Sha256),
            gnap_authorization: true,
            digests: vec![DigestAlg::Sha256, DigestAlg::Sha512],
            body: body.clone(),
        },
        outcome: Outcome::Response {
            status: 599,
            media: Some(MediaType::Ambiguous),
            body,
        },
    };
    let trace = Trace {
        attempts: vec![attempt; MAX_TRACE],
        dropped: u16::MAX,
    };
    let size = json(&trace).len();
    assert!(size <= MAX_TRACE_BYTES, "{size} bytes");
}

#[test]
fn a_full_trace_counts_what_it_no_longer_keeps() {
    let mut trace = Trace::default();
    let summary = summarize_request(&request("GET", "/gnap"), ORIGIN);
    for _ in 0..MAX_TRACE + 3 {
        trace.record(Some(summary.clone()), Some(Outcome::NoResponse));
    }
    assert_eq!(trace.attempts.len(), MAX_TRACE);
    assert_eq!(trace.dropped, 3);
    assert_eq!(
        trace.attempts.last().unwrap().seq,
        u16::try_from(MAX_TRACE - 1).unwrap()
    );
}

#[test]
fn one_field_with_two_signatures_is_ambiguous() {
    let mut request = request("GET", "/resource/folder");
    request.headers = vec![
        (
            "signature-input".into(),
            r#"a=("@method");created=1, b=("@method");created=1"#.into(),
        ),
        ("signature".into(), "a=:AAAA:, b=:AAAA:".into()),
    ];
    assert_eq!(
        summarize_request(&request, ORIGIN).proof,
        AnnouncedProof::Ambiguous
    );
}

#[test]
fn only_the_labs_labels_are_named() {
    let label = |value: &str| token_shape(&serde_json::json!({"label": value, "access": []}));
    assert_eq!(label("documents").label, Some(Label::Documents));
    assert_eq!(label("reports").label, Some(Label::Reports));
    let other = label("documents2");
    assert_eq!(other.label, None);
    assert!(other.other_label);
    let unlabelled = token_shape(&serde_json::json!({"access": []}));
    assert_eq!((unlabelled.label, unlabelled.other_label), (None, false));
}

/// The page names the same error codes as the registry, and the digest and
/// signature algorithms the way the page's tables spell them.
#[test]
fn the_pages_tables_match_the_records_names() {
    let script = include_str!("../static/app.js");
    let line = script
        .lines()
        .find(|line| line.starts_with("const ERROR_CODES = ["))
        .expect("the page's error code table");
    let mut page: Vec<&str> = line.split('\'').skip(1).step_by(2).collect();
    let mut registry = ErrorCode::REGISTERED.to_vec();
    page.sort_unstable();
    registry.sort_unstable();
    assert_eq!(page, registry);
    assert_eq!(json(&DigestAlg::Sha256), "\"sha-256\"");
    // Every closed value has its label in the page's tables, as a key.
    let values: Vec<String> = [
        json(&[
            Party::AuthorizationServer,
            Party::DocumentsServer,
            Party::ReportsServer,
        ]),
        json(&[
            Route::Grant,
            Route::Continue,
            Route::TokenManagement,
            Route::Folder,
            Route::Archive,
            Route::FolderMetadata,
            Route::Reports,
        ]),
        json(&[
            Method::Get,
            Method::Post,
            Method::Patch,
            Method::Delete,
            Method::Options,
        ]),
        json(&[
            AnnouncedProof::Httpsig,
            AnnouncedProof::Jws,
            AnnouncedProof::Jwsd,
            AnnouncedProof::Ambiguous,
            AnnouncedProof::Unparsable,
            AnnouncedProof::None,
        ]),
        json(&[
            Covered::Method,
            Covered::TargetUri,
            Covered::ContentDigest,
            Covered::ContentType,
            Covered::ContentLength,
            Covered::Authorization,
        ]),
        json(&[
            SignatureAlg::RsaPssSha512,
            SignatureAlg::EcdsaP256Sha256,
            SignatureAlg::Ed25519,
        ]),
        json(&[DigestAlg::Sha256, DigestAlg::Sha512]),
        json(&[
            MediaType::Json,
            MediaType::Jose,
            MediaType::Other,
            MediaType::Ambiguous,
        ]),
        json(&[
            BodyKind::Empty,
            BodyKind::Object,
            BodyKind::Array,
            BodyKind::Scalar,
            BodyKind::Jose,
            BodyKind::NotJson,
            BodyKind::TooLarge,
            BodyKind::TooDeep,
        ]),
        json(&[
            FieldName::AccessToken,
            FieldName::Client,
            FieldName::Continue,
            FieldName::Error,
            FieldName::InstanceId,
            FieldName::Interact,
            FieldName::InteractRef,
            FieldName::Subject,
            FieldName::User,
        ]),
        json(&[Label::Documents, Label::Reports]),
        json(&[
            Right::Folder,
            Right::Archive,
            Right::Reports,
            Right::Metadata,
        ]),
    ]
    .iter()
    .flat_map(|list| serde_json::from_str::<Vec<String>>(list).unwrap())
    .collect();
    for value in values {
        let key = |quote: &str| format!("{quote}{value}{quote}: ");
        assert!(
            script.contains(&key("'")) || script.contains(&format!(" {value}: ")),
            "the page has no label for {value}"
        );
    }
}
