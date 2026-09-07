//! Public request signing with real PS256 verification and replay memory.

use gnap_client::{sign_request, ClientError, HttpRequest};
use gnap_crypto::ps256::Ps256Signer;
use gnap_crypto::verify::{verify_request, Expectations, SignedRequest};
use gnap_types::token::TokenValue;
use std::cell::RefCell;
use std::collections::HashSet;

const NOW: u64 = 1_700_000_000;
const URL: &str = "https://rs.example/files/a%2Fb?mode=read&x=%41";

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(include_str!("fixtures/rfc9421-b12.pkcs1.pem"), "client-key")
        .unwrap()
}

fn verifies(request: &HttpRequest, seen: &RefCell<HashSet<String>>) -> bool {
    verify_request(
        &SignedRequest {
            method: &request.method,
            target_uri: &request.url,
            headers: &request.headers,
            body: request.body.as_deref(),
        },
        &signer().verifier(),
        &Expectations {
            now: NOW,
            max_clock_skew: 30,
            key_id: Some("client-key"),
        },
        &|nonce: &str, _: u64| seen.borrow_mut().insert(nonce.to_owned()),
    )
    .is_ok()
}

#[test]
fn arbitrary_content_and_exact_target_are_preserved_and_signed() {
    let mut unsigned = HttpRequest::new("PUT", URL)
        .header("Content-Type", "application/octet-stream")
        .header("X-Application", "untouched");
    unsigned.body = Some(vec![0, 255, 13, 10]);
    let token = TokenValue::new("descendant+/==").unwrap();
    let request = sign_request(unsigned.clone(), &signer(), Some(&token), NOW).unwrap();
    assert_eq!(request.method, unsigned.method);
    assert_eq!(request.url, URL);
    assert_eq!(request.body, unsigned.body);
    assert_eq!(&request.headers[..2], &unsigned.headers);
    assert_eq!(
        request.header_value("Authorization"),
        Some("GNAP descendant+/==")
    );
    assert!(verifies(&request, &RefCell::default()));

    for alteration in 0..4 {
        let mut changed = request.clone();
        match alteration {
            0 => changed.body.as_mut().unwrap()[0] = 1,
            1 => changed.url = URL.replace("%41", "A"),
            2 => changed.method = "GET".into(),
            _ => {
                changed
                    .headers
                    .iter_mut()
                    .find(|(name, _)| name == "Authorization")
                    .unwrap()
                    .1 = "GNAP parent".into();
            }
        }
        assert!(!verifies(&changed, &RefCell::default()));
    }
}

#[test]
fn empty_content_is_not_confused_with_absent_content() {
    for body in [None, Some(Vec::new())] {
        let mut unsigned = HttpRequest::new("POST", URL);
        unsigned.body = body.clone();
        let request = sign_request(unsigned, &signer(), None, NOW).unwrap();
        assert_eq!(request.body, body);
        assert_eq!(
            request.header_value("Content-Digest").is_some(),
            body.is_some()
        );
        assert!(request.header_value("Content-Type").is_none());
        assert!(request.header_value("Authorization").is_none());
        assert!(verifies(&request, &RefCell::default()));
    }
}

#[test]
fn a_fresh_signature_is_needed_for_each_use() {
    let request = HttpRequest::new("GET", URL);
    let first = sign_request(request.clone(), &signer(), None, NOW).unwrap();
    let second = sign_request(request, &signer(), None, NOW).unwrap();
    let seen = RefCell::default();
    assert!(verifies(&first, &seen));
    assert!(!verifies(&first, &seen));
    assert!(verifies(&second, &seen));
    assert_eq!(seen.borrow().len(), 2);
}

#[test]
fn supplied_security_headers_are_rejected_even_without_a_token() {
    for name in [
        "aUtHoRiZaTiOn",
        "SIGNATURE",
        "signature-input",
        "content-DIGEST",
    ] {
        for token in [None, Some(TokenValue::new("token").unwrap())] {
            let request = HttpRequest::new("GET", URL).header(name, "supplied");
            assert!(matches!(
                sign_request(request, &signer(), token.as_ref(), NOW),
                Err(ClientError::Usage(_))
            ));
        }
    }
}
