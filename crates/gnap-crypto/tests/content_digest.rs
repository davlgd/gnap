//! `Content-Digest`: RFC 9421 vectors and validation rules.

use gnap_crypto::digest::{content_digest, verify_content_digest, DigestAlgorithm, DigestError};

/// Test request and response from Appendix B.2 of RFC 9421.
const REQUEST: &[u8] = br#"{"hello": "world"}"#;
const REQUEST_SHA512: &str = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";
const RESPONSE: &[u8] = br#"{"message": "good dog"}"#;
const RESPONSE_SHA512: &str = "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:";

/// GNAP-9635-§7.3.1-M06 — the signer computes this field and includes it.
#[test]
fn rfc9421_test_vectors() {
    assert_eq!(
        content_digest(REQUEST, DigestAlgorithm::Sha512),
        REQUEST_SHA512
    );
    assert_eq!(
        content_digest(RESPONSE, DigestAlgorithm::Sha512),
        RESPONSE_SHA512
    );
}

/// GNAP-9635-§7.3.1-M07 — the verifier validates this field.
/// GNAP-9635-§7.3.1-M18 — it recomputes it whenever the message has content.
#[test]
fn validation_accepts_and_rejects_correctly() {
    assert!(verify_content_digest(REQUEST, REQUEST_SHA512).is_ok());

    // The other message's digest must not pass.
    let e = verify_content_digest(REQUEST, RESPONSE_SHA512).unwrap_err();
    assert_eq!(
        e,
        DigestError::Mismatch {
            algorithm: "sha-512"
        }
    );
    assert!(e.to_string().contains("§7.3.1"), "{e}");

    // Nor must content altered by a single byte.
    let e = verify_content_digest(br#"{"hello": "World"}"#, REQUEST_SHA512).unwrap_err();
    assert!(matches!(e, DigestError::Mismatch { .. }));
}

/// A malformed value is reported, not ignored.
#[test]
fn malformed_values_are_reported() {
    for bad in ["sha-256=abc", "sha-256=:abc", ":abc:", "sha-256"] {
        let e = verify_content_digest(REQUEST, bad).unwrap_err();
        assert!(
            matches!(e, DigestError::Malformed(_)),
            "`{bad}` should be reported as malformed, got: {e:?}"
        );
    }
    let e = verify_content_digest(REQUEST, "sha-256=:not base64!:").unwrap_err();
    assert_eq!(e, DigestError::NotBase64);
}

/// Several digests: one known match is enough, but a known digest that does
/// not match is still a failure.
#[test]
fn several_digests_in_one_field() {
    let sha256 = content_digest(REQUEST, DigestAlgorithm::Sha256);
    let combined = format!("{sha256}, {REQUEST_SHA512}");
    assert!(verify_content_digest(REQUEST, &combined).is_ok());

    // An unknown algorithm is skipped when a known one matches.
    let with_unknown = format!("blake2b-256=:AAAA:, {sha256}");
    assert!(verify_content_digest(REQUEST, &with_unknown).is_ok());

    // But no known algorithm at all is an error.
    let e = verify_content_digest(REQUEST, "blake2b-256=:AAAA:").unwrap_err();
    assert!(matches!(e, DigestError::UnsupportedAlgorithm(_)));

    // And a known digest that diverges fails the whole field.
    let e = verify_content_digest(REQUEST, &format!("{sha256}, {RESPONSE_SHA512}")).unwrap_err();
    assert!(matches!(e, DigestError::Mismatch { .. }));
}

/// RFC 9530 §2 makes `Content-Digest` a Structured Fields Dictionary of Byte
/// Sequences, so it is read with that grammar (RFC 9651 §4.2.2, §4.2.7) and
/// not by splitting on commas.
#[test]
fn the_field_is_read_as_a_structured_dictionary() {
    // §4.2.7 — padding is synthesized, so an unpadded sequence decodes.
    let unpadded = REQUEST_SHA512.trim_end_matches(':').trim_end_matches('=');
    assert!(verify_content_digest(REQUEST, &format!("{unpadded}:")).is_ok());

    // A member may carry parameters; they have to parse, and mean nothing here.
    assert!(verify_content_digest(REQUEST, &format!("{REQUEST_SHA512};p=1;q")).is_ok());

    // A repeated key denotes its last member (§4.2.2).
    let wrong_then_right = format!("{RESPONSE_SHA512},{REQUEST_SHA512}");
    assert!(verify_content_digest(REQUEST, &wrong_then_right).is_ok());
    let right_then_wrong = format!("{REQUEST_SHA512},{RESPONSE_SHA512}");
    assert!(matches!(
        verify_content_digest(REQUEST, &right_then_wrong),
        Err(DigestError::Mismatch { .. })
    ));

    // What the Dictionary grammar refuses.
    let spaced = REQUEST_SHA512.replacen('=', " =", 1);
    for bad in [
        format!("{REQUEST_SHA512},"),     // trailing comma
        spaced,                           // whitespace before the `=`
        format!("{REQUEST_SHA512};"),     // an empty parameter
        format!("{REQUEST_SHA512};P=1"),  // a parameter name is lowercase
        format!("{REQUEST_SHA512};p=?2"), // not a bare item
        format!(",{REQUEST_SHA512}"),     // an empty member
        "SHA-512=:AAAA:".to_owned(),      // a key is lowercase
    ] {
        let e = verify_content_digest(REQUEST, &bad).unwrap_err();
        assert!(
            matches!(e, DigestError::Malformed(_)),
            "`{bad}` should be malformed, got: {e:?}"
        );
    }

    // Every member is parsed: an unreadable one is not rescued by a good one,
    // whether its algorithm is unknown or its key is repeated further on.
    let e =
        verify_content_digest(REQUEST, &format!("unknown=:%%%:, {REQUEST_SHA512}")).unwrap_err();
    assert_eq!(e, DigestError::NotBase64);
    let e =
        verify_content_digest(REQUEST, &format!("sha-512=garbage, {REQUEST_SHA512}")).unwrap_err();
    assert!(matches!(e, DigestError::Malformed(_)), "{e:?}");
}
