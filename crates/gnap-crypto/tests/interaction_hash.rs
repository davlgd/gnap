//! Interaction hash: RFC test vectors and the rules of §4.2.3.

use gnap_crypto::hash::{
    interaction_hash, interaction_hash_named, verify_interaction_hash, HashError, HashMethod,
    InteractionHashInput,
};
use serde_json::Value;

const CORPUS: &str = include_str!("../../../vectors/interaction-hash.json");

/// GNAP-9635-§4.2.3-M01 — the AS always supplies this hash, the client validates it.
/// GNAP-9635-§4.2-M06 — the hash combines both nonces and the reference.
#[test]
fn vector_corpus() {
    let doc: Value = serde_json::from_str(CORPUS).expect("unreadable corpus");
    let vectors = doc["vectors"].as_array().expect("`vectors` expected");
    assert!(!vectors.is_empty(), "empty corpus");

    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let input = InteractionHashInput {
            client_nonce: v["client_nonce"].as_str().unwrap(),
            as_nonce: v["as_nonce"].as_str().unwrap(),
            interact_ref: v["interact_ref"].as_str().unwrap(),
            grant_endpoint: v["grant_endpoint"].as_str().unwrap(),
        };
        let name = v["hash_method"].as_str().unwrap();
        let expected = v["expected"].as_str().unwrap();

        let got =
            interaction_hash_named(&input, Some(name)).unwrap_or_else(|e| panic!("{id} : {e}"));
        assert_eq!(got, expected, "\n{id}: hash mismatch ({name})");

        // Verification must accept the right value and reject anything else.
        let method = HashMethod::from_name(name).unwrap();
        assert!(verify_interaction_hash(&input, method, expected).unwrap());
        assert!(!verify_interaction_hash(&input, method, "wrong").unwrap());

        println!("  {id}: {name} — conformant");
    }
}

/// GNAP-9635-§4.2.3-M02 — the name comes from the IANA "Named Information
/// Hash Algorithm" registry, not from JOSE.
#[test]
fn names_come_from_iana_not_jose() {
    assert_eq!(HashMethod::from_name("sha-256"), Some(HashMethod::Sha256));
    assert_eq!(
        HashMethod::from_name("sha3-512"),
        Some(HashMethod::Sha3_512)
    );

    // JOSE names: not the registry expected here.
    for jose in ["SHA-256", "S256", "sha256", "PS256"] {
        assert_eq!(
            HashMethod::from_name(jose),
            None,
            "`{jose}` should not resolve"
        );
    }

    let input = demo();
    let e = interaction_hash_named(&input, Some("sha256")).unwrap_err();
    assert!(matches!(e, HashError::UnsupportedMethod(_)));
    assert!(e.to_string().contains("Named Information"), "{e}");
}

/// An absent `hash_method` means `sha-256` (§4.2.3).
#[test]
fn the_default_algorithm_is_sha_256() {
    let input = demo();
    assert_eq!(
        interaction_hash_named(&input, None).unwrap(),
        interaction_hash(&input, HashMethod::Sha256).unwrap()
    );
    assert_eq!(HashMethod::DEFAULT, HashMethod::Sha256);
}

/// The base is four values joined by newlines, with no whitespace and no
/// trailing newline (§4.2.3).
#[test]
fn the_base_matches_the_rfc_exactly() {
    let input = demo();
    let base = input.base().unwrap();
    assert_eq!(
        base,
        "VJLO6A4CATR0KRO\nMBDOFXG4Y5CVJCX821LH\n4IFWWIKYB2PQ6U56NL1\nhttps://server.example.com/tx"
    );
    assert!(!base.ends_with('\n'), "no trailing newline");
    assert_eq!(base.matches('\n').count(), 3, "exactly three separators");
}

/// A newline inside a value would make the base ambiguous: reject it.
#[test]
fn a_newline_inside_a_value_is_rejected() {
    let input = InteractionHashInput {
        client_nonce: "abc\ndef",
        as_nonce: "MBDOFXG4Y5CVJCX821LH",
        interact_ref: "4IFWWIKYB2PQ6U56NL1",
        grant_endpoint: "https://server.example.com/tx",
    };
    let e = input.base().unwrap_err();
    assert!(matches!(e, HashError::NewlineInInput(_)));
    assert!(e.to_string().contains("interact.finish.nonce"), "{e}");
}

/// Every value really feeds the computation: changing one changes the hash.
#[test]
fn all_four_values_matter() {
    let base = interaction_hash(&demo(), HashMethod::Sha256).unwrap();
    let variants = [
        InteractionHashInput {
            client_nonce: "OTHER",
            ..demo()
        },
        InteractionHashInput {
            as_nonce: "OTHER",
            ..demo()
        },
        InteractionHashInput {
            interact_ref: "OTHER",
            ..demo()
        },
        InteractionHashInput {
            grant_endpoint: "https://other.example/tx",
            ..demo()
        },
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(
            interaction_hash(v, HashMethod::Sha256).unwrap(),
            base,
            "value #{} does not seem to feed the computation",
            i + 1
        );
    }
}

const fn demo() -> InteractionHashInput<'static> {
    InteractionHashInput {
        client_nonce: "VJLO6A4CATR0KRO",
        as_nonce: "MBDOFXG4Y5CVJCX821LH",
        interact_ref: "4IFWWIKYB2PQ6U56NL1",
        grant_endpoint: "https://server.example.com/tx",
    }
}

/// GNAP-9635-§4.2.3 hashes "the ASCII encoding" of the base.
///
/// A value outside ASCII has no ASCII encoding, so there is no hash the AS and
/// the client could both arrive at. Hashing its UTF-8 bytes instead would
/// invent one that only agrees by accident.
#[test]
fn a_non_ascii_value_has_no_hash() {
    use gnap_crypto::hash::{interaction_hash, HashError, HashMethod, InteractionHashInput};

    let input = InteractionHashInput {
        client_nonce: "VJLO6A4CATR0KRO",
        as_nonce: "nonce-é",
        interact_ref: "4IFWWIKYB2PQ6U56NL1",
        grant_endpoint: "https://server.example.com/tx",
    };
    assert_eq!(
        interaction_hash(&input, HashMethod::Sha256),
        Err(HashError::NotAscii("the AS nonce"))
    );
}
