/// Compliance tests for RFC 9635 Section 4 — Interaction
use gnap_compliance::crypto::{HashMethod, compute_interaction_hash};

// ─── Section 4.2.3: Interaction Hash ─────────────────────────────────────────

#[test]
fn interaction_hash_sha256_basic() {
    // Verify the hash is computed as:
    // BASE64URL(SHA-256(client_nonce + "\n" + server_nonce + "\n" + interact_ref + "\n" + grant_endpoint))
    let hash = compute_interaction_hash(
        "LKLTI25DK82FX4T4QFZC",
        "MBDOFXG4Y5CVJCX821LH",
        "4IFWWIKYBC2PQ6U56NL1",
        "https://server.example.com/gnap",
        HashMethod::Sha256,
    );

    // Hash must be non-empty base64url
    assert!(!hash.is_empty());
    assert!(
        hash.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "hash must be base64url without padding"
    );
    // Must NOT have padding
    assert!(!hash.contains('='), "base64url must not have padding");
}

#[test]
fn interaction_hash_deterministic() {
    let args = (
        "client-nonce",
        "server-nonce",
        "interact-ref",
        "https://as.example.com/gnap",
    );

    let hash1 = compute_interaction_hash(args.0, args.1, args.2, args.3, HashMethod::Sha256);
    let hash2 = compute_interaction_hash(args.0, args.1, args.2, args.3, HashMethod::Sha256);
    assert_eq!(hash1, hash2);
}

#[test]
fn interaction_hash_changes_with_any_input() {
    let base = compute_interaction_hash(
        "cn",
        "sn",
        "ref",
        "https://as.example.com/gnap",
        HashMethod::Sha256,
    );

    // Changing client nonce
    let h1 = compute_interaction_hash(
        "cn2",
        "sn",
        "ref",
        "https://as.example.com/gnap",
        HashMethod::Sha256,
    );
    assert_ne!(base, h1, "must differ when client_nonce changes");

    // Changing server nonce
    let h2 = compute_interaction_hash(
        "cn",
        "sn2",
        "ref",
        "https://as.example.com/gnap",
        HashMethod::Sha256,
    );
    assert_ne!(base, h2, "must differ when server_nonce changes");

    // Changing interact_ref
    let h3 = compute_interaction_hash(
        "cn",
        "sn",
        "ref2",
        "https://as.example.com/gnap",
        HashMethod::Sha256,
    );
    assert_ne!(base, h3, "must differ when interact_ref changes");

    // Changing grant endpoint
    let h4 = compute_interaction_hash(
        "cn",
        "sn",
        "ref",
        "https://other.example.com/gnap",
        HashMethod::Sha256,
    );
    assert_ne!(base, h4, "must differ when grant_endpoint changes");
}

#[test]
fn interaction_hash_sha512_differs_from_sha256() {
    let h256 = compute_interaction_hash(
        "cn",
        "sn",
        "ref",
        "https://as.example.com/gnap",
        HashMethod::Sha256,
    );
    let h512 = compute_interaction_hash(
        "cn",
        "sn",
        "ref",
        "https://as.example.com/gnap",
        HashMethod::Sha512,
    );
    assert_ne!(h256, h512);
    // SHA-512 produces a longer output
    assert!(h512.len() > h256.len());
}

#[test]
fn interaction_hash_rfc_test_vector() {
    // Official RFC 9635 Section 4.2.3 test vector.
    // Hash base string (no trailing newline):
    //   VJLO6A4CATR0KRO\nMBDOFXG4Y5CVJCX821LH\n4IFWWIKYB2PQ6U56NL1\nhttps://server.example.com/tx
    // Expected SHA-256 result: x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY
    let hash = compute_interaction_hash(
        "VJLO6A4CATR0KRO",
        "MBDOFXG4Y5CVJCX821LH",
        "4IFWWIKYB2PQ6U56NL1",
        "https://server.example.com/tx",
        HashMethod::Sha256,
    );
    assert_eq!(hash, "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY");
}

#[test]
fn hash_method_parsing() {
    assert_eq!(
        HashMethod::from_str_rfc("sha-256"),
        Some(HashMethod::Sha256)
    );
    assert_eq!(
        HashMethod::from_str_rfc("sha-512"),
        Some(HashMethod::Sha512)
    );
    // Non-registry names must be rejected per RFC 9635 Section 4.2.3
    assert_eq!(HashMethod::from_str_rfc("sha256"), None);
    assert_eq!(HashMethod::from_str_rfc("sha512"), None);
    assert_eq!(HashMethod::from_str_rfc("unknown"), None);
}
