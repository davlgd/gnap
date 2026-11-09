use super::*;
use gnap_crypto::Ed25519Signer;
use gnap_registry::KeyProofingMethod;
use gnap_types::key::Proof;
use std::time::Duration;

fn key(signer: &Ed25519Signer, method: KeyProofingMethod) -> KeyObject {
    KeyObject {
        proof: Proof::Named(method),
        jwk: Some(signer.public_jwk().unwrap()),
        cert: None,
        cert_s256: None,
    }
}

fn by_value(key: &KeyObject) -> Client {
    serde_json::from_value(serde_json::json!({"key": key})).unwrap()
}

fn by_reference(id: &str) -> Client {
    serde_json::from_value(serde_json::json!(id)).unwrap()
}

#[test]
fn a_reference_is_the_labs_until_its_deadline() {
    let now = Instant::now();
    let mut keys = LabKeys::new(4);
    keys.register_reference("session-a", now + Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        keys.classify(&by_reference("session-a"), None, now),
        ClientClass::Lab("session-a".into())
    );
    assert_eq!(
        keys.classify(
            &by_reference("session-a"),
            None,
            now + Duration::from_secs(10)
        ),
        ClientClass::Unknown
    );
    assert_eq!(
        keys.classify(&by_reference("session-b"), None, now),
        ClientClass::Unknown
    );
    assert_eq!(
        keys.register_reference("session-a", now),
        Err(RegistrationError::Collision)
    );
}

#[test]
fn a_presented_key_is_the_labs_only_when_it_matches_exactly() {
    let now = Instant::now();
    let signer = Ed25519Signer::generate("lab-key").unwrap();
    let jwsd = key(&signer, KeyProofingMethod::Jwsd);
    let thumbprint = key_thumbprint(&jwsd).unwrap();
    let mut keys = LabKeys::new(4);
    keys.register_key(
        "session-a",
        thumbprint.clone(),
        jwsd.clone(),
        now + Duration::from_secs(10),
    )
    .unwrap();

    let client = by_value(&jwsd);
    assert_eq!(
        presented_thumbprint(&client).as_deref(),
        Some(thumbprint.as_str())
    );
    assert_eq!(
        keys.classify(&client, Some(&thumbprint), now),
        ClientClass::Lab("session-a".into())
    );

    // The same key with another proof, or with anything beside the key, or
    // once the session ended: not the lab's, and not external either.
    let jws = by_value(&key(&signer, KeyProofingMethod::Jws));
    assert_eq!(
        keys.classify(&jws, Some(&thumbprint), now),
        ClientClass::Unknown
    );
    let displayed: Client =
        serde_json::from_value(serde_json::json!({"key": jwsd, "display": {"name": "x"}})).unwrap();
    assert_eq!(
        keys.classify(&displayed, Some(&thumbprint), now),
        ClientClass::Unknown
    );
    let extended: Client =
        serde_json::from_value(serde_json::json!({"key": jwsd, "x": 1})).unwrap();
    assert_eq!(
        keys.classify(&extended, Some(&thumbprint), now),
        ClientClass::Unknown
    );
    assert_eq!(
        keys.classify(&client, Some(&thumbprint), now + Duration::from_secs(10)),
        ClientClass::Unknown
    );

    // A key the lab doesn't hold is a candidate for the external path.
    let other = by_value(&key(
        &Ed25519Signer::generate("other").unwrap(),
        KeyProofingMethod::Jwsd,
    ));
    let other_thumbprint = presented_thumbprint(&other);
    assert_eq!(
        keys.classify(&other, other_thumbprint.as_deref(), now),
        ClientClass::External
    );
}

#[test]
fn a_held_key_is_never_overwritten_and_the_registry_is_bounded() {
    let now = Instant::now();
    let signer = Ed25519Signer::generate("lab-key").unwrap();
    let jwsd = key(&signer, KeyProofingMethod::Jwsd);
    let thumbprint = key_thumbprint(&jwsd).unwrap();
    let mut keys = LabKeys::new(2);
    keys.register_key(
        "session-a",
        thumbprint.clone(),
        jwsd.clone(),
        now + Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        keys.register_key(
            "session-b",
            thumbprint.clone(),
            jwsd.clone(),
            now + Duration::from_secs(10)
        ),
        Err(RegistrationError::Collision)
    );
    assert_eq!(
        keys.classify(&by_value(&jwsd), Some(&thumbprint), now),
        ClientClass::Lab("session-a".into())
    );
    keys.register_reference("session-c", now + Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        keys.register_reference("session-d", now),
        Err(RegistrationError::Full)
    );

    keys.forget("session-a");
    assert!(!keys.holds("session-a"));
    assert_eq!(
        keys.classify(&by_value(&jwsd), Some(&thumbprint), now),
        ClientClass::External
    );
    assert_eq!(keys.count(), 1);
}

/// The thumbprint covers the key's required members: the same key under
/// another `kid` or `alg` is the same key.
#[test]
fn the_thumbprint_names_the_key_not_its_labels() {
    let signer = Ed25519Signer::generate("one").unwrap();
    let mut relabelled = key(&signer, KeyProofingMethod::Jwsd);
    relabelled
        .jwk
        .as_mut()
        .unwrap()
        .insert("kid".into(), serde_json::json!("two"));
    assert_eq!(
        key_thumbprint(&relabelled),
        key_thumbprint(&key(&signer, KeyProofingMethod::Jwsd))
    );
}
