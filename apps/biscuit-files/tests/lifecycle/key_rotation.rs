//! Native token binding and the authoritative replay scope after a key change.

use super::*;
use gnap_crypto::Signer;
use gnap_types::{
    key::Key,
    token::{AccessToken, TokenValue},
};

fn key(signer: &Ps256Signer) -> Key {
    serde_json::from_value(serde_json::json!({
        "proof": "httpsig", "jwk": signer.public_jwk().unwrap()
    }))
    .unwrap()
}
fn native_id(f: &Fixture, token: &AccessToken) -> Vec<u8> {
    VerifiedToken::from_token(&token.value, &f.rs.roots)
        .unwrap()
        .revocation_identifiers()[0]
        .clone()
}
fn signed(value: &TokenValue, signer: &dyn Signer, now: u64) -> HttpRequest {
    sign_request(
        HttpRequest::new("GET", "https://rs.example/files/notes"),
        signer,
        Some(value),
        now,
    )
    .unwrap()
}
fn resource_status(f: &Fixture, value: &TokenValue, signer: &dyn Signer) -> (u16, bool) {
    let mut consulted = false;
    let response = f.rs.handle_with_clock(
        &signed(value, signer, f.now),
        &mut || Some(f.now),
        &mut |ids, accepted| {
            consulted = true;
            lookup(f, ids, accepted, f.now)
        },
    );
    (response.status, consulted)
}

#[test]
fn native_key_rotation_retires_old_authorities_and_preserves_approved_rights() {
    let replacement = Arc::new(Ps256Signer::generate(2048, "native-replacement").unwrap());
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let issued = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap();
    let original = issued.response().access_token.as_ref().unwrap().tokens[0].clone();
    let old_child = VerifiedToken::from_token(&original.value, &f.rs.roots)
        .unwrap()
        .attenuate(Some("https://rs.example/files/notes"), Some(f.now + 120))
        .unwrap();
    let mut sibling_session = Session::new(&direct, client(), "https://as.example/gnap");
    let sibling = sibling_session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap()
        .response()
        .access_token
        .as_ref()
        .unwrap()
        .tokens[0]
        .clone();

    let binding = key(&replacement);
    let rotated = session
        .rotate_key_owned(None, replacement.clone(), &binding, f.now)
        .unwrap();
    assert_ne!(native_id(&f, &original), native_id(&f, &rotated));
    assert_eq!(rotated.key, Some(binding));
    assert_eq!(rotated.access, original.access);
    assert_eq!(rotated.flags, original.flags);
    assert_eq!(rotated.label, original.label);
    assert_eq!(rotated.expires_in, original.expires_in);
    // Wrong-key refusal precedes the live channel. An old token presented with
    // its correct old key reaches that channel and is refused as retired.
    assert_eq!(resource_status(&f, &rotated.value, client()), (403, false));
    assert_eq!(
        resource_status(&f, &rotated.value, session.signer_for(None).unwrap()),
        (200, true)
    );
    assert_eq!(resource_status(&f, &original.value, client()), (403, true));
    assert_eq!(resource_status(&f, &old_child, client()), (403, true));
    assert_eq!(resource_status(&f, &sibling.value, client()), (200, true));

    let child = VerifiedToken::from_token(&rotated.value, &f.rs.roots)
        .unwrap()
        .attenuate(Some("https://rs.example/files/notes"), Some(f.now + 120))
        .unwrap();
    assert_eq!(
        resource_status(&f, &child, replacement.as_ref()),
        (200, true)
    );
    let refreshed = session.rotate_token(None, f.now).unwrap();
    assert_eq!(refreshed.key, rotated.key);
    assert_eq!(
        resource_status(&f, &refreshed.value, replacement.as_ref()),
        (200, true)
    );
    assert_eq!(
        resource_status(&f, &child, replacement.as_ref()),
        (403, true)
    );
    session.revoke_token(None, f.now).unwrap();
    assert_eq!(
        resource_status(&f, &refreshed.value, replacement.as_ref()),
        (403, true)
    );
    assert_eq!(resource_status(&f, &sibling.value, client()), (200, true));
}

#[test]
fn cycling_keys_preserves_each_public_keys_authoritative_nonce_history() {
    // Same kid, different RSA material: replay scopes must not use identifiers.
    let replacement = Arc::new(Ps256Signer::generate(2048, client().key_id()).unwrap());
    let f = fixture();
    let direct = Direct(&f.engine, Cell::new(f.now));
    let mut session = Session::new(&direct, client(), "https://as.example/gnap");
    let original = session
        .start(&grant(client(), "https://rs.example").unwrap(), f.now)
        .unwrap()
        .response()
        .access_token
        .as_ref()
        .unwrap()
        .tokens[0]
        .clone();
    let reserve = |token: &AccessToken| {
        f.store
            .reserve_resource(&native_id(&f, token), "same-nonce", f.now, || Some(f.now))
    };
    // Test the authoritative AS scope directly: an RS's separate global local
    // nonce filter must not mask an incorrect current-key choice here.
    assert_eq!(reserve(&original), LiveDecision::Allowed);
    let rotated = session
        .rotate_key_owned(None, replacement.clone(), &key(&replacement), f.now)
        .unwrap();
    assert_eq!(reserve(&rotated), LiveDecision::Allowed);
    assert_eq!(reserve(&rotated), LiveDecision::Denied);
    let returned = session
        .rotate_key(None, client(), &key(client()), f.now)
        .unwrap();
    assert_eq!(reserve(&returned), LiveDecision::Denied);
    assert_eq!(
        f.store.reserve_resource(
            &native_id(&f, &returned),
            "fresh-after-cycle",
            f.now,
            || Some(f.now)
        ),
        LiveDecision::Allowed
    );
    assert_eq!(resource_status(&f, &returned.value, client()), (200, true));
}
