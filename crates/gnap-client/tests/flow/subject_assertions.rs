//! Cryptographic identity checks use the session's context, not JWT-supplied trust.
use super::*;
use gnap_subject::{issue, AssertionError, Issuance, Trust};
use serde_json::json;

const ISSUER: &str = "https://identity.example";

fn assertion_key() -> Ps256Signer {
    // Public test fixture only; deployed consumers use a dedicated generated key.
    Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "assertion-fixture").unwrap()
}

fn response(nonce: &str, audience: &str) -> String {
    let assertion = issue(
        &assertion_key(),
        &Issuance {
            issuer: ISSUER,
            subject: "fictional-ro",
            audience,
            nonce,
            authenticated_at: 1000,
            issued_at: 1100,
            expires_at: 1400,
        },
    )
    .unwrap();
    json!({"subject": {
        "sub_ids":[{"format":"iss_sub","iss":ISSUER,"sub":"fictional-ro"}],
        "assertions":[assertion]
    }})
    .to_string()
}

fn subject_request() -> GrantRequest {
    let mut grant = request();
    grant.subject =
        Some(serde_json::from_value(json!({"assertion_formats":["id_token"]})).unwrap());
    grant
}

const fn trust(key: &gnap_crypto::Ps256Verifier) -> Trust<'_> {
    Trust {
        as_endpoint: ENDPOINT,
        issuer: ISSUER,
        key,
        max_age: 300,
        clock_skew: 0,
    }
}

#[test]
fn identity_requires_own_nonce_key_and_exact_as_attribution() {
    let sk = signer();
    let key = assertion_key().verifier();
    for (nonce, audience, expected_error) in [
        (CLIENT_NONCE, sk.thumbprint(), None),
        (
            "other-session",
            sk.thumbprint(),
            Some(AssertionError::Nonce),
        ),
        (
            CLIENT_NONCE,
            "other-client-key".into(),
            Some(AssertionError::Recipient),
        ),
    ] {
        let body = response(nonce, &audience);
        let transport = FakeAs::with(vec![PENDING, &body]);
        let mut session = Session::new(&transport, &sk, ENDPOINT);
        let pinned = trust(&key);
        assert!(session.verify_subject(&pinned, 1000).is_err());
        session.start(&subject_request(), 1000).unwrap();
        assert!(session.verify_subject(&pinned, 1000).is_err());
        session.accept_callback(&valid_callback(), 1005).unwrap();
        session.continue_grant(1100).unwrap();
        // Parsing a subject response is deliberately not signature verification.
        assert!(session.subject().is_some());
        if let Some(error) = expected_error {
            assert_eq!(session.verify_subject(&pinned, 1100).err(), Some(error));
        } else {
            let verified = session.verify_subject(&pinned, 1100).unwrap();
            assert_eq!(verified.as_endpoint, ENDPOINT);
            assert_eq!(verified.identity.subject(), "fictional-ro");
            assert_eq!(verified.identity.issuer(), ISSUER);
            assert_eq!(
                session
                    .verify_subject(
                        &Trust {
                            as_endpoint: "https://other.example/gnap",
                            ..pinned
                        },
                        1100
                    )
                    .err(),
                Some(AssertionError::Context)
            );
            assert_eq!(
                session.verify_subject(&trust(&key), 1400).err(),
                Some(AssertionError::Time)
            );
        }
    }
}

#[test]
fn no_finish_session_cannot_adopt_a_borrowed_nonce() {
    let sk = signer();
    let body = response(CLIENT_NONCE, &sk.thumbprint());
    let transport = FakeAs::with(vec![&body]);
    let mut session = Session::new(&transport, &sk, ENDPOINT);
    let mut grant = subject_request();
    grant.interact = None;
    session.start(&grant, 1100).unwrap();
    assert!(session.subject().is_some());
    assert_eq!(
        session
            .verify_subject(&trust(&assertion_key().verifier()), 1100)
            .err(),
        Some(AssertionError::Context)
    );
}

#[test]
fn exchanging_two_sessions_subject_responses_does_not_exchange_identities() {
    let sk = signer();
    let key = assertion_key().verifier();
    let body_a = response("nonce-a", &sk.thumbprint());
    let body_b = response("nonce-b", &sk.thumbprint());
    let transport_a = FakeAs::with(vec![PENDING, &body_b]);
    let transport_b = FakeAs::with(vec![PENDING, &body_a]);
    for (transport, nonce) in [(&transport_a, "nonce-a"), (&transport_b, "nonce-b")] {
        let mut session = Session::new(transport, &sk, ENDPOINT);
        let mut grant = subject_request();
        grant
            .interact
            .as_mut()
            .unwrap()
            .finish
            .as_mut()
            .unwrap()
            .nonce = nonce.into();
        session.start(&grant, 1000).unwrap();
        let callback = InteractCallback {
            hash: interaction_hash(
                &InteractionHashInput {
                    client_nonce: nonce,
                    as_nonce: AS_NONCE,
                    interact_ref: "4IFWWIKYBC2PQ6U56NL1",
                    grant_endpoint: ENDPOINT,
                },
                HashMethod::Sha256,
            )
            .unwrap(),
            interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
        };
        session.accept_callback(&callback, 1005).unwrap();
        session.continue_grant(1100).unwrap();
        assert_eq!(
            session.verify_subject(&trust(&key), 1100).err(),
            Some(AssertionError::Nonce)
        );
    }
}
