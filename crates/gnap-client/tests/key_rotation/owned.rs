//! Ownership changes do not change the protocol path or keep retired keys alive.

use super::*;
use std::sync::Arc;

#[test]
fn an_owned_key_outlives_its_local_handle_and_follows_value_rotation() {
    let sk = signer();
    let as_ = FakeAs::with(vec![&managed(false)]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let (weak, key, verifier) = {
        let new = Arc::new(replacement());
        let key = presented(&new);
        let verifier = new.verifier();
        as_.push(
            200,
            vec![],
            &rebound(REBOUND, Some(serde_json::to_value(&key).unwrap()), "owned"),
        );
        s.rotate_key_owned(None, new.clone(), &key, 1_010).unwrap();
        (Arc::downgrade(&new), key, verifier)
    };
    assert_eq!(weak.strong_count(), 1);
    let token = s.usable_tokens(1_020).unwrap()[0];
    let resource = gnap_client::sign_request(
        HttpRequest::new("GET", "https://rs.example/files/notes"),
        s.signer_for(None).unwrap(),
        Some(&token.value),
        1_020,
    )
    .unwrap();
    assert!(signed_by(&resource, &verifier, "rotated-1", 1_020));

    as_.push(
        200,
        vec![],
        &rebound(
            "owned-refreshed",
            Some(serde_json::to_value(&key).unwrap()),
            "refresh",
        ),
    );
    s.rotate_token(None, 1_030).unwrap();
    assert!(signed_by(&as_.last(), &verifier, "rotated-1", 1_030));
    assert_eq!(weak.strong_count(), 1);
    as_.push(204, vec![], "");
    s.revoke_token(None, 1_040).unwrap();
    assert!(signed_by(&as_.last(), &verifier, "rotated-1", 1_040));
    assert!(weak.upgrade().is_none());
}

#[test]
fn replacing_a_key_or_lot_closing_a_grant_and_dropping_a_session_release_owned_handles() {
    for action in ["key", "borrowed", "lot", "grant", "drop"] {
        let sk = signer();
        let as_ = FakeAs::with(vec![&managed(true)]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let new = Arc::new(replacement());
        let weak = Arc::downgrade(&new);
        let key = presented(&new);
        as_.push(
            200,
            vec![],
            &rebound(REBOUND, Some(serde_json::to_value(&key).unwrap()), "owned"),
        );
        s.rotate_key_owned(None, new, &key, 1_010).unwrap();
        assert_eq!(weak.strong_count(), 1);
        match action {
            "key" => {
                let next = Arc::new(replacement());
                let key = presented(&next);
                as_.push(
                    200,
                    vec![],
                    &rebound(
                        "next-owned",
                        Some(serde_json::to_value(&key).unwrap()),
                        "next",
                    ),
                );
                s.rotate_key_owned(None, next, &key, 1_020).unwrap();
            }
            "borrowed" => {
                let key = presented(&sk);
                as_.push(
                    200,
                    vec![],
                    &rebound(
                        "back-to-borrowed",
                        Some(serde_json::to_value(&key).unwrap()),
                        "borrowed",
                    ),
                );
                s.rotate_key(None, &sk, &key, 1_020).unwrap();
                assert_eq!(s.signer_for(None).unwrap().key_id(), sk.key_id());
            }
            "lot" => {
                // Reusing the value must not carry the previous owned binding.
                as_.push(200, vec![], &rebound(REBOUND, None, "new-lot"));
                let change = ContinueRequest {
                    access_token: request().access_token,
                    ..Default::default()
                };
                assert!(matches!(
                    s.modify_grant(&change, 1_020).unwrap(),
                    Step::Approved(_)
                ));
                assert_eq!(s.signer_for(None).unwrap().key_id(), sk.key_id());
            }
            "grant" => {
                as_.push(204, vec![], "");
                s.revoke_grant(1_020).unwrap();
            }
            "drop" => drop(s),
            _ => unreachable!(),
        }
        assert!(weak.upgrade().is_none(), "retained after {action}");
    }
}

#[test]
fn a_refused_or_inconclusive_rotation_does_not_retain_the_proposed_owner() {
    for body in [
        r#"{"error":{"code":"key_rotation_not_supported"}}"#.to_owned(),
        rebound(REBOUND, None, "missing-binding"),
    ] {
        let sk = signer();
        let as_ = FakeAs::with(vec![&managed(false), &body]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let new = Arc::new(replacement());
        let weak = Arc::downgrade(&new);
        let key = presented(&new);
        // The caller keeps its own handle in case the remote outcome is unknown.
        assert!(s.rotate_key_owned(None, new.clone(), &key, 1_010).is_err());
        assert_eq!(Arc::strong_count(&new), 1);
        assert_eq!(s.signer_for(None).unwrap().key_id(), sk.key_id());
        assert_eq!(s.usable_tokens(1_010).unwrap()[0].value.as_str(), ISSUED);
        drop(new);
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn a_failed_second_rotation_preserves_the_current_owned_signer() {
    for failure in ["server", "malformed", "transport"] {
        let sk = signer();
        let as_ = FakeAs::with(vec![&managed(true)]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let current = Arc::new(replacement());
        let current_weak = Arc::downgrade(&current);
        let verifier = current.verifier();
        let key = presented(&current);
        as_.push(
            200,
            vec![],
            &rebound(REBOUND, Some(serde_json::to_value(&key).unwrap()), "first"),
        );
        s.rotate_key_owned(None, current, &key, 1_010).unwrap();
        let before = serde_json::to_value(s.usable_tokens(1_010).unwrap()).unwrap();
        let continuation = s.continuation().cloned();
        match failure {
            "server" => as_.push(400, vec![], r#"{"error":{"code":"invalid_rotation"}}"#),
            "malformed" => as_.push(200, vec![], "not JSON"),
            // No queued answer: FakeAs returns a transport error.
            "transport" => {}
            _ => unreachable!(),
        }
        let next = Arc::new(replacement());
        let next_weak = Arc::downgrade(&next);
        let next_key = presented(&next);
        let error = s
            .rotate_key_owned(None, next, &next_key, 1_020)
            .unwrap_err();
        assert!(
            match failure {
                "server" => matches!(error, ClientError::Server(_)),
                "malformed" => matches!(error, ClientError::Parse(_)),
                "transport" => matches!(error, ClientError::Transport(_)),
                _ => false,
            },
            "wrong failure for {failure}: {error}"
        );
        assert_eq!(as_.sent(), 3);
        assert!(next_weak.upgrade().is_none());
        assert_eq!(current_weak.strong_count(), 1);
        assert_eq!(
            serde_json::to_value(s.usable_tokens(1_020).unwrap()).unwrap(),
            before
        );
        assert_eq!(s.continuation(), continuation.as_ref());
        let token = s.usable_tokens(1_020).unwrap()[0];
        let request = gnap_client::sign_request(
            HttpRequest::new("GET", "https://rs.example/files/notes"),
            s.signer_for(None).unwrap(),
            Some(&token.value),
            1_020,
        )
        .unwrap();
        assert!(signed_by(&request, &verifier, "rotated-1", 1_020));
    }
}
