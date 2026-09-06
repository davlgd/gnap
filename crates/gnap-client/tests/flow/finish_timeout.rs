//! Local finish policy is independent of optional AS lifetimes and polling.
use super::*;
use std::num::NonZeroU64;

#[test]
fn local_maximum_bounds_every_callback_and_never_extends_the_as_lifetime() {
    let callback = valid_callback();
    let redirect = format!(
        "https://client.example.net/cb?hash={}&interact_ref={}",
        callback.hash, callback.interact_ref
    );
    let pushed = serde_json::to_vec(&callback).unwrap();
    for duration in [None, Some(0), Some(10), Some(20), Some(30), Some(u64::MAX)] {
        let pending = duration.map_or_else(|| PENDING.to_owned(), pending_with_lifetime);
        let end = 1_000 + duration.unwrap_or(20).min(20);
        for mode in ["parsed", "redirect", "push"] {
            for now in [999, 1_000, 1_009, 1_010, 1_019, 1_020, 1_030] {
                let sk = signer();
                let as_ = FakeAs::with(vec![&pending, APPROVED]);
                let mut session = Session::new(&as_, &sk, ENDPOINT)
                    .with_finish_timeout(NonZeroU64::new(20).unwrap());
                session.start(&request(), 1_000).unwrap();
                let result = match mode {
                    "redirect" => session.accept_redirect(&redirect, now),
                    "push" => session.accept_push(&pushed, now),
                    _ => session.accept_callback(&callback, now),
                };
                assert_eq!(
                    result.is_ok(),
                    (1_000..end).contains(&now),
                    "{duration:?} {mode} {now}"
                );
                if let Err(error) = result {
                    let reason = if now < 1_000 {
                        "clock precedes"
                    } else if duration.is_some_and(|seconds| seconds <= 20) {
                        "AS-advertised"
                    } else {
                        "client-configured"
                    };
                    assert!(error.to_string().contains(reason), "{error}");
                    assert_eq!(
                        error.as_callback_error().unwrap().code,
                        ErrorCode::UnknownInteraction
                    );
                    assert_eq!(session.state(), State::Pending);
                    assert!(session.continue_grant(1_040).is_err());
                    assert_eq!(as_.seen.borrow().len(), 1);
                } else {
                    // Once accepted, the reference can be sent after the window.
                    session.continue_grant(1_040).unwrap();
                }
            }
        }
    }
}

#[test]
fn changing_policy_cannot_restart_or_extend_the_current_window() {
    let sk = signer();
    for (initial, updated, cutoff) in [
        (None, 20, 1_020),
        (Some(10), 30, 1_010),
        (Some(30), 10, 1_010),
    ] {
        let as_ = FakeAs::with(vec![PENDING]);
        let mut session = Session::new(&as_, &sk, ENDPOINT);
        if let Some(seconds) = initial {
            session = session.with_finish_timeout(NonZeroU64::new(seconds).unwrap());
        }
        session.start(&request(), 1_000).unwrap();
        session = session.with_finish_timeout(NonZeroU64::new(updated).unwrap());
        assert!(session.accept_callback(&valid_callback(), cutoff).is_err());
        // Repeating a longer setting cannot revive the expired window either.
        session = session.with_finish_timeout(NonZeroU64::new(u64::MAX).unwrap());
        assert!(session.accept_callback(&valid_callback(), cutoff).is_err());
        assert_eq!(as_.seen.borrow().len(), 1);
    }

    // Nor can a later setting extend a deadline originally supplied by the AS.
    let pending = pending_with_lifetime(5);
    let as_ = FakeAs::with(vec![&pending]);
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    session = session.with_finish_timeout(NonZeroU64::new(30).unwrap());
    let error = session
        .accept_callback(&valid_callback(), 1_005)
        .unwrap_err();
    assert!(error.to_string().contains("AS-advertised"));
}

#[test]
fn positive_and_wide_client_limits_have_exact_boundaries() {
    let sk = signer();
    for (start, limit, now, allowed) in [
        (1_000, 1, 1_000, true),
        (1_000, 1, 1_001, false),
        (1_000, u64::MAX, u64::MAX, true),
        (0, u64::MAX, u64::MAX, false),
        (u64::MAX, 1, u64::MAX, true),
        (u64::MAX, 1, u64::MAX - 1, false),
    ] {
        let as_ = FakeAs::with(vec![PENDING]);
        let mut session =
            Session::new(&as_, &sk, ENDPOINT).with_finish_timeout(NonZeroU64::new(limit).unwrap());
        session.start(&request(), start).unwrap();
        assert_eq!(
            session.accept_callback(&valid_callback(), now).is_ok(),
            allowed
        );
        assert!(session.continuation().is_some());
    }
}

#[test]
fn new_windows_use_the_latest_policy_but_absent_or_invalid_responses_do_not_renew_it() {
    let sk = signer();
    let no_interaction = r#"{"continue":{"uri":"https://as.example/continue","access_token":{"value":"replacement"},"wait":0}}"#;
    for (response, expected_error, may_finish) in [
        (no_interaction, false, false),
        (PENDING, false, true),
        ("{", true, false),
    ] {
        let as_ = FakeAs::with(vec![PENDING, response]);
        let mut session =
            Session::new(&as_, &sk, ENDPOINT).with_finish_timeout(NonZeroU64::new(10).unwrap());
        session.start(&request(), 1_000).unwrap();
        session = session.with_finish_timeout(NonZeroU64::new(30).unwrap());
        assert_eq!(
            session
                .modify_grant(&ContinueRequest::default(), 1_005)
                .is_err(),
            expected_error
        );
        assert_eq!(
            session.accept_callback(&valid_callback(), 1_034).is_ok(),
            may_finish
        );
        assert!(session.accept_callback(&valid_callback(), 1_035).is_err());
    }
}

#[test]
fn a_finish_limit_does_not_cancel_polling_or_an_already_validated_reference() {
    let sk = signer();
    let as_ = FakeAs::with(vec![POLLING, APPROVED]);
    let mut session =
        Session::new(&as_, &sk, ENDPOINT).with_finish_timeout(NonZeroU64::new(1).unwrap());
    session.start(&request(), 1_000).unwrap();
    assert!(matches!(
        session.continue_grant(1_100).unwrap(),
        Step::Approved(_)
    ));

    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut session =
        Session::new(&as_, &sk, ENDPOINT).with_finish_timeout(NonZeroU64::new(20).unwrap());
    session.start(&request(), 1_000).unwrap();
    session.accept_callback(&valid_callback(), 1_005).unwrap();
    session = session.with_finish_timeout(NonZeroU64::new(1).unwrap());
    assert!(session.accept_callback(&valid_callback(), 1_006).is_err());
    session.continue_grant(1_030).unwrap();
    let seen = as_.seen.borrow();
    let body: serde_json::Value = serde_json::from_slice(seen[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["interact_ref"], valid_callback().interact_ref);
}
