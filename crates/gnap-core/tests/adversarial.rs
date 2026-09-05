//! What a broken or hostile peer would send, and what must be refused.
//!
//! These exercise the MUST NOT requirements that do not need a network: a
//! client checking an AS response, and an AS checking a client's calls.

use gnap_core::{check_response, Event, Grant, State};
use gnap_types::message::GrantResponse;

/// GNAP-9635-§5.1-MN07 — an AS handing out a token while the grant is pending.
/// GNAP-9635-§5.2-MN05 — the same, on the polling path.
/// GNAP-9635-§3.2-M01 — "The grant request MUST be in the approved state to
/// include this field in the response."
#[test]
fn an_as_that_issues_a_token_while_pending_is_caught() {
    let response: GrantResponse = serde_json::from_str(
        r#"{"access_token":{"value":"OS9M2PMHKUR64TB8"},
            "continue":{"uri":"https://as/c","access_token":{"value":"BBB"}}}"#,
    )
    .unwrap();

    let violations = check_response(State::Pending, &response);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].field, "access_token");
    assert!(
        violations[0].to_string().contains("§3.2"),
        "{}",
        violations[0]
    );

    // The same response is fine once the grant is approved.
    assert!(check_response(State::Approved, &response).is_empty());
}

/// GNAP-9635-§3.4-M17 — subject information released outside the approved state.
#[test]
fn subject_information_outside_approved_is_caught() {
    let response: GrantResponse = serde_json::from_str(
        r#"{"subject":{"sub_ids":[{"format":"opaque","id":"J2G8G8O4AZ"}]},
            "continue":{"uri":"https://as/c","access_token":{"value":"BBB"}}}"#,
    )
    .unwrap();

    let v = check_response(State::Pending, &response);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "subject");
}

/// GNAP-9635-§3.1-R14 — a pending response with no continuation strands the client.
#[test]
fn a_pending_response_without_continuation_is_caught() {
    let response: GrantResponse =
        serde_json::from_str(r#"{"interact":{"redirect":"https://as/i/4CF"}}"#).unwrap();

    let v = check_response(State::Pending, &response);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "continue");
    assert!(v[0].to_string().contains("§3.1"), "{}", v[0]);
}

/// GNAP-9635-§3.3-M11 — interaction offered from a state that forbids it.
///
/// A response carrying both tokens and interaction modes is contradictory:
/// §3.2 requires approved, §3.3 requires pending, and the two exclude each other.
#[test]
fn a_response_that_is_both_approved_and_pending_is_caught() {
    let response: GrantResponse = serde_json::from_str(
        r#"{"access_token":{"value":"AAA"},"interact":{"redirect":"https://as/i"}}"#,
    )
    .unwrap();

    // Whichever state the client believes it is in, one field is wrong.
    assert!(!check_response(State::Approved, &response).is_empty());
    assert!(!check_response(State::Pending, &response).is_empty());
}

/// GNAP-9635-§5.4-MN03 — a client that keeps calling after revoking.
#[test]
fn calls_after_revocation_are_refused() {
    let mut g = Grant::new();
    g.apply(Event::AsNeedsNoInteraction, 0).unwrap();
    g.offer_continuation(0, Some(0));
    g.apply(Event::Revoke, 10).unwrap();
    assert_eq!(g.state(), State::Finalized);

    for event in [Event::ContinuePoll, Event::Modify, Event::Revoke] {
        let e = g.apply(event.clone(), 100).unwrap_err();
        assert!(e.reason.contains("§5.4"), "{event}: {}", e.reason);
        assert_eq!(
            g.state(),
            State::Finalized,
            "{event} moved a finalized grant"
        );
    }
}

/// GNAP-9635-§5.1-M03 — replaying an interaction reference after approval.
///
/// The RFC pairs the error with invalidating the request, so a client that
/// replays loses the grant.
#[test]
fn replaying_an_interaction_reference_kills_the_grant() {
    let mut g = Grant::new();
    g.apply(Event::AsNeedsNoInteraction, 0).unwrap();
    g.offer_continuation(0, Some(0));

    let e = g
        .apply(Event::ContinueWithInteractRef("stolen".into()), 10)
        .unwrap_err();
    assert_eq!(e.code.as_str(), "too_many_attempts");
    assert!(e.finalizes);
    assert_eq!(
        g.state(),
        State::Finalized,
        "the grant should be invalidated"
    );
}

/// GNAP-9635-§5-M09 — a client that ignores the wait period.
#[test]
fn polling_faster_than_the_wait_period_is_refused() {
    let mut g = Grant::new();
    g.apply(Event::AsRequiresInteraction, 0).unwrap();
    g.offer_continuation(0, Some(30));

    for t in [0, 1, 29] {
        let e = g.apply(Event::ContinuePoll, t).unwrap_err();
        assert_eq!(e.code.as_str(), "too_fast", "at t={t}");
    }
    assert!(
        g.apply(Event::ContinuePoll, 30).is_ok(),
        "accepted once elapsed"
    );
}

/// GNAP-9635-§5-MN13 — a client that continues without being invited to.
#[test]
fn continuing_without_an_offer_is_refused() {
    let mut g = Grant::new();
    g.apply(Event::AsRequiresInteraction, 0).unwrap();
    g.withhold_continuation();

    let e = g.apply(Event::ContinuePoll, 100).unwrap_err();
    assert_eq!(e.code.as_str(), "invalid_continuation");
    assert!(e.reason.contains("§5"), "{}", e.reason);
}

/// GNAP-9635-§3.6-MN06 — with an error, "Other fields MUST NOT be included in
/// the response."
///
/// §3.6 allows exactly one companion, and only while the client can still act
/// on it: "If an error state is reached but the grant is in the pending state
/// (and therefore the client instance can continue), the AS MAY include the
/// continue field in the response along with the error."
#[test]
fn an_error_response_carrying_anything_else_is_caught() {
    let with_a_token: GrantResponse = serde_json::from_str(
        r#"{"error":"request_denied",
            "access_token":{"value":"OS9M2PMHKUR64TB8","access":["read"]}}"#,
    )
    .unwrap();
    let violations = check_response(State::Pending, &with_a_token);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].field, "access_token");

    // Extension fields are "other fields" too.
    let with_an_extension: GrantResponse =
        serde_json::from_str(r#"{"error":"request_denied","x-hint":"try later"}"#).unwrap();
    let violations = check_response(State::Pending, &with_an_extension);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].field, "extension fields");

    // The one companion §3.6 allows, in the one state it allows it.
    let recoverable: GrantResponse = serde_json::from_str(
        r#"{"error":"too_fast","continue":{"uri":"https://as/c",
            "access_token":{"value":"BBB"}}}"#,
    )
    .unwrap();
    assert!(check_response(State::Pending, &recoverable).is_empty());
    assert!(
        !check_response(State::Finalized, &recoverable).is_empty(),
        "a finalized grant cannot be continued (§5.4)"
    );
}
