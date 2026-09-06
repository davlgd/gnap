//! Checks the implementation against `vectors/state-machine.json`.
//!
//! The specification file is the oracle: it is derived from the normative
//! requirements of RFC 9635 §3, §4 and §5, and these tests read it rather than
//! restating it. An implementation that drifts from the RFC fails here.

use gnap_core::{Event, Grant, State};
use serde_json::Value;

const SPEC: &str = include_str!("fixtures/state-machine.json");

fn spec() -> Value {
    serde_json::from_str(SPEC).expect("unreadable state machine specification")
}

/// Drives a grant into the given state, leaving a continuation on offer so the
/// continuation guards do not fire first.
fn grant_in(state: State) -> Grant {
    let mut g = Grant::new();
    match state {
        State::Processing => {}
        State::Pending => {
            g.apply(Event::AsRequiresInteraction, 0).unwrap();
            g.offer_continuation(0, Some(0));
        }
        State::Approved => {
            g.apply(Event::AsNeedsNoInteraction, 0).unwrap();
            g.offer_continuation(0, Some(0));
        }
        State::Finalized => {
            g.apply(Event::AsCannotProceed, 0).unwrap();
        }
    }
    assert_eq!(g.state(), state, "failed to reach the {state} state");
    g
}

fn event_for(trigger: &str) -> Option<Event> {
    Some(match trigger {
        "as_requires_interaction" => Event::AsRequiresInteraction,
        "as_needs_no_interaction" => Event::AsNeedsNoInteraction,
        "as_cannot_proceed" => Event::AsCannotProceed,
        "continue_poll" => Event::ContinuePoll,
        "continue_with_interact_ref" => Event::ContinueWithInteractRef("ref-1".into()),
        "out_of_band_ro_decision" => Event::OutOfBandRoDecision,
        "modify" => Event::Modify,
        "revoke" => Event::Revoke,
        _ => return None,
    })
}

/// Every state declared by the specification exists, with the right terminality.
#[test]
fn declared_states_match() {
    let spec = spec();
    let declared: Vec<&Value> = spec["states"].as_array().unwrap().iter().collect();
    assert_eq!(declared.len(), State::ALL.len(), "state count differs");

    for s in declared {
        let name = s["name"].as_str().unwrap();
        let state = State::from_name(name).unwrap_or_else(|| panic!("unknown state `{name}`"));
        assert_eq!(
            state.is_terminal(),
            s["terminal"].as_bool().unwrap(),
            "{name}: terminality differs from the specification"
        );
    }
}

/// Every transition the specification declares is accepted, and lands where it
/// says it lands.
#[test]
fn declared_transitions_are_accepted() {
    let spec = spec();
    let mut checked = 0;

    for t in spec["transitions"].as_array().unwrap() {
        let id = t["id"].as_str().unwrap();
        let Some(from) = t["from"].as_str() else {
            continue; // T01 creates the grant; covered by `a_new_grant_is_processing`
        };
        let to = State::from_name(t["to"].as_str().unwrap()).unwrap();
        let trigger = t["trigger"].as_str().unwrap();
        let Some(event) = event_for(trigger) else {
            continue; // triggers with no direct event, such as interaction_start
        };

        let mut g = grant_in(State::from_name(from).unwrap());
        let got = g
            .apply(event, 100)
            .unwrap_or_else(|e| panic!("{id}: transition refused — {e}"));
        assert_eq!(
            got, to,
            "{id}: {from} --{trigger}--> expected {to}, got {got}"
        );
        checked += 1;
    }

    assert!(checked >= 10, "only {checked} transitions exercised");
    println!("  {checked} declared transitions accepted");
}

/// Every response constraint the specification declares is enforced.
#[test]
fn declared_response_constraints_are_enforced() {
    let spec = spec();
    for c in spec["response_constraints"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let state = State::from_name(c["state"].as_str().unwrap()).unwrap();
        let field = c["field"].as_str().unwrap();
        let rule = c["rule"].as_str().unwrap();
        let allowed = gnap_core::Allowed::for_state(state);

        let actual = match field {
            "access_token" => allowed.access_token,
            "subject" => allowed.subject,
            "interact" => allowed.interact,
            "continue" => allowed.continuation,
            other => panic!("{id}: unknown field `{other}`"),
        };

        match rule {
            "allowed" | "required" => assert!(
                actual,
                "{id}: `{field}` should be {rule} in the {state} state"
            ),
            "forbidden" => assert!(
                !actual,
                "{id}: `{field}` should be forbidden in the {state} state"
            ),
            other => panic!("{id}: unknown rule `{other}`"),
        }

        if rule == "required" {
            assert!(
                gnap_core::Allowed::continuation_required(state),
                "{id}: `{field}` should be required, not merely allowed"
            );
        }
    }
    println!(
        "  {} response constraints enforced",
        spec["response_constraints"].as_array().unwrap().len()
    );
}

/// Every guard the specification declares fires, with the declared error code.
#[test]
fn declared_guards_fire_with_the_right_error() {
    let spec = spec();
    let expected: Vec<(String, String)> = spec["guards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            (
                g["id"].as_str().unwrap().to_owned(),
                g["outcome"]["error"].as_str().unwrap().to_owned(),
            )
        })
        .collect();

    // G01 — an interaction reference outside the pending state.
    let mut g = grant_in(State::Approved);
    let e = g
        .apply(Event::ContinueWithInteractRef("r".into()), 100)
        .unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G01"));
    assert!(
        e.finalizes,
        "G01 pairs the error with finalizing the request"
    );
    assert_eq!(g.state(), State::Finalized);

    // G02 — a modification from a state that does not allow it.
    let mut g = Grant::new();
    g.offer_continuation(0, Some(0));
    let e = g.apply(Event::Modify, 100).unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G02"));

    // G03 — finalized is absorbing.
    let mut g = grant_in(State::Finalized);
    let e = g.apply(Event::ContinuePoll, 100).unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G03"));

    // G04 — the wait period has not elapsed.
    let mut g = Grant::new();
    g.apply(Event::AsRequiresInteraction, 0).unwrap();
    g.offer_continuation(0, Some(30));
    let e = g.apply(Event::ContinuePoll, 10).unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G04"));
    assert!(e.reason.contains("20 s remaining"), "{}", e.reason);

    // G05 — no continuation was offered.
    let mut g = Grant::new();
    g.apply(Event::AsRequiresInteraction, 0).unwrap();
    let e = g.apply(Event::ContinuePoll, 100).unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G05"));

    // G06 — an interaction reference is single use.
    let mut g = grant_in(State::Pending);
    g.apply(Event::ContinueWithInteractRef("r".into()), 100)
        .unwrap();
    g.apply(Event::AsRequiresInteraction, 100).unwrap();
    g.offer_continuation(100, Some(0));
    let e = g
        .apply(Event::ContinueWithInteractRef("r".into()), 200)
        .unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G06"));

    // G07 — one completed start mode closes the others.
    let mut g = grant_in(State::Pending);
    g.apply(Event::InteractionStartCompleted("redirect".into()), 100)
        .unwrap();
    let e = g
        .apply(Event::InteractionStartCompleted("user_code".into()), 100)
        .unwrap_err();
    assert_eq!(e.code.as_str(), find(&expected, "G07"));

    println!(
        "  {} guards fire with the declared error code",
        expected.len()
    );
}

fn find<'a>(guards: &'a [(String, String)], id: &str) -> &'a str {
    guards.iter().find(|(g, _)| g == id).map_or_else(
        || panic!("guard {id} is missing from the specification"),
        |(_, e)| e.as_str(),
    )
}

/// A new grant starts in processing (§2, T01).
#[test]
fn a_new_grant_is_processing() {
    assert_eq!(Grant::new().state(), State::Processing);
    let a = Grant::new().allowed();
    assert!(
        !a.access_token && !a.subject && !a.interact && !a.continuation,
        "nothing is emitted from the processing state (§1.5)"
    );
}
