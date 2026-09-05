//! Bounded exploration of the state machine.
//!
//! Enumerates event sequences up to four or five steps, with representative
//! interaction references and timestamps. These checks exercise the invariants
//! described in `vectors/state-machine.json`; they do not prove them for all
//! possible histories or inputs.

use gnap_core::{Event, Grant, State};
use std::collections::{HashSet, VecDeque};

/// Every event, including the ones that are refused from most states.
fn all_events() -> Vec<Event> {
    vec![
        Event::AsRequiresInteraction,
        Event::AsNeedsNoInteraction,
        Event::AsCannotProceed,
        Event::ContinuePoll,
        Event::ContinueWithInteractRef("r1".into()),
        Event::ContinueWithInteractRef("r2".into()),
        Event::OutOfBandRoDecision,
        Event::Modify,
        Event::Revoke,
        Event::InteractionStartCompleted("redirect".into()),
        Event::InteractionStartCompleted("user_code".into()),
    ]
}

/// A walk through the machine, kept so a failure can be replayed.
#[derive(Clone)]
struct Walk {
    grant: Grant,
    path: Vec<String>,
}

/// Explores every reachable configuration up to the given depth, offering a
/// continuation at each step so the continuation guards do not mask the
/// transitions underneath.
fn explore(depth: usize, mut visit: impl FnMut(&Grant, &[String])) {
    let mut queue = VecDeque::from([Walk {
        grant: Grant::new(),
        path: Vec::new(),
    }]);
    let mut seen: HashSet<String> = HashSet::new();

    while let Some(walk) = queue.pop_front() {
        visit(&walk.grant, &walk.path);
        if walk.path.len() >= depth {
            continue;
        }
        for event in all_events() {
            let mut next = walk.clone();
            next.grant.offer_continuation(0, Some(0));
            let label = format!("{event}");
            if next.grant.apply(event, 1_000).is_err() {
                // A refused transition still counts as a configuration to
                // check: a guard that finalizes changes the state.
                next.path.push(format!("!{label}"));
            } else {
                next.path.push(label);
            }
            let key = format!("{}|{}", next.grant.state(), next.path.len());
            if seen.insert(format!("{key}|{}", next.path.join(","))) {
                queue.push_back(next);
            }
        }
    }
}

/// I01 — `finalized` is absorbing: no event leaves it.
#[test]
fn i01_finalized_is_absorbing() {
    let mut checked = 0;
    explore(4, |grant, path| {
        if grant.state() != State::Finalized {
            return;
        }
        for event in all_events() {
            let mut g = grant.clone();
            g.offer_continuation(0, Some(0));
            let before = g.state();
            let _ = g.apply(event.clone(), 2_000);
            assert_eq!(
                g.state(),
                before,
                "I01 violated: `{event}` moved a finalized grant\n  path: {}",
                path.join(" -> ")
            );
            checked += 1;
        }
    });
    assert!(checked > 0, "no finalized configuration was reached");
    println!("  I01: {checked} attempts to leave finalized, all refused");
}

/// I02 — no access token and no subject information is released while pending.
#[test]
fn i02_nothing_is_released_while_pending() {
    let mut checked = 0;
    explore(5, |grant, path| {
        if grant.state() != State::Pending {
            return;
        }
        let a = grant.allowed();
        assert!(
            !a.access_token && !a.subject,
            "I02 violated: pending allows a token or subject information\n  path: {}",
            path.join(" -> ")
        );
        assert!(
            a.continuation,
            "a pending grant always offers a continuation (§3.1)"
        );
        checked += 1;
    });
    assert!(checked > 0, "no pending configuration was reached");
    println!("  I02: {checked} pending configurations, none release anything");
}

/// I03 — an interaction reference is consumed at most once.
#[test]
fn i03_an_interaction_reference_is_spent_once() {
    let mut g = Grant::new();
    g.apply(Event::AsRequiresInteraction, 0).unwrap();
    g.offer_continuation(0, Some(0));

    // First use is accepted and sends the grant back for re-evaluation.
    assert_eq!(
        g.apply(Event::ContinueWithInteractRef("r".into()), 10)
            .unwrap(),
        State::Processing
    );

    // Back to pending, the same reference is refused.
    g.apply(Event::AsRequiresInteraction, 10).unwrap();
    g.offer_continuation(10, Some(0));
    let e = g
        .apply(Event::ContinueWithInteractRef("r".into()), 20)
        .unwrap_err();
    assert!(e.reason.contains("one-time-use"), "{}", e.reason);

    // A different reference still works.
    assert_eq!(
        g.apply(Event::ContinueWithInteractRef("r2".into()), 20)
            .unwrap(),
        State::Processing
    );
}

/// I04 — nothing is ever emitted from the processing state.
#[test]
fn i04_processing_emits_nothing() {
    let mut checked = 0;
    explore(5, |grant, path| {
        if grant.state() != State::Processing {
            return;
        }
        let a = grant.allowed();
        assert!(
            !a.access_token && !a.subject && !a.interact && !a.continuation,
            "I04 violated: processing allows a response field\n  path: {}",
            path.join(" -> ")
        );
        checked += 1;
    });
    println!("  I04: {checked} processing configurations, none emit anything");
}

/// I05 — every state is reachable, and finalized is reachable from each.
#[test]
fn i05_every_state_is_reachable() {
    let mut reached = HashSet::new();
    explore(4, |grant, _| {
        reached.insert(grant.state());
    });
    for state in State::ALL {
        assert!(
            reached.contains(&state),
            "I05 violated: {state} is unreachable"
        );
    }

    for start in [State::Processing, State::Pending, State::Approved] {
        let mut g = Grant::new();
        match start {
            State::Pending => {
                g.apply(Event::AsRequiresInteraction, 0).unwrap();
            }
            State::Approved => {
                g.apply(Event::AsNeedsNoInteraction, 0).unwrap();
            }
            _ => {}
        }
        g.offer_continuation(0, Some(0));
        let event = if start == State::Processing {
            Event::AsCannotProceed
        } else {
            Event::Revoke
        };
        g.apply(event, 10).unwrap();
        assert_eq!(
            g.state(),
            State::Finalized,
            "finalized unreachable from {start}"
        );
    }
    println!("  I05: all 4 states reachable, finalized reachable from each");
}
