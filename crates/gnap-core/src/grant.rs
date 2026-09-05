//! The grant request itself, and the transitions it accepts.

use crate::event::Event;
use crate::state::State;
use gnap_registry::ErrorCode;
use std::collections::HashSet;
use std::fmt;

/// A transition was refused, with the GNAP error code the AS must return.
///
/// Every variant carries the requirement it enforces, so a diagnostic can point
/// at the RFC rather than at this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    /// The error code to put in the response (§3.6).
    pub code: ErrorCode,
    /// Why the transition was refused, citing the RFC.
    pub reason: String,
    /// Whether the grant is finalized as a consequence.
    pub finalizes: bool,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for TransitionError {}

/// What the AS may put in the response after a transition.
///
/// Derived from the state, not chosen by the caller: §3.2, §3.3 and §3.4 tie
/// each field to a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// One flag per response field the RFC ties to a state (§3.1, §3.2, §3.3, §3.4).
// Packing them into anything denser would hide that correspondence.
#[allow(clippy::struct_excessive_bools)]
pub struct Allowed {
    /// `access_token` may be present — requires the approved state (§3.2).
    pub access_token: bool,
    /// `subject` may be present — requires the approved state (§3.4).
    pub subject: bool,
    /// `interact` may be present — requires the pending state (§3.3).
    pub interact: bool,
    /// `continue` may be present, and is required while pending (§3.1).
    pub continuation: bool,
}

impl Allowed {
    /// A response carrying none of the fields tied to a state.
    pub const NOTHING: Self = Self {
        access_token: false,
        subject: false,
        interact: false,
        continuation: false,
    };

    /// What the given state permits.
    #[must_use]
    #[allow(clippy::match_same_arms)] // the reasons differ; see the comments
    pub const fn for_state(state: State) -> Self {
        match state {
            // §1.5: a request has to leave this state before a response is
            // returned, so nothing is emitted from here.
            State::Processing => Self::NOTHING,
            State::Pending => Self {
                access_token: false,
                subject: false,
                interact: true,
                continuation: true,
            },
            State::Approved => Self {
                access_token: true,
                subject: true,
                interact: false,
                continuation: true,
            },
            // Once finalized no token, no subject information and no
            // interaction can follow (§5.4) — the same emptiness as
            // processing, reached for the opposite reason.
            State::Finalized => Self::NOTHING,
        }
    }

    /// Whether `continue` must be present, not merely allowed.
    ///
    /// §3.1: "This field is REQUIRED if the grant request is in the _pending_
    /// state".
    #[must_use]
    pub fn continuation_required(state: State) -> bool {
        state == State::Pending
    }
}

/// A grant request as the AS tracks it.
///
/// Holds only what the transitions need. Everything else — the requested
/// access, the client's key, the tokens issued — lives outside: §1.5 leaves the
/// means of managing state to the implementation.
#[derive(Debug, Clone)]
pub struct Grant {
    state: State,
    /// Whether the last response offered a continuation (§5).
    continuation_offered: bool,
    /// The earliest time the next continuation call may arrive (§3.1, §5).
    ///
    /// Wider than the clock on purpose: `now + wait` is computed from two
    /// values off the wire and the clock, and has to stay exact even when the
    /// AS names a `wait` that does not fit next to `now`. Saturating in `u64`
    /// would make `u64::MAX` a moment at which any wait has elapsed.
    not_before: u128,
    /// Interaction references already spent (§4.2).
    spent_refs: HashSet<String>,
    /// The interaction start mode that completed, if any (§4.1).
    completed_start_mode: Option<String>,
}

impl Default for Grant {
    fn default() -> Self {
        Self::new()
    }
}

impl Grant {
    /// Creates a grant request in the processing state.
    ///
    /// §2: "Sending a request to the grant endpoint creates a grant request in
    /// the _processing_ state."
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Processing,
            continuation_offered: false,
            not_before: 0,
            spent_refs: HashSet::new(),
            completed_start_mode: None,
        }
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// What a response may carry right now.
    #[must_use]
    pub const fn allowed(&self) -> Allowed {
        Allowed::for_state(self.state)
    }

    /// Records that a response offered a continuation, and when the next call
    /// may arrive.
    ///
    /// `wait` is the value of the `wait` field; §3.1 makes an absent value mean
    /// five seconds.
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    pub fn offer_continuation(&mut self, now: u64, wait: Option<u64>) {
        self.continuation_offered = true;
        // `wait` comes off the wire. A hostile or broken AS can send one that
        // does not fit next to `now` in 64 bits; wrapping would turn "wait
        // forever" into "call now", and a panic would let a response take the
        // client down. In 128 bits the sum is simply the sum.
        self.not_before = u128::from(now) + u128::from(wait.unwrap_or(DEFAULT_WAIT));
    }

    /// Records that a response offered no continuation.
    ///
    /// §5: without one, the client must not call the continuation API again.
    pub const fn withhold_continuation(&mut self) {
        self.continuation_offered = false;
    }

    /// Applies an event, returning the new state or the error the AS must send.
    ///
    /// The guards run before the transition, in the order of the state machine
    /// specification.
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    /// # Errors
    ///
    /// Fails when a guard refuses the event: a finalized grant, a wait period
    /// that has not elapsed, a continuation that was never offered, a replayed
    /// interaction reference, or an event that is not a transition out of the
    /// current state.
    ///
    pub fn apply(&mut self, event: Event, now: u64) -> Result<State, TransitionError> {
        self.check_guards(&event, now)?;

        // Each arm is one row of `vectors/state-machine.json`. Several rows
        // land in the same state; merging them would save a line and lose the
        // correspondence with the specification.
        #[allow(clippy::match_same_arms)]
        let next = match (self.state, event) {
            // T02, T03, T04 — the AS settles a processing request.
            (State::Processing, Event::AsRequiresInteraction) => State::Pending,
            (State::Processing, Event::AsNeedsNoInteraction) => State::Approved,
            (State::Processing, Event::AsCannotProceed) => State::Finalized,

            // T05, T09 — polling leaves the state as it is.
            (State::Pending, Event::ContinuePoll) => State::Pending,
            (State::Approved, Event::ContinuePoll) => State::Approved,

            // T06, T07 — the request goes back for re-evaluation.
            (State::Pending, Event::ContinueWithInteractRef(r)) => {
                self.spent_refs.insert(r);
                State::Processing
            }
            (State::Pending, Event::OutOfBandRoDecision) => State::Processing,

            // T10, T11 — a modification is re-evaluated in its new context.
            (State::Pending | State::Approved, Event::Modify) => State::Processing,

            // T08, T12 — the client ends the request.
            (State::Pending | State::Approved, Event::Revoke) => State::Finalized,

            // An interaction start completing does not move the request; it
            // only closes the other start modes (§4.1).
            (state, Event::InteractionStartCompleted(mode)) => {
                self.completed_start_mode = Some(mode);
                state
            }

            (state, refused) => {
                return Err(TransitionError {
                    code: ErrorCode::InvalidContinuation,
                    reason: format!(
                        "`{refused}` is not a transition out of the {state} state \
                         (RFC 9635 §1.5)"
                    ),
                    finalizes: false,
                })
            }
        };

        self.state = next;
        Ok(next)
    }

    /// The guards of §4 and §5, applied before any transition.
    ///
    /// One function per guard, named after the entry it enforces in
    /// `vectors/state-machine.json`, so the code and the specification can be
    /// read side by side.
    fn check_guards(&mut self, event: &Event, now: u64) -> Result<(), TransitionError> {
        self.g03_finalized_is_absorbing()?;
        if event.is_continuation() {
            self.g05_continuation_was_offered()?;
            self.g04_wait_period_elapsed(now)?;
        }
        match event {
            Event::ContinueWithInteractRef(r) => {
                self.g01_interaction_reference_only_while_pending()?;
                self.g06_interaction_reference_is_fresh(r)?;
            }
            Event::Modify => self.g02_modification_needs_an_open_grant()?,
            Event::InteractionStartCompleted(mode) => self.g07_one_start_mode_only(mode)?,
            _ => {}
        }
        Ok(())
    }

    /// G03 — once finalized, nothing moves the grant (§5.4).
    fn g03_finalized_is_absorbing(&self) -> Result<(), TransitionError> {
        if self.state == State::Finalized {
            return Err(TransitionError {
                code: ErrorCode::InvalidContinuation,
                reason: "the grant request is finalized and MUST NOT be moved to any \
                         other state (RFC 9635 §5.4)"
                    .into(),
                finalizes: false,
            });
        }
        Ok(())
    }

    /// G05 — the client calls the continuation API only when invited (§5).
    fn g05_continuation_was_offered(&self) -> Result<(), TransitionError> {
        if self.continuation_offered {
            return Ok(());
        }
        Err(TransitionError {
            code: ErrorCode::InvalidContinuation,
            reason: "no continuation was offered in the previous response, so the \
                     client MUST NOT call the continuation API (RFC 9635 §5)"
                .into(),
            finalizes: false,
        })
    }

    /// G04 — the announced wait must have elapsed (§5).
    fn g04_wait_period_elapsed(&self, now: u64) -> Result<(), TransitionError> {
        let now = u128::from(now);
        if now >= self.not_before {
            return Ok(());
        }
        Err(TransitionError {
            code: ErrorCode::TooFast,
            reason: format!(
                "the wait period has not elapsed: {} s remaining; the client MUST NOT \
                 call the continuation URI before it does (RFC 9635 §5)",
                self.not_before - now
            ),
            finalizes: false,
        })
    }

    /// G01 — an interaction reference outside the pending state ends the grant.
    ///
    /// §5.1 pairs the error with invalidating the request, so the state changes
    /// even though the transition is refused.
    fn g01_interaction_reference_only_while_pending(&mut self) -> Result<(), TransitionError> {
        if self.state == State::Pending {
            return Ok(());
        }
        let was = self.state;
        self.state = State::Finalized;
        Err(TransitionError {
            code: ErrorCode::TooManyAttempts,
            reason: format!(
                "an interaction reference was presented while the request is {was}, not \
                 pending; the AS MUST return too_many_attempts and SHOULD invalidate the \
                 request (RFC 9635 §5.1)"
            ),
            finalizes: true,
        })
    }

    /// G06 — an interaction reference is single use (§4.2).
    fn g06_interaction_reference_is_fresh(&self, reference: &str) -> Result<(), TransitionError> {
        if !self.spent_refs.contains(reference) {
            return Ok(());
        }
        Err(TransitionError {
            code: ErrorCode::InvalidInteraction,
            reason: format!(
                "interaction reference `{reference}` has already been used; it MUST be \
                 one-time-use (RFC 9635 §4.2)"
            ),
            finalizes: false,
        })
    }

    /// G02 — a modification needs the approved or pending state (§5.3).
    fn g02_modification_needs_an_open_grant(&self) -> Result<(), TransitionError> {
        if matches!(self.state, State::Approved | State::Pending) {
            return Ok(());
        }
        Err(TransitionError {
            code: ErrorCode::InvalidContinuation,
            reason: format!(
                "a modification request requires the approved or pending state, the \
                 request is {} (RFC 9635 §5.3)",
                self.state
            ),
            finalizes: false,
        })
    }

    /// G07 — one completed start mode closes the others (§4.1).
    fn g07_one_start_mode_only(&self, mode: &str) -> Result<(), TransitionError> {
        match &self.completed_start_mode {
            Some(done) if done != mode => Err(TransitionError {
                code: ErrorCode::InvalidInteraction,
                reason: format!(
                    "start mode `{done}` has already completed; the AS MUST reject \
                     attempts to use `{mode}` (RFC 9635 §4.1)"
                ),
                finalizes: false,
            }),
            _ => Ok(()),
        }
    }
}

/// The wait applied when a continuation response carries no `wait` field.
///
/// §3.1: "omission of the value MUST be interpreted as five seconds".
pub const DEFAULT_WAIT: u64 = 5;
