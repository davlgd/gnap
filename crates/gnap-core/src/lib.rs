//! The GNAP grant state machine — RFC 9635 §1.5.
//!
//! A grant request moves through four states, and most of the RFC's rules are
//! guards on the transitions between them. This crate holds that machine, and
//! nothing else: no I/O, no cryptography, no HTTP.
//!
//! The machine is specified as data in `vectors/state-machine.json`, derived
//! from the normative requirements of §3, §4 and §5. The test suite reads that
//! file and checks this implementation against it, so the two cannot drift
//! apart unnoticed.
//!
//! ```
//! use gnap_core::{Event, Grant, State};
//!
//! let mut grant = Grant::new();
//! assert_eq!(grant.state(), State::Processing);
//!
//! // The AS decides interaction is needed, and offers a continuation.
//! grant.apply(Event::AsRequiresInteraction, 0).unwrap();
//! assert_eq!(grant.state(), State::Pending);
//! assert!(!grant.allowed().access_token, "no token is released while pending");
//! ```

pub mod event;
pub mod grant;
pub mod response;
pub mod state;

pub use event::Event;
pub use grant::{Allowed, Grant, TransitionError, DEFAULT_WAIT};
pub use response::{check_response, Violation};
pub use state::State;

pub use gnap_types::unix_now;
