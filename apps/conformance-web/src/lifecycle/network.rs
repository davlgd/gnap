//! The lifecycle scenario's transport: the shared bounded transport, for
//! the operator-approved target and within the lifecycle's limits.

use super::config::Target;
use crate::net::{Bounded, Limits};

/// Used only on the lifecycle's dedicated worker thread.
pub type Network = Bounded<Target>;

/// The transport of one lifecycle run, within the lifecycle's limits.
pub fn network(target: Target, local: bool, runtime: tokio::runtime::Handle) -> Network {
    Bounded::with_limits(target, Limits::LIFECYCLE, local, runtime)
}
