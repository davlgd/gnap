//! The lifecycle scenario's transport: the shared bounded transport, for
//! the operator-approved target and within the lifecycle's limits.

use super::config::Target;
use crate::net::{Bounded, Limits};

/// Used only on the lifecycle's dedicated worker thread.
pub type Network = Bounded<Target>;

impl Network {
    pub fn new(target: Target, local: bool, runtime: tokio::runtime::Handle) -> Self {
        Self::with_limits(target, Limits::LIFECYCLE, local, runtime)
    }
}
