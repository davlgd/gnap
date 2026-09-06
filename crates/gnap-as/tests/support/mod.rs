//! Snapshot reads used by the protocol tests, without a mutable token store.

use gnap_as::{GrantSelector, GrantStore, TokenRecord};

/// Concise token assertions that still read the actual aggregate snapshot.
pub trait TokenLookup: GrantStore {
    /// Returns the record associated with a live management handle.
    fn get_token(&self, handle: &str) -> Option<TokenRecord> {
        self.lookup(GrantSelector::Management(handle))
            .expect("available test storage")?
            .aggregate
            .tokens
            .remove(handle)
    }
}

impl<T: GrantStore> TokenLookup for T {}
