//! Bounded application replay reservations, kept with the AS token records.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gnap_biscuit::LiveDecision;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub const CREATED_WINDOW: u64 = 300;
pub const CLOCK_OFFSET_BUDGET: u64 = 60;
pub const PROCESSING_MARGIN: u64 = 10;
pub const FUTURE_WINDOW: u64 = crate::SKEW + CLOCK_OFFSET_BUDGET;
pub const RETENTION: Duration = Duration::from_secs(600);
pub const PER_KEY_LIMIT: usize = 256;
pub const GLOBAL_LIMIT: usize = 4096;

/// Identity is the RSA public material, not kid, token, authority or RS instance.
pub fn key_identity(jwk: &Map<String, Value>) -> Option<[u8; 32]> {
    let mut hash = Sha256::new();
    for name in ["n", "e"] {
        let bytes = URL_SAFE_NO_PAD.decode(jwk.get(name)?.as_str()?).ok()?;
        let start = bytes.iter().position(|b| *b != 0)?;
        let bytes = &bytes[start..];
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Some(hash.finalize().into())
}

#[derive(Default)]
pub struct Reservations {
    spent: HashMap<([u8; 32], String), Instant>,
    anchor: Option<(u64, Instant)>,
    last_wall: u64,
    clock_failed: bool,
}
impl Reservations {
    pub fn fail_clock(&mut self) {
        self.clock_failed = true;
    }
    /// A clock failure latches until AS restart, which also removes authorities.
    pub fn clock_ok(&mut self, wall: u64, monotonic: Instant) -> bool {
        if self.clock_failed {
            return false;
        }
        if let Some((origin, started)) = self.anchor {
            let expected = monotonic
                .checked_duration_since(started)
                .and_then(|d| origin.checked_add(d.as_secs()));
            if wall < self.last_wall
                || expected.is_none_or(|e| e.abs_diff(wall) > PROCESSING_MARGIN)
            {
                self.clock_failed = true;
                return false;
            }
        } else {
            self.anchor = Some((wall, monotonic));
        }
        self.last_wall = wall;
        true
    }
    pub fn reserve(
        &mut self,
        key: [u8; 32],
        nonce: &str,
        created: u64,
        wall: u64,
        monotonic: Instant,
    ) -> LiveDecision {
        if !self.clock_ok(wall, monotonic) {
            return LiveDecision::Unavailable;
        }
        if nonce.is_empty()
            || nonce.len() > 128
            || !nonce.bytes().all(|b| matches!(b, b' '..=b'~'))
            || created.abs_diff(wall) > CREATED_WINDOW
            || created > wall.saturating_add(FUTURE_WINDOW)
        {
            return LiveDecision::Denied;
        }
        // Inclusive retention: never drop an entry at its exact 600s boundary.
        self.spent.retain(|_, at| {
            monotonic
                .checked_duration_since(*at)
                .is_none_or(|d| d <= RETENTION)
        });
        let scope = (key, nonce.to_owned());
        if self.spent.contains_key(&scope)
            || self.spent.len() >= GLOBAL_LIMIT
            || self.spent.keys().filter(|(k, _)| *k == key).count() >= PER_KEY_LIMIT
        {
            return LiveDecision::Denied;
        }
        self.spent.insert(scope, monotonic);
        LiveDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_has_explicit_clock_margin_and_never_evicts_early() {
        assert!(
            RETENTION.as_secs()
                > CREATED_WINDOW + crate::SKEW + CLOCK_OFFSET_BUDGET + PROCESSING_MARGIN
        );
        assert_eq!(crate::SKEW, 30);
        assert_eq!(FUTURE_WINDOW, 90);
        let now = Instant::now();
        let mut r = Reservations::default();
        assert_eq!(
            r.reserve([1; 32], "one", 1000, 1000, now),
            LiveDecision::Allowed
        );
        assert_eq!(
            r.reserve([1; 32], "one", 1600, 1600, now + RETENTION),
            LiveDecision::Denied
        );
        assert_eq!(
            r.reserve([1; 32], "one", 1601, 1601, now + Duration::from_secs(601)),
            LiveDecision::Allowed
        );
    }
    #[test]
    fn quotas_are_global_and_per_public_key_without_authority_or_instance_scope() {
        let now = Instant::now();
        let mut r = Reservations::default();
        for key in 0..GLOBAL_LIMIT / PER_KEY_LIMIT {
            for n in 0..PER_KEY_LIMIT {
                assert_eq!(
                    r.reserve([key as u8; 32], &n.to_string(), 1000, 1000, now),
                    LiveDecision::Allowed
                );
            }
            assert_eq!(
                r.reserve([key as u8; 32], "extra", 1000, 1000, now),
                LiveDecision::Denied
            );
        }
        assert_eq!(
            r.reserve([255; 32], "new-key", 1000, 1000, now),
            LiveDecision::Denied
        );
        assert_eq!(r.spent.len(), GLOBAL_LIMIT);
    }
    #[test]
    fn clock_failure_is_latched_and_created_windows_are_strict() {
        let now = Instant::now();
        let mut r = Reservations::default();
        for (n, created, expected) in [
            ("old-boundary", 700, LiveDecision::Allowed),
            ("old", 699, LiveDecision::Denied),
            ("future-boundary", 1090, LiveDecision::Allowed),
            ("future", 1091, LiveDecision::Denied),
            ("farfuture", 1301, LiveDecision::Denied),
        ] {
            assert_eq!(r.reserve([1; 32], n, created, 1000, now), expected);
        }
        assert_eq!(
            r.reserve([1; 32], "rollback", 999, 999, now),
            LiveDecision::Unavailable
        );
        assert_eq!(
            r.reserve([1; 32], "recovered", 1000, 1000, now),
            LiveDecision::Unavailable
        );
        let mut r = Reservations::default();
        assert!(r.clock_ok(1000, now));
        assert!(!r.clock_ok(1000, now + Duration::from_secs(11)));
        let mut r = Reservations::default();
        assert!(r.clock_ok(u64::MAX, now));
        assert!(!r.clock_ok(u64::MAX, now + Duration::from_secs(1)));
    }
    #[test]
    fn key_identity_ignores_kid_and_normalizes_rsa_integer_padding() {
        let mut key = serde_json::json!({"n":"AQI","e":"Aw","kid":"first"})
            .as_object()
            .unwrap()
            .clone();
        let identity = key_identity(&key).unwrap();
        key.insert("kid".into(), serde_json::json!("other"));
        key.insert("n".into(), serde_json::json!("AAEC"));
        assert_eq!(key_identity(&key), Some(identity));
    }
}
