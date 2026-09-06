//! Three-process consumer of the GNAP SDK and its restricted Biscuit profile.
pub mod authorization;
pub mod client;
pub mod config;
pub mod http;
pub mod replay;
pub mod resource;
pub mod resource_check;

pub const TTL: u64 = 1200;
pub const SKEW: u64 = 30;
pub const MAX_BODY: usize = 32 * 1024;
pub const MAX_RECORDS: usize = 64;

pub fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|t| t.as_secs())
}
