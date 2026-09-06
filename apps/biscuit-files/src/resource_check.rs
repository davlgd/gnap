//! Application-only, one-use resource decisions. Not RFC 9767 introspection.
use crate::{
    authorization::Store,
    http::{self, Network, Origin},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gnap_biscuit::LiveDecision;
use gnap_client::{HttpRequest, HttpResponse, HttpTransport};
use gnap_crypto::{
    parse_signature_params, parse_signatures, verify_request_with_policy, Expectations,
    NonceMemory, Ps256Signer, Ps256Verifier, ReceivedParams,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub const CORRELATION: &str = "biscuit-check-nonce";
pub const REQUEST_HASH: &str = "biscuit-check-request-sha256";

/// Separate instances per verifying role/key. Full or rolled-back stores deny.
#[derive(Default)]
pub struct Nonces(Mutex<(u64, HashMap<String, u64>)>);
impl NonceMemory for Nonces {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.reserve(&[nonce], now)
    }
}
impl Nonces {
    /// Both proof nonces share the ordinary memory and are inserted together.
    pub(crate) fn remember_pair(
        &self,
        previous: Option<&str>,
        replacement: Option<&str>,
        now: u64,
    ) -> bool {
        match (previous, replacement) {
            (Some(old), Some(new)) if old != new && !old.is_empty() && !new.is_empty() => {
                self.reserve(&[old, new], now)
            }
            _ => false,
        }
    }
    fn reserve(&self, nonces: &[&str], now: u64) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if now < state.0 || nonces.iter().any(|nonce| nonce.len() > 128) {
            return false;
        }
        state.0 = now;
        state.1.retain(|_, until| *until >= now);
        // Also usable by the AS core, whose accepted clock skew is 300 seconds.
        let Some(until) = now.checked_add(2 * gnap_as::server::MAX_CLOCK_SKEW) else {
            return false;
        };
        if nonces.len() > 4096 - state.1.len()
            || nonces.iter().any(|nonce| state.1.contains_key(*nonce))
        {
            return false;
        }
        for nonce in nonces {
            state.1.insert((*nonce).into(), until);
        }
        true
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    authority: String,
    nonce: String,
    created: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    request_allowed: bool,
}
fn hash(body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(body))
}

pub struct CheckService {
    pub endpoint: String,
    pub key: Ps256Verifier,
    pub store: Arc<Store>,
    pub nonces: Nonces,
}
impl CheckService {
    pub fn handle(&self, r: &HttpRequest) -> HttpResponse {
        self.handle_with_clock(r, &mut crate::now)
    }
    pub fn handle_at(&self, r: &HttpRequest, now: u64) -> HttpResponse {
        self.handle_with_clock(r, &mut || Some(now))
    }
    pub fn handle_with_clock(
        &self,
        r: &HttpRequest,
        clock: &mut impl FnMut() -> Option<u64>,
    ) -> HttpResponse {
        let Some(now) = clock() else {
            return http::denied(503);
        };
        if r.method != "POST" || r.url != self.endpoint {
            return http::denied(405);
        }
        let Some(body) = r.body.as_deref().filter(|b| b.len() <= 384) else {
            return http::denied(400);
        };
        if r.header_values("content-type").collect::<Vec<_>>() != ["application/json"]
            || r.header_values("authorization").next().is_some()
        {
            return http::denied(400);
        }
        let accepted = verify_request_with_policy(
            &http::signed(r),
            &self.key,
            &Expectations {
                now,
                max_clock_skew: crate::replay::CLOCK_OFFSET_BUDGET
                    + crate::replay::PROCESSING_MARGIN,
                key_id: None,
            },
            &self.nonces,
            &|p| p.nonce.as_ref().is_some_and(|n| n.len() <= 128),
        );
        let Ok(accepted) = accepted else {
            return http::denied(401);
        };
        let Ok(query) = serde_json::from_slice::<Query>(body) else {
            return http::denied(400);
        };
        let Ok(id) = URL_SAFE_NO_PAD.decode(&query.authority) else {
            return http::denied(400);
        };
        if id.len() != 64 || URL_SAFE_NO_PAD.encode(&id) != query.authority {
            return http::denied(400);
        }
        let mut valid_clock = true;
        let decision = self
            .store
            .reserve_resource(&id, &query.nonce, query.created, || {
                let Some(final_now) = clock() else {
                    valid_clock = false;
                    return None;
                };
                if final_now < now
                    || final_now.abs_diff(accepted.params.created?)
                        > crate::replay::CLOCK_OFFSET_BUDGET + crate::replay::PROCESSING_MARGIN
                {
                    valid_clock = false;
                    return None;
                }
                Some(final_now)
            });
        if !valid_clock || decision == LiveDecision::Unavailable {
            return http::denied(503);
        }
        let mut response = http::answer(
            200,
            serde_json::json!({"request_allowed":decision == LiveDecision::Allowed}),
        );
        response
            .headers
            .push((CORRELATION.into(), accepted.params.nonce.unwrap()));
        response.headers.push((REQUEST_HASH.into(), hash(body)));
        response
    }
}

/// Signs only this fixed application operation, using the SDK's signature
/// builder; no token or management credential is carried by the channel.
pub fn check_request(
    endpoint: &str,
    authority: &[u8],
    resource_nonce: &str,
    resource_created: u64,
    signer: &Ps256Signer,
    now: u64,
) -> Result<HttpRequest, String> {
    if authority.len() != 64 {
        return Err("invalid native authority identifier".into());
    }
    let body = serde_json::to_vec(&Query {
        authority: URL_SAFE_NO_PAD.encode(authority),
        nonce: resource_nonce.into(),
        created: resource_created,
    })
    .map_err(|_| "resource-check serialization")?;
    if body.len() > 384 {
        return Err("resource-check request too large".into());
    }
    gnap_client::sign_request(
        HttpRequest::new("POST", endpoint).json_body(body),
        signer,
        None,
        now,
    )
    .map_err(|_| "resource-check signing failed".into())
}
pub fn request_nonce(request: &HttpRequest) -> Option<String> {
    let signatures = parse_signatures(
        request.header_value("signature-input")?,
        request.header_value("signature")?,
    );
    let [Ok(signature)] = signatures.as_slice() else {
        return None;
    };
    parse_signature_params(&signature.raw_params).ok()?.nonce
}
pub fn check_response(response: &HttpResponse, request: &HttpRequest, nonce: &str) -> LiveDecision {
    let body = request.body.as_deref().unwrap_or_default();
    if response.status != 200
        || response.body.len() > 64
        || response.header_values("content-type").collect::<Vec<_>>() != ["application/json"]
        || response.header_values(CORRELATION).collect::<Vec<_>>() != [nonce]
        || response.header_values(REQUEST_HASH).collect::<Vec<_>>() != [hash(body).as_str()]
        || !response.has_no_store()
    {
        return LiveDecision::Unavailable;
    }
    match serde_json::from_slice::<Decision>(&response.body) {
        Ok(Decision {
            request_allowed: true,
        }) => LiveDecision::Allowed,
        Ok(Decision {
            request_allowed: false,
        }) => LiveDecision::Denied,
        Err(_) => LiveDecision::Unavailable,
    }
}
pub struct LiveCheck {
    network: Network,
    endpoint: String,
    signer: Ps256Signer,
}
impl LiveCheck {
    pub fn new(origin: Origin, signer: Ps256Signer) -> Result<Self, String> {
        Ok(Self {
            endpoint: format!("{}/resource-check", origin.value),
            network: Network::new(origin)?,
            signer,
        })
    }
    /// The authority and the actually accepted proof's nonce/created leave RS.
    /// No token, descendant identifier or unverified signature candidate does.
    pub fn lookup(&self, ids: &[Vec<u8>], accepted: &ReceivedParams) -> LiveDecision {
        let Some(authority) = ids.first() else {
            return LiveDecision::Unavailable;
        };
        let Some(now) = crate::now() else {
            return LiveDecision::Unavailable;
        };
        let (Some(resource_nonce), Some(created)) = (accepted.nonce.as_deref(), accepted.created)
        else {
            return LiveDecision::Unavailable;
        };
        let Ok(request) = check_request(
            &self.endpoint,
            authority,
            resource_nonce,
            created,
            &self.signer,
            now,
        ) else {
            return LiveDecision::Unavailable;
        };
        let Some(nonce) = request_nonce(&request) else {
            return LiveDecision::Unavailable;
        };
        let Ok(response) = self.network.send(request.clone()) else {
            return LiveDecision::Unavailable;
        };
        check_response(&response, &request, &nonce)
    }
}

#[cfg(test)]
mod nonce_tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn pairs_share_ordinary_retention_and_never_reserve_only_one_half() {
        let memory = Nonces::default();
        assert!(memory.remember_nonce("spent", 100));
        assert!(!memory.remember_pair(Some("spent"), Some("free"), 100));
        assert!(memory.remember_nonce("free", 100));
        for (old, new, free) in [
            (None, Some("a"), "a"),
            (Some(""), Some("b"), "b"),
            (Some("same"), Some("same"), "same"),
        ] {
            assert!(!memory.remember_pair(old, new, 100));
            assert!(memory.remember_nonce(free, 100));
        }
        assert!(memory.remember_pair(Some("old"), Some("new"), 100));
        assert!(!memory.remember_nonce("old", 100));
        assert!(!memory.remember_nonce("new", 100));
        assert!(!memory.remember_pair(Some("old"), Some("fresh"), 700));
        assert!(memory.remember_nonce("fresh", 700));
        assert!(memory.remember_pair(Some("old"), Some("new"), 701));
        assert!(!memory.remember_pair(Some("rollback-a"), Some("rollback-b"), 700));
        assert!(memory.remember_pair(Some("rollback-a"), Some("rollback-b"), 701));
        assert!(!memory.remember_pair(Some("overflow-a"), Some("overflow-b"), u64::MAX));
    }

    #[test]
    fn pairs_need_two_capacity_slots_and_fail_closed_on_poison() {
        let memory = Nonces::default();
        for i in 0..4095 {
            assert!(memory.remember_nonce(&format!("seed-{i}"), 100));
        }
        assert!(!memory.remember_pair(Some("last-a"), Some("last-b"), 100));
        assert!(memory.remember_nonce("last-a", 100));
        assert!(!memory.remember_nonce("last-b", 100));
        let poisoned = Arc::new(Nonces::default());
        let worker = poisoned.clone();
        assert!(std::thread::spawn(move || {
            let _guard = worker.0.lock().unwrap();
            panic!("poison the test nonce store");
        })
        .join()
        .is_err());
        assert!(!poisoned.remember_nonce("ordinary", 100));
        assert!(!poisoned.remember_pair(Some("old"), Some("new"), 100));
    }

    #[test]
    fn competing_pairs_have_one_winner_and_leave_the_losing_half_free() {
        let memory = Arc::new(Nonces::default());
        let gate = Arc::new(Barrier::new(3));
        let workers = ["left", "right"].map(|old| {
            let memory = memory.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                (old, memory.remember_pair(Some(old), Some("shared"), 100))
            })
        });
        gate.wait();
        let results = workers.map(|worker| worker.join().unwrap());
        assert_eq!(results.iter().filter(|(_, won)| *won).count(), 1);
        for (old, won) in results {
            assert_eq!(memory.remember_nonce(old, 100), !won);
        }
        assert!(!memory.remember_nonce("shared", 100));
    }
}
