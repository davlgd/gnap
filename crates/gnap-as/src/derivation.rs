//! One-hop opaque downstream derivation (RFC 9767 §4), an explicit SDK profile.
//!
//! RS1 requests a distinct grant using its own key. It does not rotate the
//! incoming token, inherit its client's key, or attenuate a Biscuit locally.
//! Parent-token revocation cascades, finite lifetimes and one-hop limits are
//! deployment choices here, not additional RFC MUSTs.

use crate::{GrantId, GrantSnapshot, ResolvedResourceServer, RsId, TokenRecord};
use gnap_types::{access::AccessItem, message::GrantRequest, token::TokenValue};
use sha2::{Digest, Sha256};
use std::fmt;

/// Checks that management's resolver accepts the very same cryptographic proof,
/// not merely a matching kid or another signature attached to the message.
pub(crate) fn management_binding(
    request: &gnap_types::http::HttpRequest,
    key: &gnap_types::key::KeyObject,
    management: &dyn gnap_crypto::proof::Verifier,
    now: u64,
) -> bool {
    use gnap_crypto::{
        proof::{ProofError, Verifier},
        ps256::Ps256Verifier,
        verify::{verify_request_with_policy, Expectations, SignedRequest},
    };
    struct Both<'a>(&'a dyn Verifier, &'a dyn Verifier);
    impl Verifier for Both<'_> {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
            self.0.verify(data, signature)?;
            self.1.verify(data, signature)
        }
        fn algorithm(&self) -> &'static str {
            self.0.algorithm()
        }
        fn expected_key_id(&self) -> Option<&str> {
            self.0.expected_key_id()
        }
    }
    let Some(jwk) = key.jwk.as_ref() else {
        return false;
    };
    let Ok(rs) = Ps256Verifier::from_public_jwk(jwk) else {
        return false;
    };
    if management.algorithm() != rs.algorithm()
        || management
            .expected_key_id()
            .is_some_and(|kid| Some(kid) != key.jwk_key_id())
    {
        return false;
    }
    verify_request_with_policy(
        &SignedRequest {
            method: &request.method,
            target_uri: &request.url,
            headers: &request.headers,
            body: request.body.as_deref(),
        },
        &Both(&rs, management),
        &Expectations {
            now,
            max_clock_skew: crate::server::MAX_CLOCK_SKEW,
            key_id: key.jwk_key_id(),
        },
        // RS authentication already spent the nonce; this is a consistency
        // check, never a second replay reservation or an authorization decision.
        &|_: &str, _: u64| true,
        &|params| params.nonce.as_ref().is_some_and(|nonce| !nonce.is_empty()),
    )
    .is_ok()
}

/// Maximum derived lifetime in seconds, further bounded by the parent deadline.
pub const MAX_DERIVED_LIFETIME: u64 = 60;
/// Maximum active child grants for one exact parent token in the memory store.
pub const MAX_DERIVED_CHILDREN: usize = 8;
/// Maximum retained derived grants in the memory store, including revoked grants.
pub const MAX_DERIVED_GRANTS: usize = 256;

/// Exact source token, not a revision of all unrelated grant state.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ParentToken {
    /// Stable AS-local parent grant identity.
    pub grant_id: GrantId,
    /// SHA-256 fingerprint of the source value, not an authorization credential.
    pub value_hash: [u8; 32],
}
impl ParentToken {
    /// Identifies the exact source value without retaining another secret copy.
    #[must_use]
    pub fn new(grant_id: GrantId, value: &TokenValue) -> Self {
        Self {
            grant_id,
            value_hash: Sha256::digest(value.as_str().as_bytes()).into(),
        }
    }
}
impl fmt::Debug for ParentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParentToken")
            .field("grant_id", &self.grant_id)
            .field("value_hash", &"[redacted]")
            .finish()
    }
}

/// Immutable provenance of a derived token, retained only by the AS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedToken {
    /// Exact source token whose removal retires this token.
    pub parent: ParentToken,
    /// Only this canonical RS may receive an active introspection result.
    pub audience: RsId,
}

/// Understood downstream rights approved by the deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAccess {
    /// Resolved leaf rights appropriate to the downstream API.
    pub access: Vec<AccessItem>,
    /// Canonical downstream RS, different from the RS requesting derivation.
    pub audience: RsId,
}

/// Authorizes derivation only after RS proof and live-parent validation.
pub trait DerivationPolicy {
    /// `Some` attests the parent is appropriate for this exact authenticated RS
    /// and maps its approved task to the returned downstream rights/audience.
    ///
    /// Merely recognizing the RS or a `kid` is insufficient. Understand every
    /// access dimension, forbid accidental expansion and establish the intended
    /// RO-authorized purpose. The SDK cannot infer a cross-API rights mapping.
    /// No policy/crypto is run under the storage lock or automatically retried.
    /// The callback is trusted: the complete authenticated parent snapshot can
    /// contain sibling access, management and continuation credentials. Do not
    /// log it or retain secret copies. Only the source fingerprint is persisted
    /// as the child's provenance; the transient wire request still contains the
    /// parent credential while this callback runs.
    fn evaluate(
        &self,
        request: &GrantRequest,
        resource_server: &ResolvedResourceServer,
        parent: &GrantSnapshot,
        token: &TokenRecord,
    ) -> Option<DerivedAccess>;
}
