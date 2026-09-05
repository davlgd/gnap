//! What the deployment decides, as opposed to what the protocol decides.
//!
//! RFC 9635 §4 is deliberate about this: "The details of how the AS makes this
//! determination are out of scope for this document." Whether a request needs
//! an RO's approval, which access is granted, which client is trusted — none of
//! that is protocol. It goes behind these traits.

use gnap_crypto::proof::Verifier;
use gnap_registry::ErrorCode;
use gnap_types::access::AccessItem;
use gnap_types::client::Client;
use gnap_types::message::GrantRequest;
use gnap_types::token::AccessToken;
use gnap_types::user::SubjectResponse;
use std::num::NonZeroU64;

/// What the AS decided to do with a grant request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Grant it outright: no RO approval is needed (§4).
    ///
    /// The access granted may differ from the access requested; §3.2.1 requires
    /// the response to reflect what was actually granted.
    Approve {
        /// The rights attached to the issued token.
        access: Vec<AccessItem>,
        /// Subject information to release, when it was asked for, and the
        /// ground on which the AS is entitled to release it (§3.4).
        subject: Option<ReleasedSubject>,
    },

    /// Interaction with an RO is required before anything is released (§4).
    RequireInteraction,

    /// Refuse, with the error code to return (§3.6).
    Deny(ErrorCode),
}

/// Subject information, and why the AS may release it (§3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedSubject {
    /// What makes the AS sure (§3.4-M01, §3.4-M11).
    pub ground: SubjectGround,
    /// What the AS states about the RO.
    pub subject: Box<SubjectResponse>,
}

/// Why the AS is entitled to release subject information (§3.4).
///
/// §3.4-M01: "The AS MUST return the subject field only in cases where the AS
/// is sure that the RO and the end user are the same party. This can be
/// accomplished through some forms of interaction with the RO (Section 4)."
/// §3.4-M11: "The AS MUST ensure that the returned subject information
/// represents the RO."
///
/// Neither is something a library can decide for a deployment. What it can do
/// is refuse to release subject information without the deployment saying on
/// what ground — no field to leave unset, no default — and check the one ground
/// it is able to see for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectGround {
    /// The RO answered through the interaction of §4, on this grant request.
    ///
    /// This is the ground §3.4 itself names, and the only one the AS can
    /// verify: a grant that has been through no interaction cannot claim it,
    /// and the server refuses the claim rather than the request.
    RoInteractedHere,

    /// The AS is sure by some other means, which it names here.
    ///
    /// Nothing in this library can check it. Naming it is the point: it turns
    /// releasing subject information into a decision somebody made, and puts
    /// the reason where a reviewer will read it.
    EstablishedOtherwise(&'static str),
}

/// Decides what a grant request needs.
pub trait Policy {
    /// Evaluates a fresh or modified grant request.
    fn evaluate(&self, request: &GrantRequest) -> Decision;

    /// Lifetime of a newly approved access token, in seconds (§3.2.1).
    ///
    /// Called with the approved request, including modifications accepted
    /// during continuation. `None`, the default, omits `expires_in`; it does
    /// not promise that the token can never be revoked. A finite duration
    /// must fit when added to the server's issuance time or issuance fails.
    /// Rotation preserves this duration and starts it again at rotation time;
    /// it does not reevaluate this policy method.
    fn token_lifetime(&self, _request: &GrantRequest) -> Option<NonZeroU64> {
        None
    }

    /// Whether this access token may be rotated (§6.1).
    ///
    /// §6.1: "If the AS is unable or unwilling to rotate the value of the
    /// access token, the AS responds with an `invalid_rotation` error." Willing
    /// is a policy word, so it is asked here; unable is the server's own
    /// business and it answers that itself.
    ///
    /// The default allows it, because an AS that hands out a `manage` field is
    /// offering the two actions §6 defines.
    fn may_rotate(&self, _token: &AccessToken) -> bool {
        true
    }

    /// Whether the AS recognises a user reference the client passed (§2.4.1).
    ///
    /// §2.4.1-M02: "If the AS does not recognize the user reference, it MUST
    /// return an `unknown_user` error." The references are the AS's own — it
    /// hands them out, typically as an opaque Subject Identifier (§3.4) — and
    /// their "lifetime and validity [...] are determined by the AS", so only the
    /// deployment can answer.
    ///
    /// The default recognises none, which is the right answer for a deployment
    /// that issues none: replying `unknown_user` is exactly what §2.4.1 asks of
    /// it, and is safer than treating an unknown reference as absent.
    fn recognises_user(&self, _reference: &str) -> bool {
        false
    }

    /// Evaluates a grant that is coming back from interaction.
    ///
    /// §4 notes that this happens whether the RO approved or denied, since the
    /// AS has to take the full context into account before deciding.
    fn evaluate_after_interaction(&self, request: &GrantRequest) -> Decision {
        self.evaluate(request)
    }
}

/// Finds the key a client claims, so its signature can be checked.
///
/// §2.3 lets an AS accept an unknown key, refuse it, or treat it as
/// trust-on-first-use. Returning `None` means the AS does not recognise the
/// client, which §2.3.1 answers with `invalid_client`.
pub trait KeyResolver {
    /// The verifier for this client's key, if the AS accepts it.
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>>;
}
