//! Linked HTTP signatures for a token's key rotation (RFC 9635 §7.3.1.1).
//!
//! This verifies two proofs, not a key-rotation request's authorization. The
//! caller resolves the old key from the live token and the new key from the
//! signed body, validates the request and proof method, and commits the new
//! binding only after these proofs and its own policy have succeeded.

use crate::httpsig::{parse_signature_params, parse_signatures, Component, ReceivedParams, Tag};
use crate::proof::Verifier;
use crate::verify::{authenticate_signature, Accepted, Expectations, SignedRequest, VerifyError};

/// Maximum paired-proof candidates accepted by this implementation.
///
/// This is a resource limit, not a limit imposed by GNAP. Each distinct
/// `Signature-Input` label, including an unusable candidate, counts once.
pub const MAX_ROTATION_SIGNATURES: usize = 16;

/// Maximum combined size of the two signature fields, including separators.
///
/// This implementation limit bounds parsing before cryptographic work. The
/// transport must separately bound the whole request, including its body.
pub const MAX_ROTATION_SIGNATURE_BYTES: usize = 32 * 1024;

/// The key and per-signature policy for one side of a rotation.
pub struct RotationProof<'a> {
    /// The actual key to verify, not a key selected merely by the received kid.
    pub verifier: &'a dyn Verifier,
    /// Clock, tolerance and optional key identifier for this key.
    /// Both proofs must use the same `now`; their `created` values may differ.
    pub expectations: Expectations<'a>,
    /// Additional parameter requirements, evaluated before authentication.
    /// Like `verify_request_with_policy`, this predicate must have no side
    /// effects and may narrow acceptance, never replace the mandatory checks.
    pub policy: &'a dyn Fn(&ReceivedParams) -> bool,
}

/// Atomic replay protection for a pair of authenticated, linked signatures.
///
/// An implementation must test both nonces and record both in one operation,
/// or return false without recording either. It must share the nonce state
/// used by ordinary requests under the corresponding keys: a separate cache
/// just for rotation would permit cross-path replays. Scope and retention
/// obey the same rules as [`crate::NonceMemory`].
///
/// Absent nonces do not require storage. This verifier requires distinct values
/// when both are present, so it also works with a single global nonce namespace.
/// That restriction is an implementation choice, not a per-key GNAP requirement.
/// The adapter is called only after both proofs and their link have validated.
pub trait RotationNonceMemory {
    /// Reserves both nonces at `now`, or neither if either is already seen.
    fn remember_pair(&self, previous: Option<&str>, replacement: Option<&str>, now: u64) -> bool;
}

impl<F: Fn(Option<&str>, Option<&str>, u64) -> bool> RotationNonceMemory for F {
    fn remember_pair(&self, previous: Option<&str>, replacement: Option<&str>, now: u64) -> bool {
        self(previous, replacement, now)
    }
}

/// Two authenticated signatures whose nonces have been reserved together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRotation {
    /// The current key's ordinary GNAP signature, including its actual label.
    pub previous: Accepted,
    /// The new key's `gnap-rotate` signature covering that previous signature
    /// and its input parameters, as well as the ordinary GNAP components.
    pub replacement: Accepted,
}

/// Verifies the linked signatures for a key-bound token rotation.
///
/// Both signatures cover the nonempty POST body through its checked digest and
/// cover Authorization. The previous proof uses `gnap`; the replacement uses
/// `gnap-rotate` and covers the previous proof's Signature and Signature-Input
/// values. All candidates are examined within the documented limits; each
/// candidate's cryptography is checked at most once, using its tag's key.
///
/// No nonce is spent on an invalid pair. The caller must never dispatch a POST
/// with this body to a bodyless token-value rotation, including when one proof
/// is removed. It must also validate the body's new key, unchanged proof method
/// and parameters, live token, management credential and rotation policy. This
/// function does not parse JSON, compare keys, select a token or change storage.
///
/// # Errors
/// Returns [`VerifyError::Unsigned`] when the signature fields are absent, or
/// [`VerifyError::Rejected`] for an invalid request shape, exceeded resource
/// limit, mismatched clocks, or no acceptable fresh linked pair.
pub fn verify_key_rotation(
    request: &SignedRequest<'_>,
    previous: &RotationProof<'_>,
    replacement: &RotationProof<'_>,
    nonces: &dyn RotationNonceMemory,
) -> Result<AcceptedRotation, VerifyError> {
    validate_request(request, previous, replacement)?;
    let now = previous.expectations.now;
    let (Some(input), Some(signature)) = (
        request.combined_header_value("signature-input"),
        request.combined_header_value("signature"),
    ) else {
        return Err(VerifyError::Unsigned);
    };
    let candidates = parse_signatures(&input, &signature);
    if candidates.len() > MAX_ROTATION_SIGNATURES {
        return Err(rejected("too many key-rotation signature candidates"));
    }
    let mut old = Vec::new();
    let mut new = Vec::new();
    for candidate in candidates.into_iter().flatten() {
        let Ok(params) = parse_signature_params(&candidate.raw_params) else {
            continue;
        };
        let (proof, tag, accepted) = match params.tag.as_deref() {
            Some("gnap") => (previous, Tag::Gnap, &mut old),
            Some("gnap-rotate") => (replacement, Tag::GnapRotate, &mut new),
            _ => continue,
        };
        if let Ok(signature) = authenticate_signature(
            request,
            proof.verifier,
            &proof.expectations,
            &candidate,
            proof.policy,
            tag,
        ) {
            accepted.push(signature);
        }
    }
    for previous in old {
        for replacement in &new {
            if !covers_previous(replacement, &previous.label) {
                continue;
            }
            let old_nonce = previous.params.nonce.as_deref();
            let new_nonce = replacement.params.nonce.as_deref();
            if old_nonce.is_some() && old_nonce == new_nonce {
                continue;
            }
            if nonces.remember_pair(old_nonce, new_nonce, now) {
                return Ok(AcceptedRotation {
                    previous,
                    replacement: replacement.clone(),
                });
            }
        }
    }
    Err(rejected(
        "no acceptable fresh, linked key-rotation signature pair",
    ))
}

fn validate_request(
    request: &SignedRequest<'_>,
    previous: &RotationProof<'_>,
    replacement: &RotationProof<'_>,
) -> Result<(), VerifyError> {
    if previous.expectations.now != replacement.expectations.now {
        return Err(rejected(
            "both key-rotation proofs must use the same decision time",
        ));
    }
    if request.method != "POST" || request.body.is_none_or(<[u8]>::is_empty) {
        return Err(rejected(
            "key rotation requires a POST with a nonempty body",
        ));
    }
    if request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .count()
        != 1
    {
        return Err(rejected(
            "key rotation requires exactly one Authorization field",
        ));
    }
    let mut size = 0_usize;
    for field in ["signature", "signature-input"] {
        for (index, (_, value)) in request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(field))
            .enumerate()
        {
            size = size
                .saturating_add(value.len())
                .saturating_add(usize::from(index > 0) * 2);
            if size > MAX_ROTATION_SIGNATURE_BYTES {
                return Err(rejected(
                    "key-rotation signature fields exceed the size limit",
                ));
            }
        }
    }
    Ok(())
}

fn covers_previous(replacement: &Accepted, previous_label: &str) -> bool {
    ["signature", "signature-input"].iter().all(|required| {
        replacement
            .components
            .iter()
            .any(|component| match component {
                Component::DictionaryMember { field, key } => {
                    field == required && key == previous_label
                }
                // Signature-Input can cover its own known parameters along
                // with the old input. The entire Signature field, in contrast,
                // would require the new signature to cover its own value.
                Component::Field(field) => *required == "signature-input" && field == required,
                _ => false,
            })
    })
}

fn rejected(message: &str) -> VerifyError {
    VerifyError::Rejected(message.into())
}
