//! Verifying a GNAP-signed request — RFC 9635 §7.3.1, for any role.
//!
//! §7.3.1 says what a verifier has to check, and it says it once for the AS
//! and the RS alike: every included signature examined until one is
//! acceptable, the `gnap` tag, no `alg`, `created` close to now, `keyid`
//! naming the key, the required components covered, `Content-Digest`
//! recomputed, the nonce spent exactly once. So the checks live here once,
//! and a role brings only what differs between deployments: the clock, its
//! tolerance, the key it expects, and where it remembers nonces.
//!
//! The order of the checks is part of the contract. Everything that can be
//! decided from the parameters alone is decided before the signature is
//! verified, and the nonce is remembered last: an unproven signature must not
//! be able to spend a nonce, or anyone could burn the one a legitimate client
//! is about to use.

use crate::digest::verify_content_digest;
use crate::httpsig::{
    parse_covered_components, parse_signature_params, parse_signatures, signature_base, Component,
    LabelledSignature, Message, ReceivedParams, Tag,
};
use crate::proof::Verifier;
use core::fmt;

/// The request as the verifier sees it: what the signature can cover, and the
/// headers it was carried in.
///
/// A view, not a type of its own: the fields are what any HTTP request already
/// has, so a role hands over references to what it received.
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'a> {
    /// The HTTP method.
    pub method: &'a str,
    /// The full request URI.
    pub target_uri: &'a str,
    /// Every header field, in message order, names in whatever case they came.
    pub headers: &'a [(String, String)],
    /// The message content, if any.
    pub body: Option<&'a [u8]>,
}

impl SignedRequest<'_> {
    /// Every instance of a field, in message order (RFC 9421 §2.1).
    fn header_values(&self, name: &str) -> impl Iterator<Item = &str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.as_str())
    }

    /// The instances combined as RFC 9421 §2.1 has them: each trimmed of SP
    /// and HTAB, joined by a single comma and a single space.
    fn combined_header_value(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .header_values(name)
            .map(|v| v.trim_matches([' ', '\t']))
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }
}

/// Where a verifier remembers the nonces it has accepted (§7.3.1-M14).
///
/// "When included, the verifier MUST determine that the nonce value is unique
/// within a reasonably short time period such as several minutes." What
/// "remember" means — a set in memory, a shared cache in front of several
/// servers — is the deployment's; this is the one question the verifier asks
/// it. A closure `Fn(&str, u64) -> bool` implements it.
///
/// Three things the implementation has to get right, because the verifier
/// cannot check them for it:
///
/// - **Atomicity.** Test-and-insert is one operation. Two requests carrying
///   the same nonce at the same instant must not both see it as new.
/// - **Retention.** A nonce is kept for as long as a signature carrying it
///   could still be accepted. `created` is accepted within `max_clock_skew`
///   on *either* side of now, so a signature stamped `skew` seconds in the
///   future stays acceptable until `2 × skew` after it was first seen —
///   retention is that span, not the skew itself.
/// - **Scope.** A memory shared between roles, or between keys, would let a
///   nonce spent at one deny a legitimate request at the other. Give each
///   verifying role — and, where keys are not trusted to keep their nonces
///   apart, each key — its own.
pub trait NonceMemory {
    /// Records a nonce seen at `now`, returning `false` if it was already
    /// there.
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool;
}

impl<F: Fn(&str, u64) -> bool> NonceMemory for F {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self(nonce, now)
    }
}

/// What the deployment expects of an acceptable signature.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// The current time, in seconds since the Unix epoch.
    pub now: u64,
    /// How far `created` may sit from `now`, on either side.
    ///
    /// §7.3.1 asks that the timestamp be "sufficiently close to the current
    /// time given expected network delay and clock skew", without naming a
    /// figure.
    pub max_clock_skew: u64,
    /// The identifier the `keyid` parameter has to name, when the presented
    /// key names itself — the `kid` of a JWK sent by value (§7.3.1-M15).
    ///
    /// The verifier's own [`Verifier::expected_key_id`] is checked as well;
    /// this one is for a key identity the role learned from the message.
    pub key_id: Option<&'a str>,
}

/// What an accepted signature said about itself.
///
/// Returned so that a role can log or decide on it — which label carried the
/// proof, its `created`, its nonce — without parsing the field a second time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The label of the signature that was accepted.
    pub label: String,
    /// Its signature parameters.
    pub params: ReceivedParams,
    /// The components it covered, in order.
    pub components: Vec<Component>,
}

/// Why no signature on the request was acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The request carries no `Signature-Input` and `Signature` pair at all.
    Unsigned,
    /// Every candidate was refused; this is the reason the last one was.
    Rejected(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned => {
                f.write_str("the request carries no Signature-Input and Signature pair")
            }
            Self::Rejected(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verifies the signature on a GNAP request (§7.3.1).
///
/// RFC 9635 §7.3.1-M21 — "The verifier MUST examine all included signatures
/// until it finds (at least) one that is acceptable according to its policy
/// and meets the requirements in this section." An unreadable entry is one candidate
/// lost, not a verdict on the message: a caller who prepends a malformed
/// signature must not be able to bury the valid one behind it.
///
/// # What this does not do
///
/// Success means one thing: the request was signed by the holder of the key
/// behind `verifier`, over the components §7.3.1 requires, within the clock
/// window — and, when the signature carries a nonce, not before. The nonce is
/// what §7.3.1 has the signer SHOULD include; a signature without one is
/// accepted and is replayable for the length of the window, so a caller that
/// wants every request to be single-use has to require the nonce itself from
/// [`Accepted::params`]. It is proof of possession, not authorization. In
/// particular the caller still has to:
///
/// - decide **whose** key that is and what it may do — resolving a client,
///   a token or an RS to a key is the role's job, and so is everything that
///   follows from the identity;
/// - check the **presented key itself** when there is one: that its `proof`
///   is `httpsig`, that a JWK's `alg` is the verifier's algorithm
///   (§7.3.1-M15, its first half). This function only checks that `keyid`
///   names what [`Expectations::key_id`] and [`Verifier::expected_key_id`]
///   say it should;
/// - apply any **lifetime** of its own: an access token's expiry, or the
///   `expires` signature parameter, which RFC 9421 calls a hint and which is
///   returned in [`Accepted::params`] untouched;
/// - settle what a request carrying **`Authorization` more than once**
///   means, before calling this. RFC 9110 does not make that field a list,
///   so parsers disagree on it; the first instance is the one read here.
///   Refusing such a request outright, as the AS in this workspace does, is
///   the recommended handling;
/// - give [`NonceMemory`] the atomicity, retention and scope its
///   documentation asks for.
///
/// # Errors
///
/// [`VerifyError::Unsigned`] when the request carries no signature fields;
/// [`VerifyError::Rejected`] with the last reason when none of the candidates
/// is acceptable.
pub fn verify_request(
    request: &SignedRequest<'_>,
    verifier: &dyn Verifier,
    expectations: &Expectations<'_>,
    nonces: &dyn NonceMemory,
) -> Result<Accepted, VerifyError> {
    verify_request_with_policy(request, verifier, expectations, nonces, &|_| true)
}

/// Verifies a GNAP request with additional per-signature parameter requirements.
///
/// The predicate can only narrow acceptance: all mandatory GNAP checks remain.
/// It runs after mandatory parameter checks but before cryptographic verification
/// and nonce consumption. Its input is therefore **not authenticated**. Keep the
/// predicate deterministic and free of side effects; it must not authorize an
/// operation, record a nonce or trust a claim merely because it sees it here.
///
/// A rejected candidate does not stop examination of later signatures. For a
/// profile requiring a nonce, pass `&|params| params.nonce.is_some()` instead of
/// checking the first accepted signature after [`verify_request`] returns.
///
/// # Errors
/// Returns the same errors as [`verify_request`], also rejecting candidates
/// whose parameters do not meet the additional policy.
pub fn verify_request_with_policy(
    request: &SignedRequest<'_>,
    verifier: &dyn Verifier,
    expectations: &Expectations<'_>,
    nonces: &dyn NonceMemory,
    policy: &dyn Fn(&ReceivedParams) -> bool,
) -> Result<Accepted, VerifyError> {
    let (Some(input_field), Some(signature_field)) = (
        request.combined_header_value("signature-input"),
        request.combined_header_value("signature"),
    ) else {
        return Err(VerifyError::Unsigned);
    };

    let signatures = parse_signatures(&input_field, &signature_field);
    if signatures.is_empty() {
        return Err(VerifyError::Rejected(
            "no signature carries both a Signature-Input and a Signature entry \
             (RFC 9421 §4.1, §4.2)"
                .into(),
        ));
    }

    let mut last = None;
    for candidate in &signatures {
        match candidate {
            Err(e) => last = Some(e.to_string()),
            Ok(candidate) => {
                match accept_signature(request, verifier, expectations, nonces, candidate, policy) {
                    Ok(accepted) => return Ok(accepted),
                    Err(reason) => last = Some(reason),
                }
            }
        }
    }
    Err(VerifyError::Rejected(
        last.unwrap_or_else(|| "no acceptable signature".into()),
    ))
}

/// Decides whether one labelled signature is acceptable (§7.3.1).
fn accept_signature(
    request: &SignedRequest<'_>,
    verifier: &dyn Verifier,
    expectations: &Expectations<'_>,
    nonces: &dyn NonceMemory,
    candidate: &LabelledSignature,
    policy: &dyn Fn(&ReceivedParams) -> bool,
) -> Result<Accepted, String> {
    let raw = &candidate.raw_params;
    let params = parse_signature_params(raw).map_err(|e| e.to_string())?;
    check_parameters(&params, verifier, expectations)?;
    if !policy(&params) {
        return Err("signature parameters do not meet the verifier's additional policy".into());
    }

    let components = parse_covered_components(raw).map_err(|e| e.to_string())?;

    // §7.3.1 — @method and @target-uri are always covered.
    for required in [Component::Method, Component::TargetUri] {
        if !components.contains(&required) {
            return Err(format!(
                "{} is not covered by the signature; §7.3.1 requires it",
                required.identifier()
            ));
        }
    }

    let digest_field = request.combined_header_value("content-digest");
    let digest = digest_field.as_deref();
    // Authorization is not a list field; the first instance is the one read,
    // and a role that refuses duplicates does so before coming here.
    let authorization = request.header_values("authorization").next();

    // §7.3.1 — when the request is bound to an access token, the covered
    // components MUST include `authorization`. Without this the same signature
    // could be replayed against a different token.
    if authorization.is_some() && !components.contains(&Component::Authorization) {
        return Err(
            "the request presents an access token but `authorization` is not \
             covered by the signature (RFC 9635 §7.3.1)"
                .into(),
        );
    }

    // §7.3.1 — the verifier recomputes Content-Digest when there is content.
    if let (Some(body), Some(d)) = (request.body, digest) {
        verify_content_digest(body, d).map_err(|e| e.to_string())?;
    }
    if request.body.is_some_and(|b| !b.is_empty())
        && !components.contains(&Component::ContentDigest)
    {
        return Err(
            "the request has content but `content-digest` is not covered \
             (RFC 9635 §7.3.1)"
                .into(),
        );
    }

    let message = Message {
        method: request.method,
        target_uri: request.target_uri,
        content_digest: digest,
        authorization,
        other: Vec::new(),
    }
    .with_fields(&components, |name| {
        request.header_values(name).collect::<Vec<_>>()
    });
    let base = signature_base(&message, &components, raw).map_err(|e| e.to_string())?;
    verifier
        .verify(base.as_bytes(), &candidate.signature)
        .map_err(|e| e.to_string())?;

    // §7.3.1 — "When included, the verifier MUST determine that the nonce
    // value is unique within a reasonably short time period".
    //
    // This is the last condition on purpose. Remembering the nonce is what
    // spends it, and an unproven signature must not be able to spend one:
    // otherwise anyone could burn a nonce by replaying it with a forged
    // signature, and a second candidate in the same message would then be
    // refused as a replay of the first.
    if let Some(nonce) = &params.nonce {
        if !nonces.remember_nonce(nonce, expectations.now) {
            return Err(format!(
                "the signature nonce `{nonce}` has already been seen; it MUST be \
                 unique (RFC 9635 §7.3.1)"
            ));
        }
    }

    Ok(Accepted {
        label: candidate.label.clone(),
        params,
        components,
    })
}

/// The checks that need only the signature parameters (§7.3.1): the tag, the
/// absence of `alg`, the key named, and when the signature was made.
///
/// Decided before the signature itself is verified, so an unreadable or
/// mis-aimed candidate costs nothing and gives a precise reason.
fn check_parameters(
    params: &ReceivedParams,
    verifier: &dyn Verifier,
    expectations: &Expectations<'_>,
) -> Result<(), String> {
    // §7.3.1 — "The explicit alg signature parameter MUST NOT be included",
    // since the algorithm comes from the key.
    if params.alg.is_some() {
        return Err(
            "the signature carries an `alg` parameter, which MUST NOT be \
             included (RFC 9635 §7.3.1)"
                .into(),
        );
    }

    // §7.3.1 — "The signer MUST include the tag signature parameter with the
    // value gnap, and the verifier MUST verify that the parameter exists with
    // this value." `gnap-rotate` belongs to the key rotation of §7.3.1.1,
    // which no role here implements; accepting it would accept a signature
    // made for another purpose.
    if params.tag.as_deref() != Some(Tag::Gnap.as_str()) {
        return Err(format!(
            "the signature carries tag={:?}; the verifier MUST verify that the tag \
             exists with the value `gnap` (RFC 9635 §7.3.1)",
            params.tag
        ));
    }

    // §7.3.1 — "If the signer's key presented is a JWK, the keyid parameter of
    // the signature MUST be set to the kid value of the JWK". Only a key form
    // that names itself can be checked this way. The identity the role read
    // from the message comes first; a key resolved by reference names itself
    // through the verifier. Either way the check belongs to this candidate: a
    // message may carry several signatures, and only the one that verifies
    // has to be the right key's.
    for expected in [expectations.key_id, verifier.expected_key_id()]
        .into_iter()
        .flatten()
    {
        if params.keyid.as_deref() != Some(expected) {
            return Err(format!(
                "the signature names keyid={:?}; this key is `{expected}`, and the \
                 keyid MUST be set to it (RFC 9635 §7.3.1)",
                params.keyid
            ));
        }
    }

    // §7.3.1 — created is required, and the verifier ensures it is close
    // enough to now given expected network delay and clock skew.
    let Some(created) = params.created else {
        return Err(
            "the signature carries no `created` parameter, which the signer \
             MUST include (RFC 9635 §7.3.1)"
                .into(),
        );
    };
    let skew = expectations.now.abs_diff(created);
    if skew > expectations.max_clock_skew {
        return Err(format!(
            "the signature was created {skew} s from now, beyond the {} s this \
             verifier accepts; the verifier MUST ensure the timestamp is close to \
             the current time (RFC 9635 §7.3.1)",
            expectations.max_clock_skew
        ));
    }
    Ok(())
}
