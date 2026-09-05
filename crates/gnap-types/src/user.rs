//! Identifying the end user, and subject information.
//!
//! RFC 9635 §2.2, §2.4 and §3.4.

use crate::object_or_reference;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use gnap_registry::AssertionFormat;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A Subject Identifier as defined by RFC 9493.
///
/// The structure varies with `format`, so members are kept as they are rather
/// than typed ahead of time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectIdentifier {
    /// The identifier format (`opaque`, `email`, `iss_sub`, `did`…).
    pub format: String,

    /// The members specific to the format.
    #[serde(flatten)]
    pub value: serde_json::Map<String, serde_json::Value>,
}

impl SubjectIdentifier {
    /// The `(iss, sub)` pair, for the `iss_sub` format of RFC 9493 §3.2.2.
    ///
    /// That pair is the identity: within one issuer, two different `sub` values
    /// are two different people. The other formats do not settle identity the
    /// same way — someone can hold two email addresses — so only this one is
    /// read here.
    #[must_use]
    pub fn issuer_subject(&self) -> Option<(&str, &str)> {
        if self.format != "iss_sub" {
            return None;
        }
        Some((
            self.value.get("iss")?.as_str()?,
            self.value.get("sub")?.as_str()?,
        ))
    }
}

/// An assertion about the subject (§3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    /// The assertion format.
    pub format: AssertionFormat,

    /// The assertion as a JSON string serialization.
    pub value: String,
}

impl Assertion {
    /// The `(iss, sub)` the assertion states about its subject.
    ///
    /// An `id_token` is a JWS in compact serialization; its payload is a JSON
    /// object carrying `iss` and `sub`, which together form the `iss_sub`
    /// identifier of RFC 9493 §3.2.2.
    ///
    /// The signature is deliberately not verified: this is used to compare two
    /// things the same AS sent in the same response, not to accept a claim on
    /// its own. Nothing read here is trusted for anything else.
    ///
    /// `None` when the format is not one this can read, or the payload does not
    /// carry both values.
    #[must_use]
    pub fn issuer_subject(&self) -> Option<(String, String)> {
        if self.format != AssertionFormat::IdToken {
            return None;
        }
        let payload = self.value.split('.').nth(1)?;
        let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let claims: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&decoded).ok()?;
        Some((
            claims.get("iss")?.as_str()?.to_owned(),
            claims.get("sub")?.as_str()?.to_owned(),
        ))
    }
}

/// What the client knows about the end user (§2.4).
///
/// §2.4 is clear: these identifiers are hints for the AS, never a claim that a
/// given RO is present. §11.30 covers processing assertions from a client.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserObject {
    /// Subject Identifiers for the end user.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub_ids: Option<Vec<SubjectIdentifier>>,

    /// Assertions about the end user.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub assertions: Option<Vec<Assertion>>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl UserObject {
    /// Checks §2.2-M04: "All identifiers in the `sub_ids` array MUST identify
    /// the same subject."
    ///
    /// # Errors
    ///
    /// Fails when two `iss_sub` identities from the same issuer disagree.
    pub fn validate(&self) -> Result<(), SubjectMismatch> {
        one_party(self.sub_ids.as_ref(), self.assertions.as_ref())
    }
}

object_or_reference!(
    /// The end user, sent in full or by reference (§2.4.1).
    User,
    UserObject,
    "user"
);

/// What the client asks to learn about the RO (§2.2).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubjectRequest {
    /// The requested identifier formats, as defined by RFC 9493.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub_id_formats: Option<Vec<String>>,

    /// The requested assertion formats.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub assertion_formats: Option<Vec<AssertionFormat>>,

    /// The subject targeted. When absent, the request is about the current user.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub_ids: Option<Vec<SubjectIdentifier>>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The two identities a subject response names that cannot be the same party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectMismatch {
    /// Where the first identity was stated.
    pub first: String,
    /// Where the second was.
    pub second: String,
}

impl fmt::Display for SubjectMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "subject: {} and {} name different parties; all Subject Identifiers and \
             assertions returned MUST refer to the same party (RFC 9635 §3.4, §2.2)",
            self.first, self.second
        )
    }
}

impl std::error::Error for SubjectMismatch {}

/// Checks that everything stated names one party, as far as that is decidable.
///
/// RFC 9635 §3.4: "The `sub_ids` and `assertions` response fields are independent of each
/// other. That is, a returned assertion MAY use a different Subject Identifier
/// than other assertions and Subject Identifiers in the response. However, all
/// Subject Identifiers and assertions returned MUST refer to the same party."
///
/// Only one thing here is decidable without knowing the AS's account model: the
/// `iss_sub` pair of RFC 9493 §3.2.2. Within one issuer, two different `sub`
/// values are two different people. Everything else is left alone on purpose —
/// someone can hold two email addresses, and `aliases` exists precisely to
/// group identifiers for one party — so this refuses what it can prove and
/// stays quiet about the rest.
///
/// # Errors
///
/// Fails when two `iss_sub` identities from the same issuer disagree, whether
/// they come from `sub_ids`, from an `id_token` assertion, or from one of each.
fn one_party(
    sub_ids: Option<&Vec<SubjectIdentifier>>,
    assertions: Option<&Vec<Assertion>>,
) -> Result<(), SubjectMismatch> {
    let mut seen: Vec<(&str, String, String)> = Vec::new();

    let from_ids = sub_ids.into_iter().flatten().filter_map(|id| {
        id.issuer_subject()
            .map(|(iss, sub)| ("sub_ids", iss.to_owned(), sub.to_owned()))
    });
    let from_assertions = assertions.into_iter().flatten().filter_map(|a| {
        a.issuer_subject()
            .map(|(iss, sub)| ("assertions", iss, sub))
    });

    for (where_, iss, sub) in from_ids.chain(from_assertions) {
        if let Some((other, _, other_sub)) = seen
            .iter()
            .find(|(_, seen_iss, seen_sub)| *seen_iss == iss && *seen_sub != sub)
        {
            return Err(SubjectMismatch {
                first: format!("`{other}` (iss={iss}, sub={other_sub})"),
                second: format!("`{where_}` (iss={iss}, sub={sub})"),
            });
        }
        seen.push((where_, iss, sub));
    }
    Ok(())
}

/// What the AS states about the RO (§3.4).
///
/// §3.4 restricts the use: an identifier names the RO at this AS, never a way
/// to reach them. An email returned here does not attest a usable address.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubjectResponse {
    /// The RO's identifiers.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub_ids: Option<Vec<SubjectIdentifier>>,

    /// Assertions about the RO.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub assertions: Option<Vec<Assertion>>,

    /// When the account was last updated, as an RFC 3339 date string.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub updated_at: Option<String>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl SubjectResponse {
    /// Checks §3.4-M14: "all Subject Identifiers and assertions returned MUST
    /// refer to the same party."
    ///
    /// # Errors
    ///
    /// Fails when two `iss_sub` identities from the same issuer disagree.
    pub fn validate(&self) -> Result<(), SubjectMismatch> {
        one_party(self.sub_ids.as_ref(), self.assertions.as_ref())
    }
}
