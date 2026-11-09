//! The `httpsig` proofing method — RFC 9635 §7.3.1, on top of RFC 9421.
//!
//! # Why the parameters line is built here
//!
//! The signature base ends with the line `"@signature-params": <value>`, where
//! the value is exactly that of the `Signature-Input` field (RFC 9421 §2.5). A
//! library that rebuilds this line from a parsed structure may reorder the
//! parameters, and then produce a base different from the one the sender
//! signed — which is what `httpsig` 0.0.26 does.
//!
//! So this line is serialized here and reused verbatim: on the way out as the
//! `Signature-Input` value, on the way in as the received bytes. Signing and
//! verification share a single path, and the base cannot diverge between them.
//!
//! Component canonicalization — the hard, bulky part of RFC 9421 — stays
//! delegated to `httpsig`.

use crate::proof::{ProofError, Signer, Verifier};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use core::fmt;
use core::fmt::Write as _;
use httpsig::prelude::message_component::HttpMessageComponent;

#[allow(
    clippy::redundant_pub_crate,
    reason = "Parser helpers stay crate-private; unreachable_pub rejects pub in this module"
)]
mod parse;

pub(crate) use parse::{dictionary_members, validate_parameters, SF_BASE64};
pub use parse::{
    parse_covered_components, parse_signature_params, parse_signatures, LabelledSignature,
    ReceivedParams,
};

/// The application tag GNAP mandates for the `tag` parameter (§7.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// `gnap` — an ordinary request.
    Gnap,
    /// `gnap-rotate` — the new key's signature during a key rotation
    /// (§7.3.1.1).
    GnapRotate,
}

impl Tag {
    /// The value carried by the `tag` parameter.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Gnap => "gnap",
            Self::GnapRotate => "gnap-rotate",
        }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A component covered by the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Component {
    /// `"@method"` — always required (§7.3.1).
    Method,
    /// `"@target-uri"` — always required (§7.3.1).
    TargetUri,
    /// `"content-digest"` — required as soon as the message has content.
    ContentDigest,
    /// `"authorization"` — required as soon as the request carries a token.
    Authorization,
    /// A member of a Dictionary Structured Field, `"field";key="name"`.
    ///
    /// GNAP uses it for key rotation: the new signature covers the old one's
    /// `"signature";key="…"` and `"signature-input";key="…"` (§7.3.1.1).
    DictionaryMember {
        /// The field name, lowercased.
        field: String,
        /// The key of the targeted member.
        key: String,
    },
    /// Any other header field, lowercased.
    Field(String),
}

impl Component {
    /// The serialized identifier as it appears in the base.
    #[must_use]
    pub fn identifier(&self) -> String {
        match self {
            Self::Method => "\"@method\"".into(),
            Self::TargetUri => "\"@target-uri\"".into(),
            Self::ContentDigest => "\"content-digest\"".into(),
            Self::Authorization => "\"authorization\"".into(),
            Self::Field(f) => format!("\"{}\"", f.to_ascii_lowercase()),
            Self::DictionaryMember { field, key } => {
                format!("\"{}\";key={}", field.to_ascii_lowercase(), sf_string(key))
            }
        }
    }
}

/// Rejects a value that cannot be carried in an `sf-string`.
///
/// RFC 9651 §3.3.3 limits Strings to printable ASCII, `%x20` to `%x7E`:
/// "Note that this excludes tabs, newlines, carriage returns". This matters
/// beyond well-formedness — a newline in a `keyid` would add a line to the
/// signature base, which is the canonicalization attack RFC 9421 §7.5.5 warns
/// about.
fn check_sf_string(field: &str, v: &str) -> Result<(), ProofError> {
    if let Some(c) = v.chars().find(|c| !matches!(c, ' '..='~')) {
        return Err(ProofError::Base(format!(
            "{field}: character {c:?} cannot appear in a Structured Field string, \
             which is limited to printable ASCII (RFC 9651 §3.3.3)"
        )));
    }
    Ok(())
}

/// Serializes a string as an `sf-string`, RFC 9651 §4.1.6.
///
/// The caller checks the value with [`check_sf_string`] first; escaping alone
/// cannot make a newline safe.
fn sf_string(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The parameters of a GNAP signature (§7.3.1).
///
/// The `alg` parameter is deliberately absent: §7.3.1 forbids it, because the
/// algorithm is derived from the key.
#[derive(Debug, Clone)]
pub struct SignatureInput {
    /// The covered components, in order.
    pub components: Vec<Component>,
    /// The creation timestamp. Required (§7.3.1).
    pub created: u64,
    /// The key identifier. Equals the JWK's `kid` when the key is a JWK.
    pub keyid: String,
    /// A unique nonce. Recommended (§7.3.1).
    pub nonce: Option<String>,
    /// The application tag.
    pub tag: Tag,
}

impl SignatureInput {
    /// The `Signature-Input` field value, without the signature label.
    ///
    /// This is also, word for word, the value on the base's
    /// `@signature-params` line.
    ///
    /// # Errors
    ///
    /// Fails when `keyid`, `nonce` or a dictionary key carries a character a
    /// Structured Field string cannot hold (RFC 9651 §3.3.3).
    pub fn serialize(&self) -> Result<String, ProofError> {
        check_sf_string("keyid", &self.keyid)?;
        if let Some(n) = &self.nonce {
            check_sf_string("nonce", n)?;
        }
        for c in &self.components {
            if let Component::DictionaryMember { field, key } = c {
                check_sf_string(&format!("the key of `{field}`"), key)?;
            }
        }

        let inner = self
            .components
            .iter()
            .map(Component::identifier)
            .collect::<Vec<_>>()
            .join(" ");
        let mut s = format!("({inner});created={}", self.created);
        if let Some(n) = &self.nonce {
            let _ = write!(s, ";nonce={}", sf_string(n));
        }
        let _ = write!(s, ";keyid={}", sf_string(&self.keyid));
        let _ = write!(s, ";tag={}", sf_string(self.tag.as_str()));
        Ok(s)
    }
}

/// The number of random bytes behind a signature nonce.
///
/// 128 bits: enough that a collision within the verifier's replay window is
/// not a practical concern, short enough to stay well inside an `sf-string`.
const NONCE_BYTES: usize = 16;

/// A fresh value for the `nonce` signature parameter.
///
/// The bytes come from the operating system. The encoding is base64url without
/// padding, which is printable ASCII and so always a valid `sf-string`
/// (RFC 9651 §3.3.3).
///
/// RFC 9635 §7.3.1-S13: "The signer SHOULD include the nonce parameter with a
/// unique and unguessable value." `created` alone leaves a signed request
/// replayable for as long as the verifier's clock window lasts; a nonce the
/// verifier remembers (§7.3.1-M14) closes that window to a single use.
///
/// # Errors
///
/// Fails when the operating system provides no randomness; a nonce that is
/// not random is worse than none, so nothing is made up in its place.
pub fn fresh_nonce() -> Result<String, ProofError> {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| {
        ProofError::Signing(format!("no OS randomness for the signature nonce: {e}"))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The message the base is built from, reduced to what GNAP covers.
#[derive(Debug, Clone, Default)]
pub struct Message<'a> {
    /// The HTTP method.
    pub method: &'a str,
    /// The full request URI.
    pub target_uri: &'a str,
    /// The `Content-Digest` field value, when the message has content.
    pub content_digest: Option<&'a str>,
    /// The `Authorization` field value, when the request carries a token.
    pub authorization: Option<&'a str>,
    /// Any other covered field, keyed by its serialized identifier.
    ///
    /// Used in particular for rotation components, where the key is the full
    /// serialized identifier, for example `"signature";key="old-key"`.
    pub other: Vec<(String, String)>,
}

impl Message<'_> {
    /// Fills `other` with every ordinary header field the signature covers.
    ///
    /// §7.3.1 names the components a GNAP signature MUST cover; it does not
    /// forbid covering more, and RFC 9421 lets a signer add any field it likes.
    /// A verifier that builds the base from the four named fields alone would
    /// refuse such a signature for a component "missing from the message" when
    /// the message carries it perfectly well.
    ///
    /// `header_values` returns every instance of a field, in message order.
    /// RFC 9421 §2.1 is applied to them: each value stripped of leading and
    /// trailing whitespace, and the instances "combined by concatenating the
    /// values using a single comma and a single space as a separator". A field
    /// that is covered but has no instance is left out, so that the base then
    /// fails on it as §2.5 requires. An instance with an empty value is still an
    /// instance: RFC 9421 §2.1 admits an empty field value, and the component
    /// line is then `"name": ` with nothing after it.
    ///
    /// Dictionary members (`"signature";key="…"`) are not read here: they need a
    /// Structured Field parser, and GNAP uses them only for the key rotation of
    /// §7.3.1.1.
    #[must_use]
    pub fn with_fields<'h, I>(
        mut self,
        components: &[Component],
        header_values: impl Fn(&str) -> I,
    ) -> Self
    where
        I: IntoIterator<Item = &'h str>,
    {
        for c in components {
            if let Component::Field(name) = c {
                let instances = header_values(name)
                    .into_iter()
                    .map(|v| v.trim_matches([' ', '\t']))
                    .collect::<Vec<_>>();
                if !instances.is_empty() {
                    self.other.push((c.identifier(), instances.join(", ")));
                }
            }
        }
        self
    }

    /// Resolves covered Dictionary members from the received field instances.
    ///
    /// Instances are combined in message order. RFC 9421 §2.1.2 requires the
    /// selected Item or Inner List to be serialized canonically, without its
    /// Dictionary key. In particular, the old signature's covered input during
    /// key rotation is not necessarily its original wire representation.
    /// Ordinary fields are still populated by [`Self::with_fields`].
    ///
    /// # Errors
    /// Returns an error for an absent field/member or an invalid Dictionary.
    pub fn with_dictionary_fields<'h, I>(
        mut self,
        components: &[Component],
        header_values: impl Fn(&str) -> I,
    ) -> Result<Self, ProofError>
    where
        I: IntoIterator<Item = &'h str>,
    {
        for component in components {
            let Component::DictionaryMember { field, key } = component else {
                continue;
            };
            let combined = header_values(field)
                .into_iter()
                .map(|value| value.trim_matches([' ', '\t']))
                .collect::<Vec<_>>()
                .join(", ");
            let dictionary: sfv::Dictionary =
                sfv::Parser::new(&combined).parse().map_err(|error| {
                    ProofError::Base(format!("invalid {field} Dictionary: {error}"))
                })?;
            let member = dictionary.get(key.as_str()).ok_or_else(|| {
                ProofError::Base(format!("{field} has no Dictionary member {key}"))
            })?;
            // A one-member List serializes precisely the Item or Inner List,
            // including its parameters, without a Dictionary key or comma.
            let mut serializer = sfv::ListSerializer::new();
            serializer.members([member]);
            let value = serializer.finish().ok_or_else(|| {
                ProofError::Base("a covered Dictionary member could not be serialized".into())
            })?;
            self.other.push((component.identifier(), value));
        }
        Ok(self)
    }

    fn value_of(&self, c: &Component) -> Result<String, ProofError> {
        let missing = |what: &str, why: &str| {
            ProofError::Base(format!(
                "{what} is covered by the signature but missing from the message; {why}"
            ))
        };
        Ok(match c {
            Component::Method => self.method.to_owned(),
            Component::TargetUri => self.target_uri.to_owned(),
            Component::ContentDigest => self
                .content_digest
                .ok_or_else(|| {
                    missing(
                        "content-digest",
                        "§7.3.1 requires it as soon as the request has content",
                    )
                })?
                .to_owned(),
            Component::Authorization => self
                .authorization
                .ok_or_else(|| {
                    missing(
                        "authorization",
                        "§7.3.1 requires it as soon as the request is bound to a token",
                    )
                })?
                .to_owned(),
            other => {
                let id = other.identifier();
                self.other
                    .iter()
                    .find(|(k, _)| *k == id)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| missing(&id, "it must be present in `other`"))?
            }
        })
    }
}

/// Builds the signature base (RFC 9421 §2.5).
///
/// `raw_params` is the `Signature-Input` value: the one produced by
/// [`SignatureInput::serialize`] when sending, the one received from the wire
/// when verifying. Either way it enters the base without being re-serialized.
/// # Errors
///
/// Fails when a covered component is missing from the message, or when a
/// component line is not one RFC 9421 admits.
pub fn signature_base(
    message: &Message<'_>,
    components: &[Component],
    raw_params: &str,
) -> Result<String, ProofError> {
    let mut base = String::new();
    let mut seen: Vec<String> = Vec::with_capacity(components.len());

    for c in components {
        let identifier = c.identifier();

        // §2.5 step 2.1 — "If the component identifier (including its
        // parameters) has already been added to the signature base, produce an
        // error." A repeated component is also how §7.5.7 describes padding a
        // signature base.
        if seen.contains(&identifier) {
            return Err(ProofError::Base(format!(
                "{identifier} is covered twice; a component identifier MUST occur only \
                 once in a signature base (RFC 9421 §2.5)"
            )));
        }
        seen.push(identifier.clone());

        let line = format!("{identifier}: {}", message.value_of(c)?);
        // Let the crate validate the line: it carries RFC 9421's
        // canonicalization rules.
        HttpMessageComponent::try_from(line.as_str())
            .map_err(|e| ProofError::Base(format!("{line:?} : {e:?}")))?;
        base.push_str(&line);
        base.push('\n');
    }

    base.push_str("\"@signature-params\": ");
    base.push_str(raw_params);

    // §2.5 step 4 — "Produce an error if the output string contains any
    // non-ASCII characters."
    if let Some(c) = base.chars().find(|c| !c.is_ascii()) {
        return Err(ProofError::Base(format!(
            "the signature base contains the non-ASCII character {c:?}; RFC 9421 §2.5 \
             requires it to be ASCII"
        )));
    }

    Ok(base)
}

/// Signs a GNAP request and returns `(Signature-Input, Signature)`.
///
/// The values are the field contents, prefixed with the signature label.
/// # Errors
///
/// Fails when the GNAP coverage requirements are not met (§7.3.1), when the
/// base cannot be built, or when the signer refuses.
pub fn sign(
    message: &Message<'_>,
    input: &SignatureInput,
    signer: &impl Signer,
    label: &str,
) -> Result<(String, String), ProofError> {
    check_gnap_requirements(input, message)?;
    let raw = input.serialize()?;
    let base = signature_base(message, &input.components, &raw)?;
    let sig = signer.sign(base.as_bytes())?;
    Ok((
        format!("{label}={raw}"),
        format!("{label}=:{}:", STANDARD.encode(sig)),
    ))
}

/// Verifies a received signature.
///
/// `raw_params` must be the exact value read from the message's
/// `Signature-Input`, without the label: that is what enters the base.
/// # Errors
///
/// Fails when the base cannot be rebuilt, or when the signature does not
/// match the key.
pub fn verify(
    message: &Message<'_>,
    components: &[Component],
    raw_params: &str,
    signature: &[u8],
    verifier: &impl Verifier,
) -> Result<(), ProofError> {
    let base = signature_base(message, components, raw_params)?;
    verifier.verify(base.as_bytes(), signature)
}

/// Checks the requirements GNAP adds on top of RFC 9421 (§7.3.1).
/// # Errors
///
/// Fails when a component §7.3.1 requires is not covered, or when `keyid` is
/// empty.
pub fn check_gnap_requirements(
    input: &SignatureInput,
    message: &Message<'_>,
) -> Result<(), ProofError> {
    let has = |c: &Component| input.components.contains(c);

    for required in [Component::Method, Component::TargetUri] {
        if !has(&required) {
            return Err(ProofError::Coverage(format!(
                "{} must be covered: \"covered components of the signature MUST \
                 include the following: @method, @target-uri\" (RFC 9635 §7.3.1)",
                required.identifier()
            )));
        }
    }

    if message.content_digest.is_some() && !has(&Component::ContentDigest) {
        return Err(ProofError::Coverage(
            "the message has content: `content-digest` MUST be covered \
             (RFC 9635 §7.3.1)"
                .into(),
        ));
    }

    if message.authorization.is_some() && !has(&Component::Authorization) {
        return Err(ProofError::Coverage(
            "the request carries a token: `authorization` MUST be covered \
             (RFC 9635 §7.3.1)"
                .into(),
        ));
    }

    if input.keyid.is_empty() {
        return Err(ProofError::Coverage(
            "`keyid` is empty; when the key is a JWK it MUST be its `kid` \
             (RFC 9635 §7.3.1)"
                .into(),
        ));
    }

    Ok(())
}
