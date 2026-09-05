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
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD,
};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine as _};
use core::fmt;
use core::fmt::Write as _;
use httpsig::prelude::message_component::HttpMessageComponent;

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
    getrandom::getrandom(&mut bytes).map_err(|e| {
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

/// Reads the covered component list out of a received `Signature-Input`.
///
/// A verifier needs this: the base is rebuilt from the components the sender
/// declared, and they arrive as an Inner List at the head of the value —
/// `("@method" "@target-uri" "content-digest");created=…`.
///
/// ```
/// use gnap_crypto::httpsig::{parse_covered_components, Component};
///
/// let raw = r#"("@method" "signature";key="old-key");created=1;keyid="k";tag="gnap""#;
/// let components = parse_covered_components(raw).unwrap();
/// assert_eq!(components[0], Component::Method);
/// assert_eq!(
///     components[1],
///     Component::DictionaryMember { field: "signature".into(), key: "old-key".into() }
/// );
/// ```
/// # Errors
///
/// Fails when the value does not open with an inner list, or when an
/// identifier carries a parameter other than `key`.
pub fn parse_covered_components(raw_params: &str) -> Result<Vec<Component>, ProofError> {
    let inner = raw_params
        .strip_prefix('(')
        .and_then(|s| split_outside_quotes(s, ')'))
        .map(|(list, _)| list)
        .ok_or_else(|| {
            ProofError::Base(format!(
                "`{raw_params}`: expected an inner list `( … )` at the head of the \
                 Signature-Input value (RFC 9421 §2.3)"
            ))
        })?;

    let mut components = Vec::new();
    for token in split_identifiers(inner) {
        components.push(parse_identifier(&token)?);
    }
    Ok(components)
}

/// Reads an `sf-string` and returns what it holds (RFC 9651 §4.2.5).
///
/// The value must be quoted; inside the quotes only printable ASCII is allowed,
/// and a backslash escapes nothing but a backslash or a double quote. Trimming
/// quotes off instead would let `keyid=42` or `tag=gnap` through as if they
/// were strings, and would silently keep the backslashes of an escaped value.
fn parse_sf_string(name: &str, value: &str) -> Result<String, ProofError> {
    let malformed = || {
        ProofError::Base(format!(
            "`{name}={value}`: expected a quoted string whose only escapes are \\\\ and \\\" \
             (RFC 9651 §4.2.5)"
        ))
    };

    let inner = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(malformed)?;

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(escaped @ ('\\' | '"')) => out.push(escaped),
                _ => return Err(malformed()),
            },
            '"' => return Err(malformed()),
            '\x20'..='\x7e' => out.push(c),
            _ => return Err(malformed()),
        }
    }
    Ok(out)
}

/// Splits an inner list on the spaces that sit outside quoted strings.
fn split_identifiers(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for c in inner.chars() {
        match c {
            _ if escaped => {
                current.push(c);
                escaped = false;
            }
            '\\' if in_quotes => {
                current.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn parse_identifier(token: &str) -> Result<Component, ProofError> {
    fn malformed(token: &str) -> ProofError {
        ProofError::Base(format!(
            "`{token}`: a component identifier is a quoted name, optionally followed \
             by parameters (RFC 9421 §2.5)"
        ))
    }

    let rest = token.strip_prefix('"').ok_or_else(|| malformed(token))?;
    let (name, params) = rest.split_once('"').ok_or_else(|| malformed(token))?;

    if params.is_empty() {
        return Ok(match name {
            "@method" => Component::Method,
            "@target-uri" => Component::TargetUri,
            "content-digest" => Component::ContentDigest,
            "authorization" => Component::Authorization,
            other => Component::Field(other.to_ascii_lowercase()),
        });
    }

    // The only parameterized form GNAP uses is a Dictionary member (§7.3.1.1).
    let key = params.strip_prefix(";key=").ok_or_else(|| {
        ProofError::Base(format!(
            "`{token}`: the only component parameter GNAP uses is `key` \
             (RFC 9635 §7.3.1.1)"
        ))
    })?;

    Ok(Component::DictionaryMember {
        field: name.to_ascii_lowercase(),
        key: parse_sf_string("key", key)?,
    })
}

/// The signature parameters read back out of a received `Signature-Input`.
///
/// A verifier cannot work from a substring search: §7.3.1 places requirements on
/// `created`, `nonce` and `alg`, and each has to be found as an actual
/// parameter rather than as text that happens to appear in the value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceivedParams {
    /// The `created` timestamp, in seconds since the Unix epoch.
    pub created: Option<u64>,
    /// The `keyid` parameter.
    pub keyid: Option<String>,
    /// The `nonce` parameter.
    pub nonce: Option<String>,
    /// The `tag` parameter.
    pub tag: Option<String>,
    /// The `alg` parameter, which GNAP forbids (§7.3.1).
    pub alg: Option<String>,
    /// The `expires` timestamp, in seconds since the Unix epoch.
    ///
    /// RFC 9421 §2.3 defines it and §3.1 calls it "a hint to the verifier";
    /// GNAP places no requirement on it. It is read here, typed, so that a
    /// verifier that chooses to honour it — which RFC 9421 §3.2.1 lists among
    /// the things an application may require — does not have to parse it
    /// again.
    pub expires: Option<u64>,
}

/// Reads the parameters that follow the covered component list.
///
/// The parameters are typed: RFC 9421 §2.3 makes `created` and `expires`
/// Integers and `keyid`, `nonce`, `tag` and `alg` Strings. A verifier that accepts
/// `tag=gnap` unquoted, or that keeps the backslashes of an escaped `keyid`,
/// is not reading the same value the signer signed.
///
/// A parameter that appears twice keeps its last value, as RFC 9651 §4.2.3.2
/// specifies for parameter parsing.
///
/// # Errors
///
/// Fails when the value does not open with an inner list, when the parameter
/// section is not well formed, or when one of the six parameters above carries
/// a value of the wrong type.
pub fn parse_signature_params(raw_params: &str) -> Result<ReceivedParams, ProofError> {
    let tail = raw_params
        .strip_prefix('(')
        .and_then(|s| split_outside_quotes(s, ')'))
        .map(|(_, tail)| tail)
        .ok_or_else(|| {
            ProofError::Base(format!(
                "`{raw_params}`: expected an inner list `( … )` at the head of the \
                 Signature-Input value (RFC 9421 §2.3)"
            ))
        })?;

    let mut out = ReceivedParams::default();
    for item in split_params(tail)? {
        // A parameter with no `=` is the Boolean true (RFC 9651 §4.2.3.2). None
        // of the six parameters below is a Boolean, so the bare form is a type
        // error for them and something to ignore for anything else.
        let Some((name, value)) = item.split_once('=') else {
            if matches!(
                item,
                "created" | "expires" | "keyid" | "nonce" | "tag" | "alg"
            ) {
                return Err(ProofError::Base(format!(
                    "`{item}` is present as a Boolean; RFC 9421 §2.3 gives it a value"
                )));
            }
            // A Boolean is still a parameter, and its name is still an sf-key.
            validate_key(item)?;
            continue;
        };

        match name {
            "created" => out.created = Some(parse_sf_integer(name, value)?),
            "expires" => out.expires = Some(parse_sf_integer(name, value)?),
            "keyid" => out.keyid = Some(parse_sf_string(name, value)?),
            "nonce" => out.nonce = Some(parse_sf_string(name, value)?),
            "tag" => out.tag = Some(parse_sf_string(name, value)?),
            "alg" => out.alg = Some(parse_sf_string(name, value)?),
            // An unknown parameter is allowed — GNAP is extensible — but
            // Signature-Input is a Structured Field, and a field that does not
            // parse is not a field. Skipping over a parameter it cannot read
            // would leave the verifier accepting a message it never understood.
            _ => {
                validate_key(name)?;
                validate_bare_item(name, value)?;
            }
        }
    }
    Ok(out)
}

/// Checks that a parameters section — what follows an item, `;a=1;b="x"` — is
/// well formed (RFC 9651 §3.1.2): every name an `sf-key`, every value a bare
/// item. What the parameters mean is the caller's business; whether the field
/// parses is not.
pub(crate) fn validate_parameters(section: &str) -> Result<(), ProofError> {
    for item in split_params(section)? {
        match item.split_once('=') {
            None => validate_key(item)?,
            Some((name, value)) => {
                validate_key(name)?;
                validate_bare_item(name, value)?;
            }
        }
    }
    Ok(())
}

/// Splits `;a=1;b="x;y"` into its parameter items, quotes respected.
fn split_params(section: &str) -> Result<Vec<&str>, ProofError> {
    let mut items = Vec::new();
    let mut rest = section;
    while !rest.is_empty() {
        let stripped = rest.strip_prefix(';').ok_or_else(|| {
            ProofError::Base(format!(
                "`{rest}`: a signature parameter opens with `;` (RFC 9651 §4.2.3)"
            ))
        })?;
        // The remainder keeps its separator, so the next turn sees a `;`.
        let item = split_outside_quotes(stripped, ';').map_or(stripped, |(head, _)| head);
        items.push(item);
        rest = &stripped[item.len()..];
    }
    Ok(items)
}

/// Decodes a Structured Fields Byte Sequence (RFC 9651 §4.2.7).
///
/// §4.2.7 decodes "synthesizing padding if necessary", and adds that parsers
/// "SHOULD NOT fail when `=` padding is not present". A signature refused for
/// its padding is a signature refused for nothing.
pub(crate) const SF_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The number of digits an `sf-integer` may carry (RFC 9651 §3.3.1).
const SF_INTEGER_DIGITS: usize = 15;

/// Reads an `sf-integer` (RFC 9651 §3.3.1), as `created` has to be.
///
/// The grammar is `["-"] 1*15DIGIT`, so a longer run of digits is not a large
/// integer but a malformed field.
fn parse_sf_integer(name: &str, value: &str) -> Result<u64, ProofError> {
    let invalid = |why: &str| {
        ProofError::Base(format!(
            "`{name}={value}`: {why}; expected an integer of at most \
             {SF_INTEGER_DIGITS} digits (RFC 9651 §3.3.1)"
        ))
    };
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("not an integer"));
    }
    if digits.len() > SF_INTEGER_DIGITS {
        return Err(invalid("too many digits"));
    }
    value
        .parse()
        .map_err(|_| invalid("a signature cannot have been created before the Unix epoch"))
}

/// Checks that a parameter name is an `sf-key` (RFC 9651 §3.1.2).
fn validate_key(name: &str) -> Result<(), ProofError> {
    let head_ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '*');
    let rest_ok = name.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'*')
    });
    if head_ok && rest_ok {
        Ok(())
    } else {
        Err(ProofError::Base(format!(
            "`{name}` is not a valid parameter name (RFC 9651 §3.1.2)"
        )))
    }
}

/// Checks that a parameter value is a well-formed bare item (RFC 9651 §3.3).
///
/// Only the shape is checked: what an unknown parameter means is not this
/// library's business, but whether the field parses at all is.
fn validate_bare_item(name: &str, value: &str) -> Result<(), ProofError> {
    let invalid = || {
        ProofError::Base(format!(
            "`{name}={value}`: not a Structured Fields item (RFC 9651 §3.3)"
        ))
    };

    match value.chars().next().ok_or_else(invalid)? {
        // §3.3.3 String, and §3.3.8 Display String, which is one with a `%`
        // sigil and percent-encoded bytes.
        '"' => parse_sf_string(name, value).map(|_| ()),
        '%' => validate_display_string(value).ok_or_else(invalid),
        // §3.3.5 Byte Sequence. §4.2.7 requires the base64 to decode, not
        // merely to be spelled with base64 characters.
        ':' => value
            .strip_prefix(':')
            .and_then(|v| v.strip_suffix(':'))
            .filter(|v| {
                v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            })
            .and_then(|v| SF_BASE64.decode(v).ok())
            .map(|_| ())
            .ok_or_else(invalid),
        // §3.3.6 Boolean.
        '?' => (value == "?0" || value == "?1")
            .then_some(())
            .ok_or_else(invalid),
        // §3.3.7 Date: an integer with an `@` sigil.
        '@' => parse_sf_integer(name, &value[1..]).map(|_| ()),
        // §3.3.1 Integer and §3.3.2 Decimal.
        '-' | '0'..='9' => validate_number(value).ok_or_else(invalid),
        // §3.3.4 Token.
        c if c.is_ascii_alphabetic() || c == '*' => value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":/!#$%&'*+-.^_`|~".contains(&b))
            .then_some(())
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

/// `["-"] 1*15DIGIT` or `["-"] 1*12DIGIT "." 1*3DIGIT` (RFC 9651 §3.3.1, §3.3.2).
fn validate_number(value: &str) -> Option<()> {
    let body = value.strip_prefix('-').unwrap_or(value);
    let (integral, fractional) = body
        .split_once('.')
        .map_or((body, None), |(i, f)| (i, Some(f)));

    let digits = |v: &str, max: usize| {
        !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_digit())
    };
    fractional.map_or_else(
        || digits(integral, SF_INTEGER_DIGITS).then_some(()),
        |f| (digits(integral, 12) && digits(f, 3)).then_some(()),
    )
}

/// A Display String: `%"` then percent-encoded UTF-8 and a closing quote.
///
/// §4.2.10 decodes the percent escapes into bytes and requires the result to be
/// valid UTF-8. Checking the escapes without decoding would accept `%ff`, which
/// is not a character; refusing a literal backslash would reject a value the
/// §4.1.11 serializer produces, since it percent-encodes only `%` and `"`.
fn validate_display_string(value: &str) -> Option<()> {
    let inner = value.strip_prefix("%\"")?.strip_suffix('"')?;
    let mut decoded = Vec::with_capacity(inner.len());
    let mut bytes = inner.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let digit = |b: Option<u8>| match b {
                    Some(c @ b'0'..=b'9') => Some(c - b'0'),
                    // §4.2.10 accepts lowercase hexadecimal only.
                    Some(c @ b'a'..=b'f') => Some(c - b'a' + 10),
                    _ => None,
                };
                decoded.push(digit(bytes.next())? << 4 | digit(bytes.next())?);
            }
            b'"' => return None,
            0x20..=0x7e => decoded.push(b),
            _ => return None,
        }
    }
    String::from_utf8(decoded).ok().map(|_| ())
}

/// Splits at the first occurrence of `needle` that sits outside a quoted string.
fn split_outside_quotes(s: &str, needle: char) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            _ if c == needle && !in_quotes => return Some((&s[..i], &s[i + c.len_utf8()..])),
            _ => {}
        }
    }
    None
}

/// One labelled signature carried by a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelledSignature {
    /// The label the two fields share.
    pub label: String,
    /// The `Signature-Input` value for this label, verbatim.
    pub raw_params: String,
    /// The decoded signature bytes.
    pub signature: Vec<u8>,
}

/// Pairs up the `Signature-Input` and `Signature` fields of a message.
///
/// Both are Dictionary Structured Fields keyed by a label (RFC 9421 §4.1, §4.2).
/// A verifier has to examine every entry, not only the first: RFC 9635 §7.3.1
/// requires it to "examine all included signatures until it finds (at least) one
/// that is acceptable".
///
/// That is why one outcome is returned per label instead of a single result for
/// the message: a member whose `Signature` value is malformed, or which has no
/// counterpart at all, must not stop the verifier from reaching an acceptable
/// signature further down the dictionary. A caller iterates and keeps the last
/// reason to report if none is accepted.
///
/// The entries come back in `Signature-Input` order.
#[must_use]
pub fn parse_signatures(
    signature_input: &str,
    signature: &str,
) -> Vec<Result<LabelledSignature, ProofError>> {
    let (inputs, signatures) = match (
        split_dictionary(signature_input),
        split_dictionary(signature),
    ) {
        (Ok(inputs), Ok(signatures)) => (inputs, signatures),
        // Neither field is a Dictionary, so the message carries no signature
        // this verifier can name: one outcome, and it is a refusal.
        (Err(e), _) | (_, Err(e)) => return vec![Err(e)],
    };

    inputs
        .into_iter()
        .map(|(label, raw_params)| {
            // §4.1 — a Signature-Input member is an Inner List. A member of
            // another type is a valid Dictionary member and an invalid
            // signature, so it fails here, alone.
            if !raw_params.starts_with('(') {
                return Err(ProofError::Base(format!(
                    "the Signature-Input value for `{label}` is not an inner list \
                     (RFC 9421 §4.1)"
                )));
            }
            let Some((_, raw)) = signatures.iter().find(|(l, _)| *l == label) else {
                return Err(ProofError::Base(format!(
                    "`{label}` appears in Signature-Input with no Signature entry to \
                     verify (RFC 9421 §4.2)"
                )));
            };
            let encoded = raw
                .strip_prefix(':')
                .and_then(|s| s.strip_suffix(':'))
                .ok_or_else(|| {
                    ProofError::Base(format!(
                        "the Signature value for `{label}` is not a colon-delimited byte \
                         sequence (RFC 9421 §4.2)"
                    ))
                })?;
            let signature = SF_BASE64.decode(encoded).map_err(|_| {
                ProofError::Base(format!("the signature for `{label}` is not valid base64"))
            })?;
            Ok(LabelledSignature {
                label,
                raw_params,
                signature,
            })
        })
        .collect()
}

/// Splits a Dictionary field into its members, one per key (RFC 9651 §4.2.2).
///
/// A repeated key overwrites the earlier member, so a field naming `sig1`
/// twice denotes one `sig1`: the second. Matching the first instead would let a
/// verifier accept a signature that the field does not actually carry.
///
/// The member values are left to their own parsers, which is what keeps one
/// unreadable signature from condemning the others (§7.3.1). A caller that
/// needs every occurrence parsed — the Dictionary grammar does parse each
/// member's value, and `Content-Digest` is read that strictly — takes
/// [`dictionary_members`] instead and folds the duplicates itself.
///
/// # Errors
///
/// Fails when the field is not a Dictionary at all.
pub(crate) fn split_dictionary(field: &str) -> Result<Vec<(String, String)>, ProofError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (key, value) in dictionary_members(field)? {
        if let Some(existing) = out.iter_mut().find(|(k, _)| *k == key) {
            existing.1 = value;
        } else {
            out.push((key, value));
        }
    }
    Ok(out)
}

/// Every member of a Dictionary field, in order, duplicates included
/// (RFC 9651 §4.2.2).
///
/// The algorithm is the RFC's: a key, then either `=` and a value or nothing at
/// all, which makes the member the Boolean true. Whitespace is allowed after a
/// member and after a comma, and nowhere else — `sig1 =(…)` is not a
/// Dictionary. A trailing comma fails. A Boolean member is returned as `?1`,
/// and every value is returned as written, for the caller's parser.
///
/// # Errors
///
/// Fails when the field is not a Dictionary at all.
pub(crate) fn dictionary_members(field: &str) -> Result<Vec<(String, String)>, ProofError> {
    /// SP and HTAB, the OWS §4.2.2 discards between members.
    fn trim_ows(s: &str) -> &str {
        s.trim_start_matches([' ', '\t'])
    }

    let mut out: Vec<(String, String)> = Vec::new();
    let mut rest = trim_ows(field);

    while !rest.is_empty() {
        let (member, after) =
            split_outside_quotes(rest, ',').map_or((rest, None), |(head, tail)| (head, Some(tail)));

        // Step 2.6 discards OWS after the member, so it belongs to neither the
        // key nor the value.
        let member = member.trim_end_matches([' ', '\t']);
        let key_len = member
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.*".contains(b))
            .count();
        let (key, tail) = member.split_at(key_len);
        validate_key(key)?;

        // Step 2.2 and 2.3: `=` and a value, or the Boolean true with whatever
        // parameters follow it.
        let value = match tail.strip_prefix('=') {
            Some("") => {
                return Err(ProofError::Base(format!(
                    "the Dictionary member `{key}` has no value (RFC 9651 §4.2.2)"
                )))
            }
            Some(value) => value.to_owned(),
            // The Boolean form takes only its parameters. Anything else here —
            // a space before the `=`, for one — leaves the algorithm expecting
            // a comma and finding something else, which is a parse failure.
            None if tail.is_empty() || tail.starts_with(';') => format!("?1{tail}"),
            None => {
                return Err(ProofError::Base(format!(
                    "`{member}` is not a Dictionary member: a key is followed by `=` and a \
                     value, or by its parameters alone (RFC 9651 §4.2.2)"
                )))
            }
        };

        out.push((key.to_owned(), value));

        match after {
            // Step 2.7: the field ends after a member, which is well formed.
            None => rest = "",
            Some(after) => {
                // Step 2.10: nothing after the comma is a trailing comma.
                let after = trim_ows(after);
                if after.is_empty() {
                    return Err(ProofError::Base(
                        "the Dictionary ends with a trailing comma (RFC 9651 §4.2.2)".into(),
                    ));
                }
                rest = after;
            }
        }
    }
    Ok(out)
}
