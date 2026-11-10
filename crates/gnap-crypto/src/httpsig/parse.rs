//! Reading received signature fields: the Structured Field syntax of RFC 9651
//! that `Signature-Input` and `Signature` use (RFC 9421 §4).

use super::Component;
use crate::proof::ProofError;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::{Engine as _, alphabet};

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
pub(super) fn parse_sf_string(name: &str, value: &str) -> Result<String, ProofError> {
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
pub(super) fn split_identifiers(inner: &str) -> Vec<String> {
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

pub(super) fn parse_identifier(token: &str) -> Result<Component, ProofError> {
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
pub(super) fn split_params(section: &str) -> Result<Vec<&str>, ProofError> {
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
pub(super) const SF_INTEGER_DIGITS: usize = 15;

/// Reads an `sf-integer` (RFC 9651 §3.3.1), as `created` has to be.
///
/// The grammar is `["-"] 1*15DIGIT`, so a longer run of digits is not a large
/// integer but a malformed field.
pub(super) fn parse_sf_integer(name: &str, value: &str) -> Result<u64, ProofError> {
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
pub(super) fn validate_key(name: &str) -> Result<(), ProofError> {
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
pub(super) fn validate_bare_item(name: &str, value: &str) -> Result<(), ProofError> {
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
pub(super) fn validate_number(value: &str) -> Option<()> {
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
pub(super) fn validate_display_string(value: &str) -> Option<()> {
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
pub(super) fn split_outside_quotes(s: &str, needle: char) -> Option<(&str, &str)> {
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
pub(super) fn split_dictionary(field: &str) -> Result<Vec<(String, String)>, ProofError> {
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
                )));
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
                )));
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
