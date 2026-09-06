//! Signed subject assertions carried by GNAP (RFC 9635 §§3.4 and 11.30).
//!
//! This is a PS256 ID Token profile, not an OpenID Provider or a JWT access-token
//! validator. The caller supplies the trusted issuer key, intended audience and
//! expected session nonce. No received key or URL can initiate key resolution.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gnap_crypto::{Ps256Signer, Ps256Verifier, Signer, Verifier};
use gnap_registry::AssertionFormat;
use gnap_types::user::Assertion;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use std::fmt;

/// Maximum compact assertion size, checked before decoding or verification.
pub const MAX_ASSERTION_BYTES: usize = 8192;

/// Redacted reasons an assertion cannot be issued or accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionError {
    /// Invalid issuer configuration or validation expectations.
    Configuration,
    /// Unsupported format, malformed JSON/base64 or excessive input size.
    Format,
    /// The JOSE header is incompatible with the pinned PS256 key.
    Header,
    /// The cryptographic signature could not be produced or verified.
    Signature,
    /// Required claims are missing, malformed or internally inconsistent.
    Claims,
    /// The assertion names another issuer or audience.
    Recipient,
    /// The assertion is not bound to the expected client session.
    Nonce,
    /// The assertion is expired, too old, not yet valid or excessively long-lived.
    Time,
    /// Missing session binding, wrong AS attribution or inconsistent subject data.
    Context,
}

impl fmt::Display for AssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid assertion trust configuration",
            Self::Format => "unsupported or malformed assertion",
            Self::Header => "assertion header does not match the trusted key profile",
            Self::Signature => "assertion signature failed",
            Self::Claims => "invalid assertion claims",
            Self::Recipient => "assertion issuer or audience mismatch",
            Self::Nonce => "assertion session nonce mismatch",
            Self::Time => "assertion outside the accepted time window",
            Self::Context => "assertion is not bound to this GNAP subject response",
        })
    }
}

impl std::error::Error for AssertionError {}

/// Out-of-band issuer trust for one exact GNAP grant endpoint.
///
/// Construct this from application configuration, never from a grant response
/// or JWT header. Audience and nonce still come from the current client session.
pub struct Trust<'a> {
    /// Exact AS endpoint used by the client, including its path.
    pub as_endpoint: &'a str,
    /// Exact HTTPS ID Token issuer, not inferred from that endpoint.
    pub issuer: &'a str,
    /// Dedicated, pinned assertion verification key.
    pub key: &'a Ps256Verifier,
    /// Maximum assertion lifetime and age, in seconds.
    pub max_age: u64,
    /// Accepted clock difference, at most 300 seconds.
    pub clock_skew: u64,
}

impl Trust<'_> {
    /// Verify the sole ID Token in a subject response, preserving AS attribution.
    ///
    /// Any `iss_sub` identifier must equal the verified identity. Other subject
    /// formats cannot be authenticated by this profile and are not returned.
    ///
    /// # Errors
    /// Refuses missing or multiple assertions, attribution/identifier conflicts,
    /// or an assertion that fails the pinned cryptographic and claim checks.
    pub fn verify_subject(
        &self,
        response: &gnap_types::user::SubjectResponse,
        actual_endpoint: &str,
        audience: &str,
        nonce: &str,
        now: u64,
    ) -> Result<VerifiedIdentity, AssertionError> {
        if self.as_endpoint != actual_endpoint || self.as_endpoint.is_empty() {
            return Err(AssertionError::Context);
        }
        let assertions = response
            .assertions
            .as_deref()
            .ok_or(AssertionError::Context)?;
        let [assertion] = assertions else {
            return Err(AssertionError::Context);
        };
        let identity = verify(
            assertion,
            self.key,
            &Expectations {
                issuer: self.issuer,
                audience,
                nonce,
                now,
                max_age: self.max_age,
                clock_skew: self.clock_skew,
            },
        )?;
        for id in response
            .sub_ids
            .iter()
            .flatten()
            .filter(|id| id.format == "iss_sub")
        {
            if id.issuer_subject() != Some((identity.issuer(), identity.subject())) {
                return Err(AssertionError::Context);
            }
        }
        Ok(identity)
    }
}

/// Claims supplied by an issuer after it authenticates the subject and permits release.
pub struct Issuance<'a> {
    /// Exact HTTPS issuer identifier, without query, fragment or userinfo.
    pub issuer: &'a str,
    /// Locally unique subject identifier, at most 255 ASCII characters.
    pub subject: &'a str,
    /// Client identifier agreed with the intended recipient.
    pub audience: &'a str,
    /// The recipient's nonce for this particular session, copied unchanged.
    pub nonce: &'a str,
    /// Authentication time, in integral Unix seconds.
    pub authenticated_at: u64,
    /// Issuance time, in integral Unix seconds.
    pub issued_at: u64,
    /// Exclusive expiration time, in integral Unix seconds.
    pub expires_at: u64,
}

/// Trusted expectations, never inferred from the received assertion.
pub struct Expectations<'a> {
    /// Exact issuer identifier configured for the GNAP AS.
    pub issuer: &'a str,
    /// The client's agreed audience identifier.
    pub audience: &'a str,
    /// The nonce retained by this client session.
    pub nonce: &'a str,
    /// Current integral Unix time from the caller's trusted clock.
    pub now: u64,
    /// Maximum assertion age and issued lifetime, in seconds; must be nonzero.
    pub max_age: u64,
    /// Accepted clock skew in seconds, bounded to at most 300.
    pub clock_skew: u64,
}

/// Identity claims accepted under one explicitly trusted issuer key.
///
/// No raw assertion, nonce or unknown claim is exposed by this type. The caller
/// must still retain the GNAP AS attribution and enforce its application policy.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    issuer: String,
    subject: String,
    authenticated_at: u64,
    issued_at: u64,
    expires_at: u64,
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedIdentity").finish_non_exhaustive()
    }
}

impl VerifiedIdentity {
    /// Exact issuer under which the subject identifier has meaning.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verified subject identifier; not a contact address or access credential.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Authentication time asserted by this issuer.
    #[must_use]
    pub const fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    /// Time this assertion was issued.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Assertion expiration, not the lifetime of an application login session.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Sign a compact ID Token using a dedicated, explicitly selected PS256 key.
///
/// This does not decide whether a subject is authenticated or whether GNAP may
/// release its identity. Those decisions belong to the AS policy.
///
/// # Errors
/// Returns a redacted error for invalid claims, excessive size or signing failure.
pub fn issue(signer: &Ps256Signer, input: &Issuance<'_>) -> Result<Assertion, AssertionError> {
    if !valid_issuer(input.issuer)
        || !(2048..=4096).contains(&signer.modulus_bits())
        || !bounded(input.audience, 1024)
        || !bounded(input.nonce, 512)
        || !bounded(signer.key_id(), 1024)
    {
        return Err(AssertionError::Configuration);
    }
    if !valid_subject(input.subject)
        || input.authenticated_at > input.issued_at
        || input.expires_at <= input.issued_at
    {
        return Err(AssertionError::Claims);
    }
    let header = json!({"alg":"PS256", "typ":"JWT", "kid":signer.key_id()});
    let payload = json!({"iss":input.issuer, "sub":input.subject, "aud":input.audience,
        "nonce":input.nonce, "auth_time":input.authenticated_at,
        "iat":input.issued_at, "exp":input.expires_at});
    let encode = |value: &Value| {
        serde_json::to_vec(value)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|_| AssertionError::Format)
    };
    let signing_input = format!("{}.{}", encode(&header)?, encode(&payload)?);
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|_| AssertionError::Signature)?;
    let value = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    if value.len() > MAX_ASSERTION_BYTES {
        return Err(AssertionError::Format);
    }
    Ok(Assertion {
        format: AssertionFormat::IdToken,
        value,
    })
}

/// Verify a PS256 ID Token against a pinned issuer key and session expectations.
///
/// Unknown claims are ignored. Other audiences, algorithms, JOSE key material,
/// critical extensions and unencoded payloads are not accepted by this profile.
/// Timestamp claims use integral Unix seconds. Validation never fetches keys.
///
/// # Errors
/// Returns a redacted error on any syntax, trust, signature, nonce or time failure.
pub fn verify(
    assertion: &Assertion,
    key: &Ps256Verifier,
    expected: &Expectations<'_>,
) -> Result<VerifiedIdentity, AssertionError> {
    if !valid_issuer(expected.issuer)
        || !(2048..=4096).contains(&key.modulus_bits())
        || !bounded(expected.audience, 1024)
        || !bounded(expected.nonce, 512)
        || expected.max_age == 0
        || expected.clock_skew > 300
    {
        return Err(AssertionError::Configuration);
    }
    if assertion.format != AssertionFormat::IdToken || assertion.value.len() > MAX_ASSERTION_BYTES {
        return Err(AssertionError::Format);
    }
    let mut parts = assertion.value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AssertionError::Format);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AssertionError::Format);
    }
    let header_fields = object(header)?;
    if string(&header_fields, "alg")? != "PS256"
        || ["crit", "b64", "jwk", "jku", "x5u", "x5c"]
            .iter()
            .any(|name| header_fields.contains_key(*name))
        || header_fields.get("typ").is_some_and(|v| {
            !v.as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case("JWT"))
        })
        || header_fields
            .get("kid")
            .is_some_and(|v| v.as_str().is_none() || key.expected_key_id() != v.as_str())
    {
        return Err(AssertionError::Header);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AssertionError::Format)?;
    let signed_len = header.len() + 1 + payload.len();
    key.verify(&assertion.value.as_bytes()[..signed_len], &signature)
        .map_err(|_| AssertionError::Signature)?;
    let claims = object(payload)?;
    let issuer = string(&claims, "iss")?;
    let subject = string(&claims, "sub")?;
    if !valid_subject(subject) {
        return Err(AssertionError::Claims);
    }
    let audience = claims.get("aud").ok_or(AssertionError::Claims)?;
    let intended = audience.as_str().map_or_else(
        || {
            audience.as_array().is_some_and(|items| {
                !items.is_empty() && items.iter().all(|v| v.as_str() == Some(expected.audience))
            })
        },
        |value| value == expected.audience,
    );
    if issuer != expected.issuer
        || !intended
        || claims
            .get("azp")
            .is_some_and(|v| v.as_str() != Some(expected.audience))
    {
        return Err(AssertionError::Recipient);
    }
    if string(&claims, "nonce")? != expected.nonce {
        return Err(AssertionError::Nonce);
    }
    let issued_at = integer(&claims, "iat")?;
    let expires_at = integer(&claims, "exp")?;
    let authenticated_at = integer(&claims, "auth_time")?;
    if authenticated_at > issued_at || expires_at <= issued_at {
        return Err(AssertionError::Claims);
    }
    let latest = u128::from(expected.now) + u128::from(expected.clock_skew);
    if u128::from(issued_at) > latest
        || expected.now.saturating_sub(expected.clock_skew) >= expires_at
        || expires_at - issued_at > expected.max_age
        || u128::from(expected.now)
            >= u128::from(issued_at)
                + u128::from(expected.max_age)
                + u128::from(expected.clock_skew)
    {
        return Err(AssertionError::Time);
    }
    if claims.contains_key("nbf") && u128::from(integer(&claims, "nbf")?) > latest {
        return Err(AssertionError::Time);
    }
    Ok(VerifiedIdentity {
        issuer: issuer.into(),
        subject: subject.into(),
        authenticated_at,
        issued_at,
        expires_at,
    })
}

const fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}
const fn valid_subject(value: &str) -> bool {
    bounded(value, 255) && value.is_ascii()
}
fn valid_issuer(value: &str) -> bool {
    bounded(value, 2048)
        && gnap_types::uri::is_absolute(value)
        && !value.contains(['?', '#'])
        && value.strip_prefix("https://").is_some_and(|rest| {
            let authority = rest.split('/').next().unwrap_or_default();
            !authority.is_empty() && !authority.contains('@')
        })
}
fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, AssertionError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(AssertionError::Claims)
}
fn integer(object: &Map<String, Value>, name: &str) -> Result<u64, AssertionError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(AssertionError::Claims)
}
fn object(encoded: &str) -> Result<Map<String, Value>, AssertionError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AssertionError::Format)?;
    serde_json::from_slice::<UniqueObject>(&bytes)
        .map(|value| value.0)
        .map_err(|_| AssertionError::Format)
}

struct UniqueObject(Map<String, Value>);
impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueObject;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique member names")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut object = Map::new();
                while let Some((name, value)) = input.next_entry::<String, Value>()? {
                    if object.insert(name, value).is_some() {
                        return Err(A::Error::custom("duplicate assertion member"));
                    }
                }
                Ok(UniqueObject(object))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
