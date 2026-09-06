//! Access tokens — RFC 9635 §2.1, §3.1 and §3.2.
//!
//! This is where the RFC's message-shape constraints concentrate, and where the
//! type system can enforce them:
//!
//! - the requested cardinality constrains the response's (§3.2.1, §3.2.2);
//! - a flag never appears twice (§2.1.1);
//! - a multiple request needs `label`s, present and unique (§2.1.2);
//! - a `bearer` token carries no `key` (§3.2.1).

use crate::access::AccessItem;
use crate::key::Key;
use gnap_registry::AccessTokenFlag;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;

/// The shape in which the tokens were requested.
///
/// §3.2.2 is explicit: a request made with an array gets an array back, "even
/// if only a single access token is granted". The shape therefore has to travel
/// from request to response, hence this marker in the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    /// An object: a single token requested (§2.1.1).
    Single,
    /// An array: several tokens requested (§2.1.2).
    Multiple,
}

/// The tokens the client asks for (§2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRequest {
    /// The shape used, to be mirrored in the response.
    pub cardinality: Cardinality,
    /// The tokens requested. Always at least one.
    pub tokens: Vec<TokenRequest>,
}

/// A request for one token (§2.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// The access rights requested. Required.
    pub access: Vec<AccessItem>,
    /// The name the client gives the token. Required in a multiple request.
    pub label: Option<String>,
    /// The token behaviours requested.
    pub flags: Vec<AccessTokenFlag>,
    /// Unrecognized fields retained so a deployment can reject unsupported constraints.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn check_unique_flags<E: de::Error>(flags: &[AccessTokenFlag]) -> Result<(), E> {
    let mut seen = HashSet::new();
    for f in flags {
        if !seen.insert(f.as_str()) {
            return Err(E::custom(format!(
                "access_token.flags: `{f}` appears more than once; \
                 a flag MUST NOT be repeated \
                 (RFC 9635 §2.1.1 -> invalid_flag)"
            )));
        }
    }
    Ok(())
}

impl<'de> Deserialize<'de> for TokenRequest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            access: Vec<AccessItem>,
            #[serde(default)]
            label: Option<String>,
            #[serde(default)]
            flags: Vec<AccessTokenFlag>,
            #[serde(flatten)]
            extra: serde_json::Map<String, serde_json::Value>,
        }
        let r = Raw::deserialize(d)?;
        check_unique_flags(&r.flags)?;
        Ok(Self {
            access: r.access,
            label: r.label,
            flags: r.flags,
            extra: r.extra,
        })
    }
}

impl Serialize for TokenRequest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("access", &self.access)?;
        if let Some(l) = &self.label {
            m.serialize_entry("label", l)?;
        }
        if !self.flags.is_empty() {
            m.serialize_entry("flags", &self.flags)?;
        }
        for (name, value) in &self.extra {
            if matches!(name.as_str(), "access" | "label" | "flags") {
                return Err(serde::ser::Error::custom(
                    "token request extension shadows a defined field",
                ));
            }
            m.serialize_entry(name, value)?;
        }
        m.end()
    }
}

impl Serialize for AccessTokenRequest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.cardinality {
            // An array stays an array, even with a single element.
            Cardinality::Multiple => self.tokens.serialize(s),
            Cardinality::Single => self.tokens.first().map_or_else(
                || {
                    Err(serde::ser::Error::custom(
                        "access_token: Single cardinality with no token",
                    ))
                },
                |t| t.serialize(s),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for AccessTokenRequest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = AccessTokenRequest;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "access_token: an object (single token), or an array of objects"
                )
            }

            fn visit_map<M: MapAccess<'de>>(self, m: M) -> Result<Self::Value, M::Error> {
                let t: TokenRequest =
                    Deserialize::deserialize(de::value::MapAccessDeserializer::new(m))?;
                Ok(AccessTokenRequest {
                    cardinality: Cardinality::Single,
                    tokens: vec![t],
                })
            }

            fn visit_seq<S: SeqAccess<'de>>(self, s: S) -> Result<Self::Value, S::Error> {
                let tokens: Vec<TokenRequest> =
                    Deserialize::deserialize(de::value::SeqAccessDeserializer::new(s))?;

                // §2.1.2: every entry MUST carry a label, and labels MUST be
                // unique within the request.
                let mut seen = HashSet::new();
                for (i, t) in tokens.iter().enumerate() {
                    match &t.label {
                        None => {
                            return Err(de::Error::custom(format!(
                                "access_token[{i}]: `label` is required for a multiple \
                                 token request (RFC 9635 §2.1.2 -> invalid_request)"
                            )))
                        }
                        Some(l) if !seen.insert(l.as_str()) => {
                            return Err(de::Error::custom(format!(
                                "access_token[{i}]: duplicate label `{l}`; labels MUST be \
                                 unique (RFC 9635 §2.1.2 -> invalid_request)"
                            )))
                        }
                        _ => {}
                    }
                }
                Ok(AccessTokenRequest {
                    cardinality: Cardinality::Multiple,
                    tokens,
                })
            }
        }
        d.deserialize_any(V)
    }
}

/// The value of an access token (§3.2.1).
///
/// Restricted to the `token68` character set of RFC 9110 §11.2, so it travels
/// in an HTTP header with no extra encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct TokenValue(String);

impl TokenValue {
    /// Builds the value after checking the character set.
    /// # Errors
    ///
    /// Fails when the value is empty or carries a character outside the
    /// `token68` set.
    pub fn new(v: impl Into<String>) -> Result<Self, TokenValueError> {
        let v = v.into();
        if v.is_empty() {
            return Err(TokenValueError::Empty);
        }
        // token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        let body_end = v.len() - v.chars().rev().take_while(|c| *c == '=').count();
        let (body, _pad) = v.split_at(body_end);
        if body.is_empty() {
            return Err(TokenValueError::Empty);
        }
        if let Some(c) = body.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/'))
        }) {
            return Err(TokenValueError::InvalidChar(c));
        }
        Ok(Self(v))
    }

    /// The value as it travels.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What prevents a string from being a token value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenValueError {
    /// The value is empty.
    Empty,
    /// A character outside the `token68` set.
    InvalidChar(char),
}

impl fmt::Display for TokenValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "access_token.value: cannot be empty"),
            Self::InvalidChar(c) => write!(
                f,
                "access_token.value: character `{c}` is outside the token68 set; \
                 the value MUST be limited to it (RFC 9635 §3.2.1)"
            ),
        }
    }
}

impl std::error::Error for TokenValueError {}

impl<'de> Deserialize<'de> for TokenValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(s).map_err(de::Error::custom)
    }
}

/// An access token issued by the AS (§3.2.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessToken {
    /// The value, opaque to the client.
    pub value: TokenValue,

    /// The label the client chose, when it gave one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub label: Option<String>,

    /// Access to this token's management API (§6).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub manage: Option<TokenManage>,

    /// The rights actually attached. May differ from what was requested.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access: Option<Vec<AccessItem>>,

    /// Remaining validity, in seconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in: Option<u64>,

    /// The key bound to the token, when different from the client's.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key: Option<Key>,

    /// The token's behaviours.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub flags: Vec<AccessTokenFlag>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Access to a token's management API (§3.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenManage {
    /// The management URI. Absolute, and contains no token value.
    pub uri: String,

    /// The token protecting this API. Bound to the client's key, never `bearer`.
    pub access_token: BoundToken,
}

impl TokenManage {
    /// Checks what §3.2.1 requires of a management API, given the token it
    /// manages.
    ///
    /// # Errors
    ///
    /// Fails when the URI is not absolute, when it carries either token value,
    /// or when the protecting token is the managed token itself.
    pub fn validate(&self, managed: &TokenValue) -> Result<(), AccessTokenError> {
        if !crate::uri::is_absolute(&self.uri) {
            return Err(AccessTokenError::ManageUriNotAbsolute(self.uri.clone()));
        }

        // §3.2.1 — "This URI MUST NOT include the value of the access token
        // being managed or the value of the access token used to protect the
        // URI." A URI travels through logs, referrers and browser history; a
        // token in one is a token given away.
        for (value, which) in [
            (managed, "the token it manages"),
            (&self.access_token.value, "the token that protects it"),
        ] {
            if self.uri.contains(value.as_str()) {
                return Err(AccessTokenError::ManageUriLeaksToken(which));
            }
        }

        if self.access_token.value == *managed {
            return Err(AccessTokenError::ManageTokenIsTheManagedToken);
        }
        Ok(())
    }
}

/// A token bound to the client's key, with no management of its own.
///
/// §3.1 and §3.2.1 place the same restrictions on continuation and management
/// tokens: bound to the client's key, never `bearer`, `key` omitted, no
/// `manage`. A distinct type makes those prohibitions structural rather than
/// declarative.
///
/// What the RFC forbids is the `bearer` flag, not the `flags` array: a
/// continuation token may perfectly well be `durable`, or carry a registered
/// extension flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundToken {
    /// The token value.
    pub value: TokenValue,

    /// The token's flags, never including `bearer`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub flags: Vec<AccessTokenFlag>,

    /// Extension fields, kept as they are.
    ///
    /// The fields §3.1 forbids never reach this map: they are refused while
    /// deserializing, which is what makes the prohibition structural instead of
    /// a rule every call site has to remember.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The fields §3.1 and §3.2.1 forbid outright on a bound token.
///
/// A `key` "MUST be omitted" and the token "MUST NOT have a manage field".
/// Neither name can be reused as an extension: both are registered.
const FORBIDDEN_ON_BOUND_TOKEN: [&str; 2] = ["key", "manage"];

impl BoundToken {
    /// A bound token with no flags and no extension fields.
    #[must_use]
    pub fn new(value: TokenValue) -> Self {
        Self {
            value,
            flags: Vec::new(),
            extra: serde_json::Map::default(),
        }
    }
}

impl<'de> Deserialize<'de> for BoundToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            value: TokenValue,
            #[serde(default)]
            flags: Vec<AccessTokenFlag>,
            #[serde(flatten)]
            extra: serde_json::Map<String, serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        for forbidden in FORBIDDEN_ON_BOUND_TOKEN {
            if raw.extra.contains_key(forbidden) {
                return Err(de::Error::custom(format!(
                    "a continuation or management access token carries `{forbidden}`: it is \
                     bound to the client's key and has no management of its own \
                     (RFC 9635 §3.1, §3.2.1)"
                )));
            }
        }
        if raw.flags.contains(&AccessTokenFlag::Bearer) {
            return Err(de::Error::custom(
                "a continuation or management access token carries the `bearer` flag: it \
                 MUST be bound to the client instance's key and MUST NOT be a bearer token \
                 (RFC 9635 §3.1, §3.2.1)",
            ));
        }
        if let Some(duplicate) = first_duplicate(&raw.flags) {
            return Err(de::Error::custom(format!(
                "access token flag `{duplicate}` appears more than once (RFC 9635 §3.2.1)"
            )));
        }
        Ok(Self {
            value: raw.value,
            flags: raw.flags,
            extra: raw.extra,
        })
    }
}

/// What makes an issued token invalid as the RFC defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessTokenError {
    /// The token carries both `bearer` and a `key` field (§3.2.1).
    BearerWithKey,
    /// A flag appears more than once (§3.2.1).
    DuplicateFlag(String),

    /// The token carries no `access`, which §3.2.1 makes REQUIRED.
    MissingAccess,

    /// The management URI is not an absolute URI (§3.2.1).
    ManageUriNotAbsolute(String),

    /// The management URI carries one of the two token values (§3.2.1).
    ///
    /// The string names which one: a URI is not a secret, and putting a token
    /// in one spreads it through logs, referrers and browser history.
    ManageUriLeaksToken(&'static str),

    /// The management token has the same value as the token it manages
    /// (§3.2.1).
    ManageTokenIsTheManagedToken,
}

impl fmt::Display for AccessTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerWithKey => write!(
                f,
                "access_token: the `bearer` flag and the `key` field are both present; \
                 the client software MUST reject this token (RFC 9635 §3.2.1)"
            ),
            Self::DuplicateFlag(v) => write!(
                f,
                "access_token.flags: `{v}` appears more than once (RFC 9635 §3.2.1)"
            ),
            Self::MissingAccess => write!(
                f,
                "access_token: no `access` field; it is REQUIRED and MUST reflect the \
                 rights associated with the issued token (RFC 9635 §3.2.1)"
            ),
            Self::ManageUriNotAbsolute(uri) => write!(
                f,
                "access_token.manage.uri: `{uri}` is not an absolute URI, and this one \
                 MUST be (RFC 9635 §3.2.1, RFC 3986)"
            ),
            Self::ManageUriLeaksToken(which) => write!(
                f,
                "access_token.manage.uri: it holds {which}; the URI MUST NOT include the \
                 value of the access token being managed or the value of the access token \
                 used to protect the URI (RFC 9635 §3.2.1)"
            ),
            Self::ManageTokenIsTheManagedToken => write!(
                f,
                "access_token.manage.access_token: it has the same value as the token it \
                 manages, which it MUST NOT (RFC 9635 §3.2.1)"
            ),
        }
    }
}

impl std::error::Error for AccessTokenError {}

impl AccessToken {
    /// `true` when the token is a bearer token, usable without key proof.
    #[must_use]
    pub fn is_bearer(&self) -> bool {
        self.flags.contains(&AccessTokenFlag::Bearer)
    }

    /// `true` when the AS states the token survives a rotation (§3.2.1).
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.flags.contains(&AccessTokenFlag::Durable)
    }

    /// Checks the §3.2.1 constraints the client has to enforce.
    ///
    /// ```
    /// use gnap_types::token::{AccessToken, AccessTokenError};
    ///
    /// let t: AccessToken = serde_json::from_str(
    ///     r#"{"value":"ABC","access":["read"],"flags":["bearer"],"key":"k-1"}"#).unwrap();
    /// assert_eq!(t.validate(), Err(AccessTokenError::BearerWithKey));
    ///
    /// // `access` is REQUIRED: without it the client cannot tell what the
    /// // token is good for.
    /// let t: AccessToken = serde_json::from_str(r#"{"value":"ABC"}"#).unwrap();
    /// assert_eq!(t.validate(), Err(AccessTokenError::MissingAccess));
    /// ```
    /// # Errors
    ///
    /// Fails when the token carries both the `bearer` flag and a `key`, when a
    /// flag appears more than once, or when `access` is absent.
    ///
    pub fn validate(&self) -> Result<(), AccessTokenError> {
        if self.is_bearer() && self.key.is_some() {
            return Err(AccessTokenError::BearerWithKey);
        }
        if self.access.is_none() {
            return Err(AccessTokenError::MissingAccess);
        }
        if let Some(duplicate) = first_duplicate(&self.flags) {
            return Err(AccessTokenError::DuplicateFlag(duplicate));
        }
        if let Some(manage) = &self.manage {
            manage.validate(&self.value)?;
        }
        Ok(())
    }
}

/// The first flag that appears twice, if any (§3.2.1).
fn first_duplicate(flags: &[AccessTokenFlag]) -> Option<String> {
    let mut seen = HashSet::new();
    flags
        .iter()
        .find(|f| !seen.insert(f.as_str()))
        .map(ToString::to_string)
}

/// One or more issued tokens (§3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct AccessTokenResponse {
    /// The shape used, which must mirror the request's.
    pub cardinality: Cardinality,
    /// The tokens issued.
    pub tokens: Vec<AccessToken>,
}

impl AccessTokenResponse {
    /// Checks that the response answers in the request's shape.
    ///
    /// §3.2.1 forbids answering an object request with an array, and §3.2.2
    /// forbids the reverse — even when a single token is issued.
    /// # Errors
    ///
    /// Fails when the response shape differs from the request's.
    ///
    pub fn check_cardinality(&self, requested: Cardinality) -> Result<(), CardinalityError> {
        if self.cardinality == requested {
            Ok(())
        } else {
            Err(CardinalityError {
                requested,
                answered: self.cardinality,
            })
        }
    }

    /// Applies [`AccessToken::validate`] to every token.
    /// # Errors
    ///
    /// Fails on the first token that breaks a rule of §3.2.1.
    pub fn validate(&self) -> Result<(), AccessTokenError> {
        self.tokens.iter().try_for_each(AccessToken::validate)
    }
}

/// The response does not match the request's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardinalityError {
    /// The shape requested.
    pub requested: Cardinality,
    /// The shape received.
    pub answered: Cardinality,
}

impl fmt::Display for CardinalityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (r, a, sec) = match self.requested {
            Cardinality::Single => ("an object", "an array", "§3.2.1"),
            Cardinality::Multiple => ("an array", "an object", "§3.2.2"),
        };
        write!(
            f,
            "access_token: the request asked for {r}, the response is {a}; \
             the response shape MUST follow the request's (RFC 9635 {sec})"
        )
    }
}

impl std::error::Error for CardinalityError {}

impl Serialize for AccessTokenResponse {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.cardinality {
            Cardinality::Multiple => self.tokens.serialize(s),
            Cardinality::Single => self.tokens.first().map_or_else(
                || {
                    Err(serde::ser::Error::custom(
                        "access_token: Single cardinality with no token",
                    ))
                },
                |t| t.serialize(s),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for AccessTokenResponse {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = AccessTokenResponse;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "access_token: an object, or an array of objects")
            }

            fn visit_map<M: MapAccess<'de>>(self, m: M) -> Result<Self::Value, M::Error> {
                let t: AccessToken =
                    Deserialize::deserialize(de::value::MapAccessDeserializer::new(m))?;
                Ok(AccessTokenResponse {
                    cardinality: Cardinality::Single,
                    tokens: vec![t],
                })
            }

            fn visit_seq<S: SeqAccess<'de>>(self, s: S) -> Result<Self::Value, S::Error> {
                let tokens: Vec<AccessToken> =
                    Deserialize::deserialize(de::value::SeqAccessDeserializer::new(s))?;

                // §3.2.2: every token carries a unique label, echoed from the request.
                let mut seen = HashSet::new();
                for (i, t) in tokens.iter().enumerate() {
                    match &t.label {
                        None => {
                            return Err(de::Error::custom(format!(
                                "access_token[{i}]: `label` is required for multiple \
                                 tokens (RFC 9635 §3.2.2)"
                            )))
                        }
                        Some(l) if !seen.insert(l.as_str()) => {
                            return Err(de::Error::custom(format!(
                                "access_token[{i}]: duplicate label `{l}` (RFC 9635 §3.2.2)"
                            )))
                        }
                        _ => {}
                    }
                }
                Ok(AccessTokenResponse {
                    cardinality: Cardinality::Multiple,
                    tokens,
                })
            }
        }
        d.deserialize_any(V)
    }
}
