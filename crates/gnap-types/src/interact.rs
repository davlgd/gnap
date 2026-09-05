//! Interacting with the end user — RFC 9635 §2.5 and §3.3.

use crate::polymorphic::MethodOrObject;
use gnap_registry::{InteractionFinishMethod, InteractionStartMode};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A start mode, named or detailed (§2.5.1).
pub type StartMode = MethodOrObject<InteractionStartMode>;

/// What the client can do to drive interaction (§2.5).
///
/// §2.5 requires it: a client does not declare a mode it cannot carry out. If
/// no mode fits, the AS cannot reach the RO otherwise, and interaction is
/// required, the AS answers `invalid_interaction`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InteractRequest {
    /// The ways the client can start interaction. Required, possibly empty
    /// when the client can start nothing.
    #[serde(default)]
    pub start: Vec<StartMode>,

    /// How the client wants to be told interaction has finished.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub finish: Option<InteractFinish>,

    /// Suggestions for the interaction (locales and the like).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hints: Option<InteractHints>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// How the AS will call the client back (§2.5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractFinish {
    /// The callback method.
    pub method: InteractionFinishMethod,

    /// The URI the AS will call. Absolute, no fragment, required for
    /// `redirect` and `push`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uri: Option<String>,

    /// A nonce unique to this request, chosen by the client. Required.
    ///
    /// Feeds the interaction hash (§4.2.3), which ties the callback to the
    /// pending request.
    pub nonce: String,

    /// The callback hash algorithm, named after the IANA "Named Information
    /// Hash Algorithm" registry. Defaults to `sha-256`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hash_method: Option<String>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl InteractFinish {
    /// The effective hash algorithm: `sha-256` when none is given (§4.2.3).
    #[must_use]
    pub fn effective_hash_method(&self) -> &str {
        self.hash_method.as_deref().unwrap_or("sha-256")
    }

    /// Checks what §2.5.2 requires of a callback (§2.5.2-MN03, §2.5.2-R07).
    ///
    /// The AS calls this before accepting a request: a fragment would swallow
    /// the query the callback parameters travel in (§4.2.1), and a relative URI
    /// has no host to reach.
    ///
    /// # Errors
    ///
    /// Fails when a `redirect` or `push` method carries no URI, or when the URI
    /// is relative or carries a fragment.
    pub fn validate(&self) -> Result<(), FinishError> {
        // §2.5.2-R09 — the nonce is required, and §4.2.3 hashes it inside an
        // ASCII base whose separator is a newline. Exactly three values cannot
        // go in there: the empty one, one that is not ASCII, and one carrying
        // the separator itself. Nothing more is refused: an unusual but ASCII
        // nonce is the client's business, as are uniqueness and randomness.
        if self.nonce.is_empty() || !self.nonce.is_ascii() || self.nonce.contains('\n') {
            return Err(FinishError::UnusableNonce);
        }

        let needs_uri = matches!(
            self.method,
            InteractionFinishMethod::Redirect | InteractionFinishMethod::Push
        );
        let Some(uri) = &self.uri else {
            return if needs_uri {
                Err(FinishError::MissingUri)
            } else {
                Ok(())
            };
        };

        if uri.contains('#') {
            return Err(FinishError::Fragment);
        }
        if !crate::uri::is_absolute(uri) {
            return Err(FinishError::Relative);
        }
        // §4.2.1 adds `hash` and `interact_ref` to this URI's query. One that
        // already names either would arrive with the parameter twice, and which
        // of the two the client reads is anybody's guess.
        if let Some(query) = uri.split_once('?').map(|(_, q)| q) {
            for pair in query.split('&') {
                let name = decoded_name(pair.split('=').next().unwrap_or(pair));
                if name == "hash" || name == "interact_ref" {
                    return Err(FinishError::ReservedQueryParameter);
                }
            }
        }
        Ok(())
    }
}

/// The decoded name of a query parameter, for comparison (§2.1).
///
/// A name is compared after decoding: `h%61sh` and `hash` are the same
/// parameter, and a client framework that decodes before this library compared
/// would see the collision this one is looking for. A name that does not decode
/// is no name this library recognises; `is_absolute` has already refused the
/// URI that carried it.
fn decoded_name(name: &str) -> String {
    percent_decode(name).unwrap_or_default()
}

/// What makes a callback unusable (§2.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishError {
    /// A `redirect` or `push` method with no URI to call.
    MissingUri,
    /// The URI carries a fragment, which §2.5.2 forbids.
    Fragment,
    /// The URI is not absolute, or is not a URI at all.
    Relative,
    /// The URI's query already names `hash` or `interact_ref` (§4.2.1).
    ReservedQueryParameter,
    /// The nonce is empty, or holds something the interaction hash cannot take.
    UnusableNonce,
}

impl fmt::Display for FinishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUri => write!(
                f,
                "interact.finish.uri: REQUIRED for the redirect and push methods \
                 (RFC 9635 §2.5.2)"
            ),
            Self::Fragment => write!(
                f,
                "interact.finish.uri: this URI MUST NOT contain any fragment component; \
                 the callback parameters travel in its query (RFC 9635 §2.5.2, §4.2.1)"
            ),
            Self::Relative => write!(
                f,
                "interact.finish.uri: this URI MUST be an absolute URI (RFC 9635 §2.5.2, \
                 RFC 3986)"
            ),
            Self::ReservedQueryParameter => write!(
                f,
                "interact.finish.uri: its query already names `hash` or `interact_ref`, \
                 which the AS adds when the interaction finishes (RFC 9635 §4.2.1)"
            ),
            Self::UnusableNonce => write!(
                f,
                "interact.finish.nonce: REQUIRED, and it feeds an ASCII hash base whose \
                 separator is a newline, so it must be non-empty ASCII without one \
                 (RFC 9635 §2.5.2, §4.2.3)"
            ),
        }
    }
}

impl std::error::Error for FinishError {}

/// Suggestions for driving the interaction (§2.5.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InteractHints {
    /// The end user's preferred locales, as defined by RFC 5646.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ui_locales: Option<Vec<String>>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// What the AS returns to enable interaction (§3.3).
///
/// §3.3 sets two prohibitions: the AS never answers with a mode the client did
/// not offer, nor with a mode it cannot support itself.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InteractResponse {
    /// The URI to send the end user to (§3.3.1).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub redirect: Option<String>,

    /// The application URI to launch (§3.3.2).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app: Option<String>,

    /// The short code to show the end user (§3.3.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_code: Option<String>,

    /// The short code and the short URI to enter it at (§3.3.4).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_code_uri: Option<UserCodeUri>,

    /// The AS nonce, used to validate the callback (§3.3.5).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub finish: Option<String>,

    /// How long these modes stay usable, in seconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in: Option<u64>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A short code and its matching short URI (§3.3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCodeUri {
    /// The code the end user types. Handled case-insensitively (§4.1.3).
    pub code: String,

    /// The entry URI, short enough to type. Does not contain the code.
    pub uri: String,
}

impl InteractCallback {
    /// Reads a callback out of a redirect URI's query (§4.2.1).
    ///
    /// §4.2.1-M05: "the client instance MUST parse the query parameters to
    /// extract the hash and interaction reference values." Parsing them is the
    /// client's job, so it belongs here rather than in every caller: a query is
    /// percent-encoded, may carry the client's own parameters alongside, and
    /// getting that wrong is how a callback ends up validated against the wrong
    /// reference.
    ///
    /// Takes the whole URI the browser arrived at, or just its query.
    ///
    /// # Errors
    ///
    /// Fails when either parameter is missing, repeated, or not decodable.
    pub fn from_redirect(uri: &str) -> Result<Self, CallbackError> {
        let query = uri.split_once('?').map_or(uri, |(_, q)| q);
        let mut hash = None;
        let mut interact_ref = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match percent_decode(name)?.as_str() {
                "hash" => &mut hash,
                "interact_ref" => &mut interact_ref,
                _ => continue,
            };
            if slot.is_some() {
                return Err(CallbackError::Repeated);
            }
            *slot = Some(percent_decode(value)?);
        }

        Ok(Self {
            hash: hash.ok_or(CallbackError::Missing("hash"))?,
            interact_ref: interact_ref.ok_or(CallbackError::Missing("interact_ref"))?,
        })
    }

    /// Reads a callback out of a pushed JSON body (§4.2.2).
    ///
    /// §4.2.2-M04: "the client instance MUST parse the JSON object and validate
    /// the hash value". This is the parsing half; validating is
    /// `Session::accept_callback`.
    ///
    /// # Errors
    ///
    /// Fails when the content is not the JSON object §4.2.2 describes.
    pub fn from_push(body: &[u8]) -> Result<Self, CallbackError> {
        serde_json::from_slice(body).map_err(|e| CallbackError::Malformed(e.to_string()))
    }
}

/// Percent-decodes one query component (RFC 3986 §2.1).
///
/// Percent-encoding works on octets, and RFC 3986 §2.5 has them decoded as
/// UTF-8 — so the escapes are gathered into bytes first and read as a string
/// once, rather than each byte being taken for a character of its own.
///
/// # Errors
///
/// Fails on a `%` that is not followed by two hexadecimal digits, and when the
/// decoded octets are not UTF-8. Keeping a malformed escape as literal text, or
/// skipping it, would hand the caller a value the sender never wrote.
fn percent_decode(value: &str) -> Result<String, CallbackError> {
    let malformed = |why: &str| CallbackError::Malformed(format!("`{value}`: {why}"));
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        match b {
            // §4.2.1 puts the values in a query, where `+` is the conventional
            // encoding of a space in form-style queries.
            b'+' => out.push(b' '),
            b'%' => {
                let digit = |b: Option<u8>| match b {
                    Some(d @ b'0'..=b'9') => Some(d - b'0'),
                    Some(d @ b'a'..=b'f') => Some(d - b'a' + 10),
                    Some(d @ b'A'..=b'F') => Some(d - b'A' + 10),
                    _ => None,
                };
                match (digit(bytes.next()), digit(bytes.next())) {
                    (Some(hi), Some(lo)) => out.push(hi * 16 + lo),
                    _ => {
                        return Err(malformed(
                            "a `%` must be followed by two hexadecimal digits (RFC 3986 §2.1)",
                        ))
                    }
                }
            }
            _ => out.push(b),
        }
    }
    String::from_utf8(out)
        .map_err(|_| malformed("the percent-encoded octets are not UTF-8 (RFC 3986 §2.5)"))
}

/// What stops a callback from being read (§4.2.1, §4.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackError {
    /// One of the two required values is absent.
    Missing(&'static str),
    /// One of them appears more than once, so which one meant is a guess.
    Repeated,
    /// The pushed content is not the JSON object §4.2.2 describes.
    Malformed(String),
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(what) => write!(
                f,
                "the interaction callback carries no `{what}`; both it and the other are \
                 REQUIRED (RFC 9635 §4.2.1, §4.2.2)"
            ),
            Self::Repeated => write!(
                f,
                "the interaction callback names `hash` or `interact_ref` more than once, \
                 so which value was meant is a guess (RFC 9635 §4.2.1)"
            ),
            Self::Malformed(e) => write!(
                f,
                "the interaction callback is not the JSON object §4.2.2 describes: {e}"
            ),
        }
    }
}

impl std::error::Error for CallbackError {}

/// What the AS conveys to the client when interaction finishes (§4.2).
///
/// Serves both callback methods: as query parameters for `redirect` (§4.2.1),
/// as a JSON body for `push` (§4.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractCallback {
    /// The interaction hash (§4.2.3). The client **must** validate it before
    /// passing `interact_ref` on to the AS.
    pub hash: String,

    /// The interaction reference, single use (§4.2).
    pub interact_ref: String,
}
