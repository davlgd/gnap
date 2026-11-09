//! JOSE proofs of possession: attached (`jws`) and detached (`jwsd`) JWS,
//! RFC 9635 §7.3.4 and §7.3.3, with their key rotations (§7.3.4.1, §7.3.3.1).
//!
//! A `jwsd` proof signs the SHA-256 digest of the content and travels in the
//! `Detached-JWS` header field. A `jws` proof signs the content itself and
//! replaces it, as `application/jose`; without content, it travels in
//! `Detached-JWS` over an empty payload. Both protect the method, the target
//! URI, the creation time, and, when the request presents an access token,
//! its hash in `ath`.
//!
//! The verifier takes the key from the caller, never from the JWS, and its
//! checks run in a fixed order: the envelope and the protected header first,
//! then the payload against the content, then the signature, and only then
//! the replay reservation, so that an unproven request can't spend anything.
//! A `jws` verifier returns the authenticated payload as the request content:
//! the caller processes that, and only that.

mod compact;
mod replay;

pub use replay::{JwsReplayMemory, ReplayCache, ReplayId};

use crate::jwk::{PublicKey, JWS_ALGORITHMS, MAX_KEY_ID_BYTES};
use crate::proof::{ProofError, Signer, Verifier};
use crate::verify::{Expectations, SignedRequest, VerifyError};
use compact::{decode, encode, typ, Header, Role, Segments};
use gnap_types::token::TokenValue;
use gnap_types::uri;
use sha2::{Digest as _, Sha256};
use std::borrow::Cow;

/// The header field that carries a detached JWS (RFC 9635 §7.3.3).
pub const DETACHED_JWS_HEADER: &str = "Detached-JWS";

/// The media type of a request whose content is an attached JWS (§7.3.4).
pub const JOSE_MEDIA_TYPE: &str = "application/jose";

/// Longest decoded protected header, in bytes.
pub const MAX_JWS_HEADER_BYTES: usize = 8 * 1024;

/// Longest decoded signature, in bytes: that of a 4,096-bit RSA key.
pub const MAX_JWS_SIGNATURE_BYTES: usize = crate::MAX_MODULUS_BITS / 8;

/// Longest `Detached-JWS` field value, in bytes, a key rotation's included.
pub const MAX_DETACHED_JWS_BYTES: usize = 32 * 1024;

/// Longest attached JWS, in bytes, a key rotation's included.
///
/// The transport has to bound the whole request before this crate sees it.
pub const MAX_ATTACHED_JWS_BYTES: usize = 256 * 1024;

/// The JOSE proof method of a key (RFC 9635 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwsMethod {
    /// `jws`: the JWS carries the content as its payload.
    Jws,
    /// `jwsd`: the JWS signs the digest of the content and travels apart.
    Jwsd,
}

impl JwsMethod {
    /// The method's name in a key's `proof`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Jws => "jws",
            Self::Jwsd => "jwsd",
        }
    }
}

/// What a JWS proof covers of the request it signs.
#[derive(Clone, Copy)]
pub struct JwsParams<'a> {
    /// The HTTP method, which the proof compares case-sensitively.
    pub method: &'a str,
    /// The target URI: an `absolute-URI` of RFC 3986 §4.3, which has no
    /// fragment.
    pub target_uri: &'a str,
    /// The creation time, in seconds since the Unix epoch.
    pub created: u64,
    /// The access token the request presents in `Authorization`, if any.
    pub access_token: Option<&'a str>,
}

impl core::fmt::Debug for JwsParams<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JwsParams")
            .field("method", &self.method)
            .field("target_uri", &self.target_uri)
            .field("created", &self.created)
            .field("access_token", &self.access_token.map(|_| "<redacted>"))
            .finish()
    }
}

/// A signed JWS proof, and where the request carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsProof {
    /// The value of the [`DETACHED_JWS_HEADER`] field. The request keeps its
    /// content, if it has one.
    Detached(String),
    /// The request content to send instead of the original one, with the
    /// [`JOSE_MEDIA_TYPE`] media type.
    Attached(String),
}

/// Signs a request with a `jws` or `jwsd` proof.
///
/// An empty `content` means the request has none: a `jwsd` proof then signs
/// an empty payload, and a `jws` proof travels in [`DETACHED_JWS_HEADER`].
///
/// The header carries the signer's [`Signer::key_id`] as `kid`, which RFC 9635
/// requires for a key presented as a JWK. A signer with an empty identifier
/// signs without `kid`, for a key presented otherwise: verify its proofs with
/// a verifier that expects no `kid`.
///
/// # Errors
///
/// Fails for a signer whose algorithm isn't one of [`JWS_ALGORITHMS`], for a
/// method, URI, access token, or key identifier the proof can't carry, for a
/// proof longer than the verifier's bounds, or when the signer fails.
pub fn sign_jws(
    method: JwsMethod,
    params: &JwsParams<'_>,
    content: &[u8],
    signer: &dyn Signer,
) -> Result<JwsProof, ProofError> {
    let header = header(method, Role::Binding, params, signer)?;
    match method {
        JwsMethod::Jwsd => Ok(JwsProof::Detached(compact(
            &header,
            &content_digest(content),
            signer,
            MAX_DETACHED_JWS_BYTES,
        )?)),
        JwsMethod::Jws if content.is_empty() => Ok(JwsProof::Detached(compact(
            &header,
            b"",
            signer,
            MAX_DETACHED_JWS_BYTES,
        )?)),
        JwsMethod::Jws => {
            require_json(content).map_err(ProofError::Signing)?;
            Ok(JwsProof::Attached(compact(
                &header,
                content,
                signer,
                MAX_ATTACHED_JWS_BYTES,
            )?))
        }
    }
}

/// Signs a key rotation (RFC 9635 §7.3.3.1, §7.3.4.1).
///
/// The previous key signs the request with the rotation `typ`, and the
/// replacement key signs that JWS, as its payload, with the ordinary one.
/// `content` is the rotation message, which names the new key.
///
/// # Errors
///
/// Fails as [`sign_jws`] does, or for an empty `content`.
pub fn sign_jws_rotation(
    method: JwsMethod,
    params: &JwsParams<'_>,
    content: &[u8],
    previous: &dyn Signer,
    replacement: &dyn Signer,
) -> Result<JwsProof, ProofError> {
    if content.is_empty() {
        return Err(ProofError::Signing(
            "a key rotation signs the message that names the new key".into(),
        ));
    }
    let inner_payload = match method {
        JwsMethod::Jws => {
            require_json(content).map_err(ProofError::Signing)?;
            content.to_vec()
        }
        JwsMethod::Jwsd => content_digest(content),
    };
    let limit = match method {
        JwsMethod::Jws => MAX_ATTACHED_JWS_BYTES,
        JwsMethod::Jwsd => MAX_DETACHED_JWS_BYTES,
    };
    let inner = compact(
        &header(method, Role::Rotation, params, previous)?,
        &inner_payload,
        previous,
        limit,
    )?;
    let outer = compact(
        &header(method, Role::Binding, params, replacement)?,
        inner.as_bytes(),
        replacement,
        limit,
    )?;
    Ok(match method {
        JwsMethod::Jws => JwsProof::Attached(outer),
        JwsMethod::Jwsd => JwsProof::Detached(outer),
    })
}

/// The key a JWS proof has to be signed with, as the caller resolved it.
///
/// Prefer [`JwsKey::for_public_key`] for a key imported from a JWK: it takes
/// the identity from the key and leaves the `kid` to the key. Building one by
/// hand is for a key the caller resolved otherwise, and then the caller
/// answers for the three fields. Either way, the proof shows possession of
/// the key, not what its holder may do.
pub struct JwsKey<'a> {
    /// The key to verify with: the one the caller trusts for this request,
    /// never one the JWS names. Its [`Verifier::expected_key_id`], which a
    /// JWK import sets to the key's `kid`, is the `kid` the JWS must carry.
    pub verifier: &'a dyn Verifier,
    /// What identifies the key for replay protection: canonical and stable,
    /// the same for two names of one key, and never the `kid` a JWS presents.
    /// A JWK thumbprint is one. It can't be empty.
    pub identity: Cow<'a, str>,
    /// The clock and its tolerance, and a `kid` the JWS must also carry, if
    /// the caller learned one from the message.
    pub expectations: Expectations<'a>,
}

impl<'a> JwsKey<'a> {
    /// The key for a JWK import, identified by its thumbprint (RFC 7638).
    #[must_use]
    pub fn for_public_key(key: &'a PublicKey, now: u64, max_clock_skew: u64) -> Self {
        Self {
            verifier: key,
            identity: Cow::Owned(key.thumbprint()),
            expectations: Expectations {
                now,
                max_clock_skew,
                key_id: None,
            },
        }
    }
}

/// An accepted JWS proof, reserved against replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedJws {
    /// The authenticated request content, empty when there is none: the JWS
    /// payload for `jws`, the message content for `jwsd`.
    pub content: Vec<u8>,
    /// The `created` of the proof, the outer one for a key rotation.
    pub created: u64,
}

/// Verifies the `jws` or `jwsd` proof of a request (RFC 9635 §7.3.3, §7.3.4).
///
/// The JWS must carry the ordinary `typ` of the method, the algorithm and,
/// where expected, the `kid` of `key`, the request's method and target URI,
/// a `created` within the tolerated skew, and `ath` exactly when the request
/// presents a GNAP access token. A request that also carries an HTTP message
/// signature is refused.
///
/// # Errors
///
/// [`VerifyError::Unsigned`] when the request carries no JWS proof, and
/// [`VerifyError::Rejected`] with the reason when its proof isn't acceptable
/// or was already used.
pub fn verify_jws_request(
    method: JwsMethod,
    request: &SignedRequest<'_>,
    key: &JwsKey<'_>,
    replay: &dyn JwsReplayMemory,
) -> Result<AcceptedJws, VerifyError> {
    let envelope = Envelope::of(method, request)?;
    let proof = Parsed::new(envelope.compact).map_err(VerifyError::Rejected)?;
    proof
        .check(typ(method, Role::Binding), request, key)
        .map_err(VerifyError::Rejected)?;
    let content = if envelope.attached {
        require_json(&proof.payload).map_err(VerifyError::Rejected)?;
        proof.payload.clone()
    } else {
        let expected = match method {
            JwsMethod::Jws => Vec::new(),
            JwsMethod::Jwsd => content_digest(envelope.content),
        };
        if proof.payload != expected {
            return Err(rejected(
                "the JWS payload doesn't match the request content",
            ));
        }
        envelope.content.to_vec()
    };
    let id = proof.authenticate(key).map_err(VerifyError::Rejected)?;
    reserve(replay, &[id], key.expectations.now)?;
    Ok(AcceptedJws {
        content,
        created: proof.header.created,
    })
}

/// Verifies the proof of a key rotation (RFC 9635 §7.3.3.1, §7.3.4.1).
///
/// The outer JWS must be an ordinary proof by `replacement` whose payload is
/// the inner JWS, a proof by `previous` with the rotation `typ` over the
/// same request. Both proofs are checked before either is reserved, and both
/// are reserved together or not at all.
///
/// # Errors
///
/// Fails as [`verify_jws_request`] does, for either proof, or for a request
/// without content.
pub fn verify_jws_rotation(
    method: JwsMethod,
    request: &SignedRequest<'_>,
    previous: &JwsKey<'_>,
    replacement: &JwsKey<'_>,
    replay: &dyn JwsReplayMemory,
) -> Result<AcceptedJws, VerifyError> {
    let envelope = Envelope::of(method, request)?;
    let outer = Parsed::new(envelope.compact).map_err(VerifyError::Rejected)?;
    outer
        .check(typ(method, Role::Binding), request, replacement)
        .map_err(VerifyError::Rejected)?;
    let inner = core::str::from_utf8(&outer.payload)
        .map_err(|_| rejected("the outer JWS of a key rotation signs the inner JWS"))
        .and_then(|inner| Parsed::new(inner).map_err(VerifyError::Rejected))?;
    inner
        .check(typ(method, Role::Rotation), request, previous)
        .map_err(VerifyError::Rejected)?;
    let content = if envelope.attached {
        require_json(&inner.payload).map_err(VerifyError::Rejected)?;
        inner.payload.clone()
    } else {
        envelope.content.to_vec()
    };
    if content.is_empty() {
        return Err(rejected(
            "a key rotation carries the message that names the new key",
        ));
    }
    if !envelope.attached && inner.payload != content_digest(&content) {
        return Err(rejected(
            "the inner JWS payload doesn't match the request content",
        ));
    }
    let outer_id = outer
        .authenticate(replacement)
        .map_err(VerifyError::Rejected)?;
    let inner_id = inner
        .authenticate(previous)
        .map_err(VerifyError::Rejected)?;
    reserve(replay, &[inner_id, outer_id], replacement.expectations.now)?;
    Ok(AcceptedJws {
        content,
        created: outer.header.created,
    })
}

/// The payload of a request's attached JWS, decoded WITHOUT verification.
///
/// A server needs it for one thing: to find, in a first request, the key that
/// the proof claims, so that it can resolve that key and verify the proof
/// with [`verify_jws_request`]. Nothing in it is authenticated: read only the
/// key from it, and process the content that the verification returns. It
/// decodes one JWS within the bounds of the verifier, refuses what its
/// envelope check refuses, and neither verifies, reserves, nor normalizes.
///
/// # Errors
///
/// [`VerifyError::Unsigned`] when the request carries no attached JWS, and
/// [`VerifyError::Rejected`] when its envelope or serialization is malformed.
pub fn unverified_attached_payload(request: &SignedRequest<'_>) -> Result<Vec<u8>, VerifyError> {
    let envelope = Envelope::of(JwsMethod::Jws, request)?;
    if !envelope.attached {
        return Err(VerifyError::Unsigned);
    }
    Parsed::new(envelope.compact)
        .map(|proof| proof.payload)
        .map_err(VerifyError::Rejected)
}

/// Where the request carries its JWS.
struct Envelope<'r> {
    compact: &'r str,
    /// The message content a detached proof covers; empty for an attached one.
    content: &'r [u8],
    attached: bool,
}

impl<'r> Envelope<'r> {
    fn of(method: JwsMethod, request: &'r SignedRequest<'_>) -> Result<Self, VerifyError> {
        if request.header_values("signature").next().is_some()
            || request.header_values("signature-input").next().is_some()
        {
            return Err(rejected(
                "a request with a JWS proof can't carry an HTTP message signature too",
            ));
        }
        let mut fields = request.header_values(DETACHED_JWS_HEADER);
        let detached = fields.next().map(|value| value.trim_matches([' ', '\t']));
        if fields.next().is_some() {
            return Err(rejected("the request carries Detached-JWS more than once"));
        }
        let content = request.body.unwrap_or_default();
        match (method, detached) {
            (JwsMethod::Jws, Some(_)) if !content.is_empty() => Err(rejected(
                "an attached JWS replaces the content, so Detached-JWS can't accompany it",
            )),
            (JwsMethod::Jws, None) if !content.is_empty() => {
                let mut types = request.header_values("content-type");
                let first = types.next();
                if types.next().is_some() {
                    return Err(rejected(
                        "an attached JWS needs one Content-Type naming application/jose",
                    ));
                }
                // Content of another media type, without Detached-JWS, carries
                // no JWS at all: the request is unsigned, as one without
                // Signature is for httpsig.
                let jose = first.is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim_matches([' ', '\t'])
                        .eq_ignore_ascii_case(JOSE_MEDIA_TYPE)
                });
                if !jose {
                    return Err(VerifyError::Unsigned);
                }
                if content.len() > MAX_ATTACHED_JWS_BYTES {
                    return Err(rejected("the attached JWS is too long"));
                }
                let compact = core::str::from_utf8(content)
                    .map_err(|_| rejected("an attached JWS is ASCII text"))?;
                Ok(Self {
                    compact,
                    content: &[],
                    attached: true,
                })
            }
            (_, None) => Err(VerifyError::Unsigned),
            (_, Some(compact)) => {
                if compact.len() > MAX_DETACHED_JWS_BYTES {
                    return Err(rejected("the Detached-JWS field is too long"));
                }
                Ok(Self {
                    compact,
                    content,
                    attached: false,
                })
            }
        }
    }
}

/// A JWS decoded but not yet authenticated.
struct Parsed<'c> {
    segments: Segments<'c>,
    header: Header,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl<'c> Parsed<'c> {
    fn new(compact: &'c str) -> Result<Self, String> {
        let segments = Segments::split(compact)?;
        Ok(Self {
            header: Header::parse(&decode(segments.protected, "protected header")?)?,
            payload: decode(segments.payload, "payload")?,
            signature: decode(segments.signature, "signature")?,
            segments,
        })
    }

    /// The checks that need no cryptography: everything the header says
    /// against the request and the key.
    fn check(
        &self,
        typ: &str,
        request: &SignedRequest<'_>,
        key: &JwsKey<'_>,
    ) -> Result<(), String> {
        if key.identity.is_empty() {
            return Err("the key has no identity to scope its replay protection".into());
        }
        let header = &self.header;
        if header.typ != typ {
            return Err(format!("the JWS typ must be {typ}"));
        }
        let alg = key.verifier.algorithm();
        if header.alg != alg || !JWS_ALGORITHMS.contains(&alg) {
            return Err(format!(
                "the JWS alg must be the key's, {alg}, for jws and jwsd"
            ));
        }
        for expected in [key.expectations.key_id, key.verifier.expected_key_id()]
            .into_iter()
            .flatten()
        {
            if header.kid.as_deref() != Some(expected) {
                return Err(format!("the JWS kid must be {expected}"));
            }
        }
        if header.htm != request.method || !is_token(&header.htm) {
            return Err("the JWS htm must be the request method".into());
        }
        if header.uri != request.target_uri || !uri::is_absolute(&header.uri) {
            return Err("the JWS uri must be the absolute request URI, without fragment".into());
        }
        let Expectations {
            now,
            max_clock_skew,
            ..
        } = key.expectations;
        if now.abs_diff(header.created) > max_clock_skew {
            return Err("the JWS created is outside the tolerated clock skew".into());
        }
        match (access_token(request)?, header.ath.as_deref()) {
            (Some(token), Some(ath)) if ath == token_hash(token) => Ok(()),
            (Some(_), _) => Err("the JWS ath must hash the presented access token".into()),
            (None, Some(_)) => {
                Err("the JWS carries ath, but the request presents no access token".into())
            }
            (None, None) => Ok(()),
        }
    }

    /// Verifies the signature, and returns the identifier to reserve.
    fn authenticate(&self, key: &JwsKey<'_>) -> Result<ReplayId, String> {
        key.verifier
            .verify(self.segments.signing_input().as_bytes(), &self.signature)
            .map_err(|e| format!("the JWS signature doesn't verify: {e}"))?;
        Ok(ReplayId::new(
            &key.identity,
            self.segments.protected,
            self.segments.payload,
            self.header.created,
        ))
    }
}

fn header(
    method: JwsMethod,
    role: Role,
    params: &JwsParams<'_>,
    signer: &dyn Signer,
) -> Result<Header, ProofError> {
    let alg = signer.algorithm();
    if !JWS_ALGORITHMS.contains(&alg) {
        return Err(ProofError::Signing(format!(
            "{alg} isn't accepted for jws and jwsd"
        )));
    }
    if !is_token(params.method) {
        return Err(ProofError::Signing(
            "the request method isn't a token".into(),
        ));
    }
    if !uri::is_absolute(params.target_uri) {
        return Err(ProofError::Signing(
            "the target URI must be absolute, without fragment".into(),
        ));
    }
    if params.access_token.is_some_and(|token| !is_token68(token)) {
        return Err(ProofError::Signing(
            "the access token isn't a token68 value".into(),
        ));
    }
    let kid = signer.key_id();
    if kid.len() > MAX_KEY_ID_BYTES {
        return Err(ProofError::Signing(format!(
            "the key identifier is longer than {MAX_KEY_ID_BYTES} bytes"
        )));
    }
    Ok(Header {
        alg: alg.into(),
        kid: (!kid.is_empty()).then(|| kid.into()),
        typ: typ(method, role).into(),
        htm: params.method.into(),
        uri: params.target_uri.into(),
        created: params.created,
        ath: params.access_token.map(token_hash),
    })
}

/// Signs a compact JWS within the bounds its verifier applies, so that no
/// proof this crate signs is refused for its size.
fn compact(
    header: &Header,
    payload: &[u8],
    signer: &dyn Signer,
    limit: usize,
) -> Result<String, ProofError> {
    let header = header.to_json();
    if header.len() > MAX_JWS_HEADER_BYTES {
        return Err(ProofError::Signing(
            "the JWS protected header is too long".into(),
        ));
    }
    let signing_input = format!("{}.{}", encode(header), encode(payload));
    let signature = signer.sign(signing_input.as_bytes())?;
    if signature.len() > MAX_JWS_SIGNATURE_BYTES {
        return Err(ProofError::Signing("the JWS signature is too long".into()));
    }
    let compact = format!("{signing_input}.{}", encode(signature));
    if compact.len() > limit {
        return Err(ProofError::Signing("the JWS is too long to send".into()));
    }
    Ok(compact)
}

/// The `jwsd` payload: the SHA-256 digest of the content, or nothing.
fn content_digest(content: &[u8]) -> Vec<u8> {
    if content.is_empty() {
        Vec::new()
    } else {
        Sha256::digest(content).to_vec()
    }
}

/// An attached payload is "the JSON serialized content of the request"
/// (RFC 9635 §7.3.4). Requiring it tells an ordinary proof from the outer
/// proof of a key rotation, whose payload is a compact JWS, and it refuses an
/// empty attached payload. Its members are the caller's to parse.
fn require_json(payload: &[u8]) -> Result<(), String> {
    serde_json::from_slice::<serde::de::IgnoredAny>(payload)
        .map(drop)
        .map_err(|_| "an attached JWS payload is the JSON content of the request".into())
}

/// The `ath` of an access token: its SHA-256 digest, base64url-encoded.
fn token_hash(token: &str) -> String {
    encode(Sha256::digest(token.as_bytes()))
}

/// The access token of a `GNAP` `Authorization` field, if the request has one.
fn access_token<'r>(request: &'r SignedRequest<'_>) -> Result<Option<&'r str>, String> {
    let mut fields = request.header_values("authorization");
    let Some(field) = fields.next() else {
        return Ok(None);
    };
    if fields.next().is_some() {
        return Err("the request carries Authorization more than once".into());
    }
    field
        .trim_matches([' ', '\t'])
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("GNAP"))
        // RFC 9110 §11.4: one or more spaces, and no tab, separate the two.
        .map(|(_, token)| token.trim_start_matches(' '))
        .filter(|token| is_token68(token))
        .map(Some)
        .ok_or_else(|| "Authorization must present one GNAP access token".into())
}

/// Whether a value is a `token68` (RFC 9110 §11.2), the syntax of an access
/// token value (RFC 9635 §3.2.1).
fn is_token68(value: &str) -> bool {
    TokenValue::new(value).is_ok()
}

/// Whether a method is an HTTP token (RFC 9110 §5.6.2).
fn is_token(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn reserve(replay: &dyn JwsReplayMemory, ids: &[ReplayId], now: u64) -> Result<(), VerifyError> {
    if replay.reserve(ids, now) {
        Ok(())
    } else {
        Err(rejected(
            "the JWS proof was already used, or can't be reserved",
        ))
    }
}

fn rejected(reason: &str) -> VerifyError {
    VerifyError::Rejected(reason.into())
}
