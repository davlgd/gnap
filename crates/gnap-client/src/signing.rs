//! Signing a request without choosing an HTTP transport.

use crate::{ClientError, HttpRequest};
use gnap_crypto::digest::{content_digest, DigestAlgorithm};
use gnap_crypto::httpsig::{fresh_nonce, sign, Component, Message, SignatureInput, Tag};
use gnap_crypto::proof::Signer;
use gnap_types::token::TokenValue;

/// Adds a GNAP HTTP signature and, when supplied, an access token (§7.2–7.3.1).
///
/// Signs but does not send. The method, exact target URI, body and existing
/// application headers are preserved; no JSON content type is imposed. A
/// present body, including an empty one, receives a SHA-256 Content-Digest.
/// The signature covers the method, target URI, that digest and Authorization
/// when present. Other application headers are not covered by this helper.
///
/// `now` is the current Unix timestamp in seconds. Each call generates a fresh,
/// unpredictable nonce: send its result only once and sign again for a retry.
/// TLS, redirect policy, audience, token validity and the choice of a matching
/// signing key remain the caller's responsibility. This function neither
/// validates a token's permissions nor constrains the destination URI.
///
/// # Errors
///
/// Rejects pre-existing Authorization, Signature, Signature-Input or
/// Content-Digest headers, regardless of case. Also fails if secure randomness
/// or signing fails. It never silently replaces a supplied security header.
pub fn sign_request(
    request: HttpRequest,
    signer: &(impl Signer + ?Sized),
    token: Option<&TokenValue>,
    now: u64,
) -> Result<HttpRequest, ClientError> {
    sign_request_labelled(request, signer, token, now, "sig1")
}

/// [`sign_request`] with a chosen signature label.
///
/// The label names the signature within `Signature-Input` and `Signature`
/// (RFC 9421 §4.1); a key rotation covers the first signature by that name.
///
/// # Errors
///
/// As [`sign_request`].
pub(crate) fn sign_request_labelled(
    mut request: HttpRequest,
    signer: &(impl Signer + ?Sized),
    token: Option<&TokenValue>,
    now: u64,
    label: &str,
) -> Result<HttpRequest, ClientError> {
    const RESERVED: [&str; 4] = [
        "Authorization",
        "Signature",
        "Signature-Input",
        "Content-Digest",
    ];
    if request.headers.iter().any(|(name, _)| {
        RESERVED
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
    }) {
        return Err(ClientError::Usage(
            "sign_request requires a request without Authorization, Signature, Signature-Input or Content-Digest headers"
                .into(),
        ));
    }
    let digest = request
        .body
        .as_ref()
        .map(|body| content_digest(body, DigestAlgorithm::Sha256));
    // GNAP-9635-§7.2-M03 — present the token using the GNAP scheme.
    let authorization = token.map(|value| format!("GNAP {}", value.as_str()));
    let mut components = vec![Component::Method, Component::TargetUri];
    if digest.is_some() {
        components.push(Component::ContentDigest);
    }
    if authorization.is_some() {
        components.push(Component::Authorization);
    }
    let message = Message {
        method: &request.method,
        target_uri: &request.url,
        content_digest: digest.as_deref(),
        authorization: authorization.as_deref(),
        other: Vec::new(),
    };
    let input = SignatureInput {
        components,
        created: now,
        keyid: signer.key_id().to_owned(),
        // §7.3.1-S13 — use an unguessable nonce for every signature.
        nonce: Some(fresh_nonce()?),
        tag: Tag::Gnap,
    };
    let (signature_input, signature) = sign(&message, &input, &Borrowed(signer), label)?;
    if let Some(value) = authorization {
        request = request.header("Authorization", value);
    }
    if let Some(value) = digest {
        request = request.header("Content-Digest", value);
    }
    Ok(request
        .header("Signature-Input", signature_input)
        .header("Signature", signature))
}

/// A borrowed signer, sized so that it can be handed to the signing helpers
/// whether the caller holds a concrete key or a `dyn Signer`.
pub(crate) struct Borrowed<'a, S: ?Sized>(pub &'a S);

impl<S: Signer + ?Sized> Signer for Borrowed<'_, S> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, gnap_crypto::ProofError> {
        self.0.sign(data)
    }
    fn key_id(&self) -> &str {
        self.0.key_id()
    }
    fn algorithm(&self) -> &'static str {
        self.0.algorithm()
    }
}
