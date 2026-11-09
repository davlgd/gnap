//! Signing a request without choosing an HTTP transport.

use crate::session::SessionProof;
use crate::{ClientError, HttpRequest};
use gnap_crypto::digest::{content_digest, DigestAlgorithm};
use gnap_crypto::httpsig::{fresh_nonce, sign, Component, Message, SignatureInput, Tag};
use gnap_crypto::jws::{
    sign_jws, JwsMethod, JwsParams, JwsProof, DETACHED_JWS_HEADER, JOSE_MEDIA_TYPE,
};
use gnap_crypto::proof::Signer;
use gnap_crypto::JWS_ALGORITHMS;
use gnap_registry::KeyProofingMethod;
use gnap_types::message::GrantRequest;
use gnap_types::polymorphic::MethodOrObject;
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
    let (signature_input, signature) = sign(&message, &input, &signer, label)?;
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

/// The proof method a grant request commits its session to (§2.3, §7.3).
///
/// A key sent by value names its method, and the session's signer has to be
/// able to perform it: for `jws` and `jwsd`, a proof without parameters, an
/// algorithm they take, and a JWK whose `alg` and `kid` are the signer's,
/// since the proof carries both. A key named by reference, or a client named
/// by reference, proves with `httpsig`.
pub(crate) fn session_proof(
    request: &GrantRequest,
    signer: &dyn Signer,
) -> Result<SessionProof, ClientError> {
    let Some(key) = request
        .client
        .as_value()
        .and_then(|client| client.key.as_value())
    else {
        return Ok(SessionProof::Httpsig);
    };
    let jose = match key.proof.method() {
        KeyProofingMethod::Httpsig => return Ok(SessionProof::Httpsig),
        KeyProofingMethod::Jws => JwsMethod::Jws,
        KeyProofingMethod::Jwsd => JwsMethod::Jwsd,
        other => {
            return Err(ClientError::Usage(format!(
                "client.key.proof: this session can't present a `{}` proof; the key MUST be \
                 used with the proofing mechanism it declares (RFC 9635 §2.3, §7.3)",
                other.as_str()
            )))
        }
    };
    let usage = |reason: &str| Err(ClientError::Usage(format!("client.key: {reason}")));
    if matches!(&key.proof, MethodOrObject::Detailed { params, .. } if !params.is_empty()) {
        return usage("the jws and jwsd proofs take no parameters (RFC 9635 §7.3.3, §7.3.4)");
    }
    let alg = signer.algorithm();
    if !JWS_ALGORITHMS.contains(&alg) {
        return usage(&format!(
            "the signer's {alg} isn't an algorithm of jws and jwsd"
        ));
    }
    let Some(jwk) = key.jwk.as_ref() else {
        return usage("a jws or jwsd proof names its key, presented as a JWK");
    };
    let member = |name: &str| jwk.get(name).and_then(serde_json::Value::as_str);
    if member("alg") != Some(alg) || member("kid") != Some(signer.key_id()) {
        return usage(
            "the JWK's alg and kid must be the signer's, which the proof carries \
             (RFC 9635 §7.3.3, §7.3.4)",
        );
    }
    Ok(SessionProof::Jose(jose))
}

/// Signs a request with a `jws` or `jwsd` proof (RFC 9635 §7.3.3, §7.3.4).
///
/// `content` is the JSON content, if any. A detached proof travels in
/// `Detached-JWS` next to it; an attached one replaces it, as
/// `application/jose`. The access token, if any, is presented with the GNAP
/// scheme, and the proof covers it in `ath`.
pub(crate) fn sign_jose(
    request: HttpRequest,
    method: JwsMethod,
    content: Option<Vec<u8>>,
    signer: &dyn Signer,
    token: Option<&TokenValue>,
    now: u64,
) -> Result<HttpRequest, ClientError> {
    let content = content.unwrap_or_default();
    let proof = sign_jws(
        method,
        &JwsParams {
            method: &request.method,
            target_uri: &request.url,
            created: now,
            access_token: token.map(TokenValue::as_str),
        },
        &content,
        signer,
    )?;
    let mut request = match proof {
        JwsProof::Detached(value) => {
            let request = if content.is_empty() {
                request
            } else {
                request.json_body(content)
            };
            request.header(DETACHED_JWS_HEADER, value)
        }
        JwsProof::Attached(value) => {
            let mut request = request.header("Content-Type", JOSE_MEDIA_TYPE);
            request.body = Some(value.into_bytes());
            request
        }
    };
    if let Some(value) = token {
        // GNAP-9635-§7.2-M03 — present the token using the GNAP scheme.
        request = request.header("Authorization", format!("GNAP {}", value.as_str()));
    }
    Ok(request)
}
