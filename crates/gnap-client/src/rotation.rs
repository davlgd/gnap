//! Presenting a new key for an access token (RFC 9635 §6.1.1, §7.3.1.1,
//! §7.3.3.1, §7.3.4.1).
//!
//! The request carries the new public key in its content and two proofs,
//! the new key's covering the current key's. With `httpsig`, they are two
//! signatures, the new one tagged `gnap-rotate`; with `jws` and `jwsd`, the
//! new key signs the current key's JWS. This module builds that request;
//! [`crate::Session::rotate_key`] sends it and reads the answer.

use crate::session::SessionProof;
use crate::{ClientError, HttpRequest};
use gnap_crypto::PublicKey;
use gnap_crypto::httpsig::{
    Component, Message, SignatureInput, Tag, fresh_nonce, parse_signatures, sign, signature_base,
};
use gnap_crypto::jws::{
    JwsKey, JwsMethod, JwsParams, ReplayId, sign_jws_rotation, verify_jws_rotation,
};
use gnap_crypto::proof::{Signer, Verifier};
use gnap_registry::KeyProofingMethod;
use gnap_types::key::{Key, KeyObject};
use gnap_types::token::TokenValue;

/// The label of the current key's signature in a rotation request.
pub(crate) const PREVIOUS_LABEL: &str = "previous";
/// The label of the new key's signature in a rotation request.
pub(crate) const REPLACEMENT_LABEL: &str = "replacement";

/// Checks that a key can be presented as the new key by this session, and
/// returns the verifier for it, which [`sign_key_rotation`] uses to check the
/// real signature before anything leaves.
///
/// §6.1.1: "keys passed by value are always public keys", and "The proofing
/// method and parameters for the new key MUST be the same as those
/// established for the previous key." The session presents, by value, a
/// public JWK of its own proof method and an algorithm that method takes,
/// with the `kid` its new signer uses, and for `jws` and `jwsd` its
/// algorithm too. A reference, another format, another proofing method,
/// proofing parameters, a private member or a mismatched `kid` are refused
/// before anything leaves. These are the limits of this session, not rules
/// GNAP places on every client.
///
/// # Errors
///
/// [`ClientError::Usage`] describing the first limit the key breaks.
pub(crate) fn presentable<'k>(
    key: &'k Key,
    replacement: &dyn Signer,
    proof: SessionProof,
) -> Result<(&'k KeyObject, PublicKey), ClientError> {
    let usage = |m: &str| ClientError::Usage(format!("rotate_key: {m}"));
    let Some(object) = key.as_value() else {
        return Err(usage(
            "this session presents a new key by value only; a key reference cannot be \
             checked here (RFC 9635 §6.1.1, §7.1)",
        ));
    };
    object.validate().map_err(|e| usage(&e.to_string()))?;
    // The session established `httpsig` in its named form, with no proofing
    // parameters at all. Any parameter, known or not, is a change this session
    // cannot present as "the same"; none is ignored.
    let parameterised = matches!(
        &object.proof,
        gnap_types::key::Proof::Detailed { params, .. } if !params.is_empty()
    );
    let method = match proof {
        SessionProof::Httpsig => KeyProofingMethod::Httpsig,
        SessionProof::Jose(JwsMethod::Jws) => KeyProofingMethod::Jws,
        SessionProof::Jose(JwsMethod::Jwsd) => KeyProofingMethod::Jwsd,
    };
    if object.proof.method() != &method || parameterised {
        return Err(usage(&format!(
            "the new key must use the {} proofing method with the same parameters as the \
             current key, which has none; \"The proofing method and parameters for the new \
             key MUST be the same as those established for the previous key\" \
             (RFC 9635 §6.1.1)",
            method.as_str()
        )));
    }
    let Some(jwk) = object.jwk.as_ref() else {
        return Err(usage(
            "this session presents the new key as a JWK; certificates need a \
             certificate-aware adapter (RFC 9635 §7.1)",
        ));
    };
    // §6.1.1 — "keys passed by value are always public keys". The JWK import
    // refuses private members, certificate members and unusable keys, and
    // checks that the JWK actually describes a key `httpsig` accepts.
    let verifier = match proof {
        SessionProof::Httpsig => PublicKey::for_httpsig(jwk),
        SessionProof::Jose(_) => PublicKey::for_jws(jwk),
    }
    .map_err(|e| usage(&e.to_string()))?;
    if matches!(proof, SessionProof::Jose(_)) && verifier.algorithm() != replacement.algorithm() {
        return Err(usage(
            "the presented JWK `alg` must be the new signer's, which its proof carries \
             (RFC 9635 §7.3.3, §7.3.4)",
        ));
    }
    if object.jwk_key_id() != Some(replacement.key_id()) {
        return Err(usage(
            "the presented JWK `kid` must be the `keyid` the new signer uses; when the key \
             is a JWK the signature's keyid MUST be its kid (RFC 9635 §7.3.1)",
        ));
    }
    Ok((object, verifier))
}

/// Signs a token-management request with the current key, then with the new
/// key so that the second signature covers the first (§7.3.1.1).
///
/// The request must carry its JSON body and no security headers yet. The
/// body receives a SHA-256 Content-Digest and the management credential goes
/// in Authorization; both signatures cover the method, target URI, digest and
/// Authorization (§7.3.1). The new key's signature additionally covers the
/// `Signature` and `Signature-Input` members of the first signature, carries
/// the `gnap-rotate` tag and the new signer's `keyid`, and uses its own nonce.
///
/// # Errors
///
/// Rejects a request that already carries a security header or no body, and
/// reports signing or randomness failures.
pub(crate) fn sign_key_rotation(
    request: HttpRequest,
    current: &dyn Signer,
    replacement: &dyn Signer,
    presented: &dyn Verifier,
    management: &TokenValue,
    now: u64,
) -> Result<HttpRequest, ClientError> {
    if request.body.as_ref().is_none_or(Vec::is_empty) {
        return Err(ClientError::Usage(
            "a key rotation request carries the new key in its body (RFC 9635 §6.1.1)".into(),
        ));
    }
    let mut request = crate::signing::sign_request_labelled(
        request,
        current,
        Some(management),
        now,
        PREVIOUS_LABEL,
    )?;
    let digest = request.combined_header_value("content-digest");
    let authorization = request.combined_header_value("authorization");
    let components = vec![
        Component::Method,
        Component::TargetUri,
        Component::ContentDigest,
        Component::Authorization,
        Component::DictionaryMember {
            field: "signature".into(),
            key: PREVIOUS_LABEL.into(),
        },
        Component::DictionaryMember {
            field: "signature-input".into(),
            key: PREVIOUS_LABEL.into(),
        },
    ];
    let message = Message {
        method: &request.method,
        target_uri: &request.url,
        content_digest: digest.as_deref(),
        authorization: authorization.as_deref(),
        other: Vec::new(),
    }
    .with_dictionary_fields(&components, |name| {
        request.header_values(name).collect::<Vec<_>>()
    })?;
    // Two fresh nonces from the same source do not repeat; the verifier
    // refuses equal nonces, so a repeat is a failing randomness source, and
    // that is reported rather than retried.
    let nonce = fresh_nonce()?;
    if previous_nonce(&request).as_deref() == Some(nonce.as_str()) {
        return Err(ClientError::Usage(
            "the nonce source repeated a value; the two rotation proofs need distinct \
             nonces and no request was sent"
                .into(),
        ));
    }
    let input = SignatureInput {
        components,
        created: now,
        keyid: replacement.key_id().to_owned(),
        nonce: Some(nonce),
        tag: Tag::GnapRotate,
    };
    let (signature_input, signature) = sign(&message, &input, &replacement, REPLACEMENT_LABEL)?;
    // A `kid` is a name, not a key: the presented JWK has to be the public
    // half of the key that just signed, or the AS would bind the token to a
    // key this session cannot use. The real signature settles that locally.
    let unverifiable = || {
        ClientError::Usage(
            "rotate_key: the presented JWK does not verify the new signer's signature; the key \
             the AS would bind is not the key this session would use"
                .into(),
        )
    };
    let produced = parse_signatures(&signature_input, &signature);
    let candidate = produced
        .into_iter()
        .flatten()
        .find(|candidate| candidate.label == REPLACEMENT_LABEL)
        .ok_or_else(unverifiable)?;
    let base = signature_base(&message, &input.components, &candidate.raw_params)?;
    presented
        .verify(base.as_bytes(), &candidate.signature)
        .map_err(|_| unverifiable())?;
    request = request
        .header("Signature-Input", signature_input)
        .header("Signature", signature);
    Ok(request)
}

fn previous_nonce(request: &HttpRequest) -> Option<String> {
    let input = request.combined_header_value("signature-input")?;
    let raw = input.strip_prefix(&format!("{PREVIOUS_LABEL}="))?;
    gnap_crypto::parse_signature_params(raw).ok()?.nonce
}

/// Signs a key rotation with JOSE proofs (§7.3.3.1, §7.3.4.1): the current
/// key signs the request with the rotation `typ`, and the new key signs that
/// JWS. Both proofs are checked under their public JWKs before anything leaves.
///
/// # Errors
///
/// Reports signing failures, and a proof that doesn't verify under the key
/// it claims, as [`ClientError::Usage`].
#[allow(
    clippy::too_many_arguments,
    reason = "Each argument is a distinct part of the rotation; grouping them would only hide that"
)]
pub(crate) fn sign_jose_rotation(
    uri: &str,
    method: JwsMethod,
    content: Vec<u8>,
    current: &dyn Signer,
    replacement: &dyn Signer,
    keys: (&PublicKey, &PublicKey),
    management: &TokenValue,
    now: u64,
) -> Result<HttpRequest, ClientError> {
    let proof = sign_jws_rotation(
        method,
        &JwsParams {
            method: "POST",
            target_uri: uri,
            created: now,
            access_token: Some(management.as_str()),
        },
        &content,
        current,
        replacement,
    )?;
    let request = crate::signing::jose_request(
        HttpRequest::new("POST", uri),
        proof,
        content,
        Some(management),
    );
    let unreserved = |_: &[ReplayId], _: u64| true;
    verify_jws_rotation(
        method,
        &crate::signing::signed_view(&request),
        &JwsKey::for_public_key(keys.0, now, 0),
        &JwsKey::for_public_key(keys.1, now, 0),
        &unreserved,
    )
    .map_err(|e| {
        ClientError::Usage(format!(
            "rotate_key: the rotation proofs don't verify under the current and new JWKs: {e}"
        ))
    })?;
    Ok(request)
}
