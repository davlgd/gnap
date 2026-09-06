//! Presenting a new key for an access token (RFC 9635 §6.1.1, §7.3.1.1).
//!
//! The request carries the new public key in its body and two signatures:
//! the current key's ordinary GNAP signature, then the new key's signature,
//! tagged `gnap-rotate`, covering the first one. This module builds that
//! request; [`crate::Session::rotate_key`] sends it and reads the answer.

use crate::{ClientError, HttpRequest};
use gnap_crypto::httpsig::{
    fresh_nonce, parse_signatures, sign, signature_base, Component, Message, SignatureInput, Tag,
};
use gnap_crypto::proof::{Signer, Verifier};
use gnap_crypto::ps256::Ps256Verifier;
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
/// established for the previous key." This session signs with `httpsig` and
/// RSA PS256 keys, so it presents only a public PS256 JWK, by value, with the
/// `kid` its new signer uses. A reference, another format, another proofing
/// method, proofing parameters, a private member or a mismatched `kid` are
/// refused before anything leaves. These are the limits of this session, not
/// rules GNAP places on every client.
///
/// # Errors
///
/// [`ClientError::Usage`] describing the first limit the key breaks.
pub(crate) fn presentable<'k>(
    key: &'k Key,
    replacement: &dyn Signer,
) -> Result<(&'k KeyObject, Ps256Verifier), ClientError> {
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
    if object.proof.method() != &KeyProofingMethod::Httpsig || parameterised {
        return Err(usage(
            "the new key must use the httpsig proofing method with the same parameters as \
             the current key, which has none; \"The proofing method and parameters for the \
             new key MUST be the same as those established for the previous key\" \
             (RFC 9635 §6.1.1)",
        ));
    }
    let Some(jwk) = object.jwk.as_ref() else {
        return Err(usage(
            "this session presents the new key as a JWK; certificates need a \
             certificate-aware adapter (RFC 9635 §7.1)",
        ));
    };
    // §6.1.1 — "keys passed by value are always public keys". The PS256 parser
    // refuses private members, certificate members and unusable sizes, and
    // checks that the JWK actually describes a key.
    let verifier = Ps256Verifier::from_public_jwk(jwk).map_err(|e| usage(&e.to_string()))?;
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
    let (signature_input, signature) = sign(
        &message,
        &input,
        &crate::signing::Borrowed(replacement),
        REPLACEMENT_LABEL,
    )?;
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
