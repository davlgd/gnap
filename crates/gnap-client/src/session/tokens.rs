//! Token management (§6): signers, rotation, and revocation of issued tokens.

use super::response::grant_response;
use super::{Session, SessionProof, SharedSigner};
use crate::error::ClientError;
use crate::rotation;
use crate::transport::{HttpRequest, HttpResponse, HttpTransport};
use gnap_crypto::proof::Signer;
use gnap_registry::AccessTokenFlag;
use gnap_types::key::Key;
use gnap_types::message::GrantResponse;
use gnap_types::token::{AccessToken, Cardinality, TokenManage, TokenValue};

impl<T: HttpTransport, S: Signer> Session<T, S> {
    /// Rotates a token's value through its management API (§6.1).
    ///
    /// "Rotating an access token consists of issuing a new access token in
    /// place of an existing access token, with the same rights and properties
    /// as the original token, apart from an updated token value and expiration
    /// time." The rights cannot be changed here: §6.1 sends a client that wants
    /// different access to the continuation API (§5.3) or to a new grant.
    ///
    /// `label` names the token when several are held (§3.2.2); `None` selects
    /// the token when exactly one is held, labelled or not. The rotated token
    /// replaces it in the session, with the new management URI §6.1-M04
    /// requires the client to use from then on.
    ///
    /// The rotation answers with one token in the form of §3.2.1, whatever
    /// the shape of the grant that issued it; the session refuses an array.
    ///
    /// §6.1 describes the rotated token as having "the same rights and
    /// properties as the original token, apart from an updated token value and
    /// expiration time". Of the properties compared here (rights, label, flags
    /// and key), only the rights carry a stated MUST (§6.1-M05). For the rest,
    /// this session compares meaning rather than bytes and refuses what it cannot
    /// keep presenting as the same token: a label the answer omits is kept, a
    /// changed label is refused since the label is how the session names the
    /// token; flags are compared as a set; a `key` field is unchanged only when
    /// both answers omit it or both spell out the same key, since the session
    /// holds no key material to compare and a `kid` is a name, not a key
    /// (§3.2.1). Binding another key is a different operation (§6.1.1) that
    /// this method does not perform; use [`Self::rotate_key`] instead.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, when it carries no `manage` field,
    /// when the AS refuses the rotation, or when the answer does not keep the
    /// rights §6.1-M05 requires it to keep, repeats the value §6.1 forbids it to
    /// repeat, or changes the label, flags or key binding as described above.
    pub fn rotate_token(
        &mut self,
        label: Option<&str>,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let (index, manage) = self.managed(label)?;
        let previous_value = self.held_value(index)?;
        let signer = self.management_signer(index)?;
        let response = self.call_management("POST", &manage, None, signer, now)?;
        let parsed = grant_response(&response)?;

        let rotated = {
            let previous = &self.held(index)?.1;
            let rotated = checked_rotation(parsed, previous, &manage)?;
            if !same_binding(rotated.key.as_ref(), previous.key.as_ref()) {
                return Err(ClientError::Protocol(
                    "the session cannot establish that the rotated token keeps the original \
                     token's key binding; binding a new key is a separate operation, \
                     `rotate_key` (RFC 9635 §6.1, §6.1.1)"
                        .into(),
                ));
            }
            rotated
        };
        self.adopt_rotated(index, &previous_value, rotated, None, now)
    }

    /// Binds a new key to a held token (§6.1.1), keeping its value's lifecycle.
    ///
    /// The request carries `presented`, the new public key, in its content,
    /// and two proofs, with the session's proof method. With `httpsig`, the
    /// token's current key signs as usual, then `replacement` signs with the
    /// `gnap-rotate` tag over that first signature (§7.3.1.1). With `jws` or
    /// `jwsd`, the current key signs the request with the rotation `typ`, and
    /// `replacement` signs that JWS (§7.3.3.1, §7.3.4.1); both are checked
    /// under their public JWKs before anything leaves. `presented` must be a
    /// public JWK by value of the session's method and an algorithm it takes,
    /// whose `kid` is the one of `replacement`, and for `jws` and `jwsd` whose
    /// `alg` is too; the new key may use another algorithm than the old one. A
    /// reference, another format, another proofing method or any proofing
    /// parameter, a private or symmetric member, a certificate or a mismatched
    /// `kid` is refused before anything is sent; these are the limits of this
    /// session.
    ///
    /// The answer is checked like a value rotation (one token in the form of
    /// §3.2.1, new value, same rights, kept label, same flags, a management
    /// URI) and, in addition, has to name the new key: §3.2.1 makes an omitted
    /// `key` mean the key of the grant request, so only a `key` equal to
    /// `presented` shows that the AS bound the token to the new key. From then
    /// on this session signs that token's management with `replacement`, and
    /// [`Session::signer_for`] hands it to the application for its resource
    /// requests. The continuation keeps the session's signer, and every other
    /// token keeps the signer it has, rotated or not. A bearer token has no key
    /// to rotate (§6.1.1) and is refused before anything is sent. Any refusal
    /// leaves the token, its key and this session unchanged (§6.1: the client
    /// "MUST consider the access token to not have changed its state").
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] when the key cannot be presented by this session
    /// or no such managed token is held; [`ClientError::Server`] for a GNAP
    /// error such as `invalid_rotation` or `key_rotation_not_supported`;
    /// [`ClientError::Protocol`] when the answer breaks a rule above.
    ///
    /// `replacement` must be `Send + Sync + 'static`, so that a session holding
    /// it can move between threads. A signer that is `Send` but not `Sync`
    /// meets that bound behind a `Mutex`, in a wrapper of your own.
    ///
    /// The session keeps its handle on `replacement` only after a successful
    /// response. A value rotation carries it forward; another key change, a
    /// confirmed revocation, a newly issued lot or the end of the session
    /// releases it. Keep a clone if the application needs the key after an
    /// inconclusive exchange: a failed response doesn't undo a change already
    /// made at the AS, and the session doesn't adopt the key on failure.
    pub fn rotate_key(
        &mut self,
        label: Option<&str>,
        replacement: SharedSigner,
        presented: &Key,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        self.rotate_key_with(label, replacement, presented, now)
    }

    fn rotate_key_with(
        &mut self,
        label: Option<&str>,
        replacement: SharedSigner,
        presented: &Key,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let (object, verifier) =
            rotation::presentable(presented, replacement.as_ref(), self.session_proof())?;
        let (index, manage) = self.managed(label)?;
        let previous_value = self.held_value(index)?;
        let (proof, current) = self.presentation(index)?;
        let body = serde_json::to_vec(&serde_json::json!({ "key": object }))
            .map_err(|e| ClientError::Usage(format!("serializing the new key: {e}")))?;
        let http = match proof {
            SessionProof::Httpsig => rotation::sign_key_rotation(
                HttpRequest::new("POST", &manage.uri).json_body(body),
                current,
                replacement.as_ref(),
                &verifier,
                &manage.access_token.value,
                now,
            )?,
            SessionProof::Jose(method) => {
                let previous = self.current_key(index)?;
                rotation::sign_jose_rotation(
                    &manage.uri,
                    method,
                    body,
                    current,
                    replacement.as_ref(),
                    (&previous, &verifier),
                    &manage.access_token.value,
                    now,
                )?
            }
        };
        let response = self.round_trip(http)?;
        let parsed = grant_response(&response)?;

        let rotated = {
            let previous = &self.held(index)?.1;
            let rotated = checked_rotation(parsed, previous, &manage)?;
            // §3.2.1 — `key` is "The key that the token is bound to, if
            // different from the client instance's presented key"; omitted, it
            // means the grant request's key (§2.3), not the key of this body.
            // Only an explicit, identical key shows the new binding took.
            if rotated.key.as_ref() != Some(presented) {
                return Err(ClientError::Protocol(
                    "the key-rotation response does not name the presented key as the \
                     token's key binding; an omitted or different key means the AS did not \
                     bind the token to the new key (RFC 9635 §3.2.1, §6.1.1)"
                        .into(),
                ));
            }
            rotated
        };
        self.adopt_rotated(index, &previous_value, rotated, Some(replacement), now)
    }

    /// The signer that presents a held token: the key it was rotated to, or
    /// the session's key. The application signs its resource requests with it.
    /// A token does not need a management API to be presented to a resource.
    ///
    /// This session knows its implicit grant key and keys adopted by its own
    /// successful rotations. An initially issued explicit key is not resolved
    /// here, even if it might be equivalent to the grant key: matching a `kid`
    /// does not establish that equivalence. Such a token needs an application
    /// adapter. A bearer token is presented without a key proof.
    /// The returned reference borrows this session, including when the signer
    /// was supplied as an owned handle; do not keep it across a mutable call.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, the token is bearer, or its explicit
    /// binding is not known to this session. `None` is ambiguous with several
    /// held tokens. No request is sent and no signature is made by this lookup.
    ///
    /// The signer isn't a proof method: [`sign_request`](crate::sign_request)
    /// proves with `httpsig`, whatever proof the session's grant uses.
    pub fn signer_for(&self, label: Option<&str>) -> Result<&dyn Signer, ClientError> {
        self.presentation(self.select(label)?)
            .map(|(_, signer)| signer)
    }

    /// The proof method and the signer that present a token's key: the
    /// session's method, which a key change keeps (§6.1.1), and the key the
    /// token was rotated to, or the session's.
    fn presentation(&self, index: usize) -> Result<(SessionProof, &dyn Signer), ClientError> {
        let token = &self.held(index)?.1;
        if token.is_bearer() {
            return Err(ClientError::Usage(
                "a bearer token has no presentation key; present it without a key proof".into(),
            ));
        }
        if let Some(signer) = self.rotated.get(token.value.as_str()) {
            return Ok((self.session_proof(), signer.as_ref()));
        }
        if token.key.is_some() {
            return Err(ClientError::Usage(
                "this session cannot establish the signer for an initially explicit token key; \
                 an application key adapter is required"
                    .into(),
            ));
        }
        Ok((self.session_proof(), &self.signer))
    }

    /// The public JWK of a token's current key, for the session's own JOSE
    /// proofs: the key the token was rotated to, or the first request's.
    fn current_key(&self, index: usize) -> Result<gnap_crypto::PublicKey, ClientError> {
        let token = &self.held(index)?.1;
        let key = if self.rotated.contains_key(token.value.as_str()) {
            token.key.as_ref().and_then(gnap_types::key::Key::as_value)
        } else {
            self.protocol.key.as_ref()
        };
        key.and_then(|key| key.jwk.as_ref())
            .and_then(|jwk| gnap_crypto::PublicKey::for_jws(jwk).ok())
            .ok_or_else(|| {
                ClientError::Usage(
                    "the session doesn't know the public JWK of the token's current key".into(),
                )
            })
    }

    fn management_signer(&self, index: usize) -> Result<(SessionProof, &dyn Signer), ClientError> {
        // §7.3 binds bearer-token management to the client instance's key.
        if self.held(index)?.1.is_bearer() {
            Ok((self.session_proof(), &self.signer))
        } else {
            self.presentation(index)
        }
    }

    fn held(&self, index: usize) -> Result<&(u64, AccessToken), ClientError> {
        self.protocol
            .issued
            .as_ref()
            .and_then(|held| held.get(index))
            .ok_or_else(|| {
                ClientError::Usage("the session no longer holds the token that was rotated".into())
            })
    }

    fn held_value(&self, index: usize) -> Result<TokenValue, ClientError> {
        Ok(self.held(index)?.1.value.clone())
    }

    /// Installs a rotated token and moves or sets its signer, on success only.
    fn adopt_rotated(
        &mut self,
        index: usize,
        previous_value: &TokenValue,
        rotated: AccessToken,
        new_signer: Option<SharedSigner>,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let Some(held) = self.protocol.issued.as_mut() else {
            return Err(ClientError::Usage(
                "the session no longer holds the token that was rotated".into(),
            ));
        };
        // The session tells its tokens, and their signers, apart by value. A
        // value that already names a sibling cannot be adopted without
        // confusing the two; GNAP expects distinct values anyway (§3.2.2:
        // "each access token is expected to have a unique value").
        if held
            .iter()
            .enumerate()
            .any(|(i, (_, token))| i != index && token.value == rotated.value)
        {
            return Err(ClientError::Protocol(
                "the rotated token repeats the value of another token this session holds; \
                 the session cannot tell them apart (RFC 9635 §3.2.2)"
                    .into(),
            ));
        }
        let carried = self.rotated.remove(previous_value.as_str());
        if let Some(signer) = new_signer.or(carried) {
            self.rotated
                .insert(rotated.value.as_str().to_owned(), signer);
        }
        // §6.1 — the rotation carries "an updated token value and expiration
        // time", so `expires_in` starts running again, from now.
        held[index] = (now, rotated.clone());
        Ok(rotated)
    }

    /// Revokes a token through its management API (§6.2).
    ///
    /// §6.2 is for the client's own use: when the user says they no longer want
    /// it to have access, or the application sees itself being uninstalled.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, when it carries no `manage` field, or
    /// when the exchange does.
    pub fn revoke_token(&mut self, label: Option<&str>, now: u64) -> Result<(), ClientError> {
        let (index, manage) = self.managed(label)?;
        let value = self.held_value(index)?;
        let signer = self.management_signer(index)?;
        let response = self.call_management("DELETE", &manage, None, signer, now)?;

        if response.status != 204 {
            // §3.6 — a well-formed GNAP error is the AS's refusal, not a
            // malformed answer, and the token's state is unchanged. "Other
            // fields MUST NOT be included": the raw object is checked, since
            // parsing drops a known field whose value is null.
            let only_error = serde_json::from_slice::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|body| {
                    body.as_object()
                        .map(|fields| fields.keys().all(|k| k == "error"))
                })
                .unwrap_or(false);
            if let (
                true,
                Ok(GrantResponse {
                    error: Some(error), ..
                }),
            ) = (only_error, grant_response(&response))
            {
                return Err(ClientError::Server(error));
            }
            return Err(ClientError::Protocol(format!(
                "revoking answered {} where §6.2 says 204 No Content",
                response.status
            )));
        }
        if let Some(tokens) = self.protocol.issued.as_mut() {
            tokens.remove(index);
        }
        self.rotated.remove(value.as_str());
        Ok(())
    }

    /// Finds a held token by label, independently of its management API.
    ///
    /// `None` names the only token held, whether or not it carries a label
    /// (§3.2.1 lets the AS label a single token); with several held, a caller
    /// has to say which one, since the labels are what tells them apart
    /// (§3.2.2).
    fn select(&self, label: Option<&str>) -> Result<usize, ClientError> {
        let tokens = self.protocol.issued.as_ref().ok_or_else(|| {
            ClientError::Usage("no access token has been issued to this session".into())
        })?;
        let index = match label {
            Some(wanted) => tokens
                .iter()
                .position(|(_, t)| t.label.as_deref() == Some(wanted))
                .ok_or_else(|| {
                    ClientError::Usage(format!("no access token is labelled {wanted:?}"))
                })?,
            None if tokens.len() == 1 => 0,
            None => {
                return Err(ClientError::Usage(format!(
                    "{} access tokens are held; select one by its label \
                     (RFC 9635 §3.2.2)",
                    tokens.len()
                )));
            }
        };
        Ok(index)
    }

    /// Finds the selected token's optional management API (§3.2.1).
    fn managed(&self, label: Option<&str>) -> Result<(usize, TokenManage), ClientError> {
        let index = self.select(label)?;
        let manage = self.held(index)?.1.manage.clone().ok_or_else(|| {
            ClientError::Usage(
                "this access token carries no `manage` field, so there is no management \
                 API to call (RFC 9635 §3.2.1, §6)"
                    .into(),
            )
        })?;
        Ok((index, manage))
    }

    /// Makes a signed call to a token management URI (§6, §7.2).
    fn call_management(
        &self,
        method: &str,
        manage: &TokenManage,
        body: Option<Vec<u8>>,
        (proof, signer): (SessionProof, &dyn Signer),
        now: u64,
    ) -> Result<HttpResponse, ClientError> {
        // §6 — "The client instance MUST present proof of the key associated
        // with the token along with the value of the token management access
        // token", which is §7.2 applied to the management token. After a key
        // rotation (§6.1.1) that key is the token's new key, not the session's.
        let http = Self::signed_request(
            proof,
            method,
            &manage.uri,
            body,
            Some(&manage.access_token.value),
            signer,
            now,
        )?;
        self.round_trip(http)
    }
}

/// The checks a rotation answer has to pass before either kind of rotation
/// looks at the key binding (§6.1).
fn checked_rotation(
    parsed: GrantResponse,
    previous: &AccessToken,
    manage: &TokenManage,
) -> Result<AccessToken, ClientError> {
    if let Some(e) = parsed.error {
        // §6.1-M06 — "Upon receiving such an error, the client instance
        // MUST consider the access token to not have changed its state."
        // Nothing here has touched what the session holds.
        return Err(ClientError::Server(e));
    }

    // §6.1 — the AS responds with "the rotated access token in the
    // access_token field described in Section 3.2.1": one token object,
    // even when the grant issued several (§3.2.2). Taking the first entry
    // of an array would silently accept a different exchange.
    let Some(tokens) = parsed.access_token else {
        return Err(ClientError::Protocol(
            "the rotation response carries no access token (RFC 9635 §6.1)".into(),
        ));
    };
    if tokens.cardinality != Cardinality::Single || tokens.tokens.len() != 1 {
        return Err(ClientError::Protocol(
            "the rotation response carries several access tokens where §6.1 describes \
             one rotated token in the form of §3.2.1"
                .into(),
        ));
    }
    let mut rotated = tokens
        .tokens
        .into_iter()
        .next()
        .ok_or_else(|| ClientError::Protocol("the rotation response is empty".into()))?;
    rotated
        .validate()
        .map_err(|e| ClientError::Protocol(e.to_string()))?;

    // §6.1 — "The value of the access token MUST NOT be the same as the
    // current value of the access token used to access the management API."
    if rotated.value == manage.access_token.value {
        return Err(ClientError::Protocol(
            "the rotated token reuses the previous management credential (RFC 9635 §6.1)".into(),
        ));
    }
    // The same section describes replacing the resource token with an
    // updated value. Its old value and the management credential above
    // are distinct: neither may become the new resource token.
    if rotated.value == previous.value {
        return Err(ClientError::Protocol(
            "the rotated token repeats the value it was meant to replace (RFC 9635 §6.1)".into(),
        ));
    }
    // §6.1-M05 — "The access rights in the access array for the rotated
    // access token MUST be included in the response and MUST be the same as
    // the token before rotation."
    if rotated.access != previous.access {
        return Err(ClientError::Protocol(
            "the rotated token does not carry the same access rights as the token it \
             replaces (RFC 9635 §6.1)"
                .into(),
        ));
    }
    // §6.1 — a rotation issues a token "with the same rights and properties
    // as the original token, apart from an updated token value and
    // expiration time". That sentence describes the operation; it states
    // no MUST beyond the rights. What follows is this session's reading of
    // it: the label is the name the session manages the token by (§3.2.2),
    // and the flags decide how it is presented (§7.2), so a token that
    // changes them is not one the session can go on using as the same.
    match (&rotated.label, &previous.label) {
        (None, kept) => rotated.label.clone_from(kept),
        (Some(answered), Some(kept)) if answered == kept => {}
        (Some(_), _) => {
            return Err(ClientError::Protocol(
                "the rotated token changes the label the session manages the token by; \
                 this session keeps a rotated token under its original label \
                 (RFC 9635 §6.1 describes a rotation as keeping the token's properties)"
                    .into(),
            ));
        }
    }
    if !same_flags(&rotated.flags, &previous.flags) {
        return Err(ClientError::Protocol(
            "the rotated token changes the flags of the token it replaces; this session \
             does not present a rotated token differently from the original \
             (RFC 9635 §6.1)"
                .into(),
        ));
    }
    // §6.1-M03 — "The response MUST include an access token management
    // URI", which §6.1-M04 has the client use from now on.
    if rotated.manage.is_none() {
        return Err(ClientError::Protocol(
            "the rotated token carries no management URI (RFC 9635 §6.1)".into(),
        ));
    }
    Ok(rotated)
}

/// Whether two flag lists say the same thing (§3.2.1).
///
/// Flags are a set: §3.2.1 forbids repeating one, and their order carries no
/// meaning, so `["durable", "x"]` and `["x", "durable"]` are the same flags.
fn same_flags(answered: &[AccessTokenFlag], previous: &[AccessTokenFlag]) -> bool {
    answered.len() == previous.len() && answered.iter().all(|flag| previous.contains(flag))
}

/// Whether two `key` fields are known to name the same binding (§3.2.1).
///
/// An omitted `key` binds the token to the key the client presented, which is
/// the session's signer. The session holds no copy of its public key, only
/// the `kid` it signs with, and a `kid` is a name, not a key: two different
/// keys can carry the same one. So an answer that spells a key out where the
/// original omitted it, or the reverse, cannot be established as unchanged
/// and is refused; two explicit fields have to match as written. A caller
/// that can compare key material has to do so outside the session.
fn same_binding(answered: Option<&Key>, previous: Option<&Key>) -> bool {
    match (answered, previous) {
        (None, None) => true,
        (Some(a), Some(p)) => a == p,
        (Some(_), None) | (None, Some(_)) => false,
    }
}
