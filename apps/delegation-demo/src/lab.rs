//! Who the lab's own clients are.
//!
//! Each browser session of the lab is a client: named by reference when it
//! proves with the application's shared key over `httpsig`, or by the public
//! key it presents by value when it proves with its own key over `jws` or
//! `jwsd`. [`LabKeys`] is the one registry of those clients, and the one place
//! a request's client is classified from.
//!
//! Its lock is a leaf: nothing else is locked while it is held, and it is held
//! only for map lookups and equality checks. It can therefore be taken under
//! the consent registry's lock or the grant storage's, in either order,
//! without an inversion. A key's thumbprint, which takes hashing, is computed
//! by the caller before taking it.

use gnap_crypto::jws::JwsMethod;
use gnap_crypto::proof::{ProofError, Signer};
use gnap_crypto::{Ed25519Signer, JwkSigner, Ps256Signer, PublicKey};
use gnap_registry::KeyProofingMethod;
use gnap_types::client::Client;
use gnap_types::key::KeyObject;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The registry shared by the worker, the authorization server and the
/// resource servers. A leaf lock: see the module documentation.
pub(super) type SharedLabKeys = Arc<Mutex<LabKeys>>;

/// What a request's client is to the lab, at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ClientClass {
    /// A live session of the lab, by its identifier.
    Lab(String),
    /// A client the lab doesn't know as its own: a candidate for the external
    /// client path, which applies its own checks. Being external grants
    /// nothing by itself.
    External,
    /// A client that resembles one of the lab's but doesn't match it, or whose
    /// session has ended: refused, and never handed to the external path.
    Unknown,
}

#[derive(Debug)]
struct LabKey {
    session: String,
    key: KeyObject,
    deadline: Instant,
}

/// Why a client couldn't be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistrationError {
    /// Another live client already holds this key.
    Collision,
    /// The registry holds as many clients as the lab allows.
    Full,
}

/// The lab's clients, each until its session's deadline.
#[derive(Debug)]
pub(super) struct LabKeys {
    capacity: usize,
    references: HashMap<String, Instant>,
    keys: HashMap<String, LabKey>,
}

impl Default for LabKeys {
    /// As many clients as the lab has sessions.
    fn default() -> Self {
        Self::new(super::MAX_SESSIONS)
    }
}

impl LabKeys {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            references: HashMap::new(),
            keys: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.references.len() + self.keys.len()
    }

    /// Registers a session that proves with the shared key, by reference.
    pub(super) fn register_reference(
        &mut self,
        session: &str,
        deadline: Instant,
    ) -> Result<(), RegistrationError> {
        if self.references.contains_key(session) {
            return Err(RegistrationError::Collision);
        }
        if self.len() >= self.capacity {
            return Err(RegistrationError::Full);
        }
        self.references.insert(session.to_owned(), deadline);
        Ok(())
    }

    /// Registers a session that proves with its own key, presented by value.
    /// A thumbprint another client holds is refused, never overwritten.
    pub(super) fn register_key(
        &mut self,
        session: &str,
        thumbprint: String,
        key: KeyObject,
        deadline: Instant,
    ) -> Result<(), RegistrationError> {
        if self.keys.contains_key(&thumbprint) {
            return Err(RegistrationError::Collision);
        }
        if self.len() >= self.capacity {
            return Err(RegistrationError::Full);
        }
        self.keys.insert(
            thumbprint,
            LabKey {
                session: session.to_owned(),
                key,
                deadline,
            },
        );
        Ok(())
    }

    /// Whether a session is registered, live or not.
    #[cfg(test)]
    pub(super) fn holds(&self, session: &str) -> bool {
        self.references.contains_key(session)
            || self.keys.values().any(|entry| entry.session == session)
    }

    /// How many clients are registered, live or not.
    #[cfg(test)]
    pub(super) fn count(&self) -> usize {
        self.len()
    }

    /// Forgets a session, whichever way it was registered.
    pub(super) fn forget(&mut self, session: &str) {
        self.references.remove(session);
        self.keys.retain(|_, entry| entry.session != session);
    }

    /// What `client` is at `now`. `thumbprint` is the thumbprint of the key
    /// the client presents by value, computed before the lock was taken.
    pub(super) fn classify(
        &self,
        client: &Client,
        thumbprint: Option<&str>,
        now: Instant,
    ) -> ClientClass {
        if let Some(session) = client.as_reference() {
            return match self.references.get(session) {
                Some(deadline) if now < *deadline => ClientClass::Lab(session.to_owned()),
                _ => ClientClass::Unknown,
            };
        }
        let Some(value) = client.as_value() else {
            return ClientClass::Unknown;
        };
        let Some(entry) = thumbprint.and_then(|thumbprint| self.keys.get(thumbprint)) else {
            return ClientClass::External;
        };
        // The lab presents its key and nothing else: a match on the key with
        // other fields, another proof, or after the session ended is no match,
        // and it doesn't fall back to the external path either.
        let exact = value.class_id.is_none()
            && value.display.is_none()
            && value.extra.is_empty()
            && value.key.as_value() == Some(&entry.key);
        if exact && now < entry.deadline {
            ClientClass::Lab(entry.session.clone())
        } else {
            ClientClass::Unknown
        }
    }
}

/// The proof method a session's client uses, chosen when it starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProofChoice {
    /// HTTP message signatures, with the application's shared key.
    #[default]
    Httpsig,
    /// An attached JWS, with the session's own key.
    Jws,
    /// A detached JWS, with the session's own key.
    Jwsd,
}

impl ProofChoice {
    /// The JOSE method, for the choices that use one.
    pub(super) const fn jose(self) -> Option<JwsMethod> {
        match self {
            Self::Httpsig => None,
            Self::Jws => Some(JwsMethod::Jws),
            Self::Jwsd => Some(JwsMethod::Jwsd),
        }
    }

    /// The proofing method the session's key declares.
    pub(super) const fn method(self) -> KeyProofingMethod {
        match self {
            Self::Httpsig => KeyProofingMethod::Httpsig,
            Self::Jws => KeyProofingMethod::Jws,
            Self::Jwsd => KeyProofingMethod::Jwsd,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Httpsig => "httpsig",
            Self::Jws => "jws",
            Self::Jwsd => "jwsd",
        }
    }
}

/// The body a start may carry: the proof method, and nothing else.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartBody {
    pub proof: ProofChoice,
}

/// Longest start body read, in bytes.
pub(super) const MAX_START_BODY: usize = 64;

/// What a lab session signs with: the application's shared key, over
/// `httpsig`, or the key the session generated, over `jws` or `jwsd`.
#[derive(Clone)]
pub(super) enum LabSigner<'a> {
    Shared(&'a Ps256Signer),
    Own(Arc<Ed25519Signer>),
}

impl Signer for LabSigner<'_> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        match self {
            Self::Shared(key) => key.sign(data),
            Self::Own(key) => key.sign(data),
        }
    }
    fn key_id(&self) -> &str {
        match self {
            Self::Shared(key) => key.key_id(),
            Self::Own(key) => key.key_id(),
        }
    }
    fn algorithm(&self) -> &'static str {
        match self {
            Self::Shared(key) => key.algorithm(),
            Self::Own(key) => key.algorithm(),
        }
    }
}

impl JwkSigner for LabSigner<'_> {
    fn public_jwk(&self) -> Result<serde_json::Map<String, serde_json::Value>, ProofError> {
        match self {
            Self::Shared(key) => key.public_jwk(),
            Self::Own(key) => key.public_jwk(),
        }
    }
    fn thumbprint(&self) -> String {
        match self {
            Self::Shared(key) => JwkSigner::thumbprint(*key),
            Self::Own(key) => JwkSigner::thumbprint(key.as_ref()),
        }
    }
}

/// The RFC 7638 thumbprint of the key a client presents by value, if it is a
/// public JWK the crypto library reads. Computed outside the registry's lock.
pub(super) fn presented_thumbprint(client: &Client) -> Option<String> {
    let key = client.as_value()?.key.as_value()?;
    key_thumbprint(key)
}

/// The RFC 7638 thumbprint of a key's JWK.
pub(super) fn key_thumbprint(key: &KeyObject) -> Option<String> {
    PublicKey::from_jwk(key.jwk.as_ref()?)
        .ok()
        .map(|public| public.thumbprint())
}

/// Classifies `client` against `keys`: the thumbprint first, then the lock.
pub(super) fn classify(keys: &SharedLabKeys, client: &Client, now: Instant) -> ClientClass {
    let thumbprint = presented_thumbprint(client);
    keys.lock().map_or(ClientClass::Unknown, |keys| {
        keys.classify(client, thumbprint.as_deref(), now)
    })
}

#[cfg(test)]
#[path = "lab_tests.rs"]
mod tests;
