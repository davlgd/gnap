//! Access-token representation, separate from authorization and storage.

use gnap_types::{access::AccessItem, client::Client, token::TokenValue};

/// Authorized inputs for one new access-token value.
///
/// The same contract is used for issuance and rotation. Management credentials
/// are deliberately absent. An encoder may reject unsupported rights, missing
/// public key material, or an absent expiration instead of weakening its format.
pub struct TokenEncodingContext<'a> {
    /// The configured grant endpoint identifying this AS.
    pub issuer: &'a str,
    /// The client whose proof the AS has verified.
    ///
    /// This may be a reference. An encoder needing public key material must
    /// resolve it from trusted configuration or fail; an identifier is not a key.
    pub client: &'a Client,
    /// The rights approved by policy, not the unfiltered client request.
    pub access: &'a [AccessItem],
    /// Issuance time supplied to the server, in Unix seconds.
    pub issued_at: u64,
    /// Advertised duration, already checked for deadline overflow by the AS.
    pub expires_in: Option<u64>,
    /// A fresh value from the configured nonce source.
    ///
    /// The opaque encoder uses it directly. Structured encoders may use their
    /// own format's randomness instead. It is never a management credential.
    pub candidate_nonce: &'a str,
}

/// A token representation and an optional format-native status identifier.
pub struct EncodedToken {
    /// The value sent to the client and presented to the resource server.
    pub value: TokenValue,
    /// Opaque bytes for the deployment's live-token index, if the format needs it.
    ///
    /// For an attenuable format this can identify the ancestor shared by its
    /// descendants. A replacement identifier must differ on rotation. This
    /// metadata is not sent in the GNAP response and does not itself synchronize
    /// revocation with an RS.
    /// `Some` must contain at least one byte. The encoder is responsible for
    /// avoiding collisions with identifiers of independently issued tokens;
    /// the token store does not guarantee global identifier uniqueness.
    /// A rotation may return `None` even when the previous token had an
    /// identifier. Deployments requiring an indexable format must enforce that
    /// contract in their encoder and resource-server adapter.
    pub identifier: Option<Vec<u8>>,
}

/// The configured encoder could not safely represent the authorized token.
///
/// Deliberately carries no token or key material into a protocol error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenEncodingError;

impl std::fmt::Display for TokenEncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("access-token encoding failed")
    }
}

impl std::error::Error for TokenEncodingError {}

/// Represents already authorized rights as an access token.
///
/// Implementations must preserve the supplied rights, key binding and lifetime,
/// or return an error. They do not modify storage or publish revocation state:
/// the AS can still reject their output before committing it. An error during
/// rotation leaves the existing record unchanged.
///
/// This is trusted implementation code, not a validator for arbitrary token
/// formats. The AS checks the returned wire value and identifier constraints,
/// but cannot establish that a format's protected claims match the context.
/// The encoder and the corresponding RS verifier must implement that contract.
pub trait TokenEncoder {
    /// Creates a fresh representation without changing authorization state.
    ///
    /// # Errors
    ///
    /// Returns an error when the format cannot preserve the supplied rights,
    /// key binding or lifetime, or when cryptographic encoding fails.
    fn encode(
        &self,
        context: &TokenEncodingContext<'_>,
    ) -> Result<EncodedToken, TokenEncodingError>;
}

/// The existing opaque reference-token representation.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpaqueTokenEncoder;

impl TokenEncoder for OpaqueTokenEncoder {
    fn encode(
        &self,
        context: &TokenEncodingContext<'_>,
    ) -> Result<EncodedToken, TokenEncodingError> {
        Ok(EncodedToken {
            value: TokenValue::new(context.candidate_nonce).map_err(|_| TokenEncodingError)?,
            identifier: None,
        })
    }
}
