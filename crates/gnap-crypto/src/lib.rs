//! Key proofing and interaction hashing for GNAP.
//!
//! This crate covers what RFC [9635] calls "Securing Requests from the Client
//! Instance" (§7) plus the interaction hash (§4.2.3). It performs no I/O: it
//! produces and verifies bytes.
//!
//! [9635]: https://www.rfc-editor.org/rfc/rfc9635

pub mod digest;
pub mod ed25519;
pub mod es256;
pub mod hash;
pub mod httpsig;
pub mod jwk;
pub mod jws;
pub mod proof;
pub mod ps256;
pub mod rotation;
pub mod rs256;
#[allow(
    clippy::redundant_pub_crate,
    reason = "RSA helpers stay crate-private; unreachable_pub rejects pub in this module"
)]
mod rsa_key;
pub mod verify;

pub use digest::{
    DigestAlgorithm, content_digest, content_digest_algorithms, verify_content_digest,
};
pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use es256::{Es256Signer, Es256Verifier};
pub use hash::{
    HashError, HashMethod, InteractionHashInput, interaction_hash, interaction_hash_named,
    verify_interaction_hash,
};
pub use httpsig::{LabelledSignature, ReceivedParams, parse_signature_params, parse_signatures};
pub use jwk::{HTTPSIG_ALGORITHMS, JWS_ALGORITHMS, PublicKey};
pub use jws::{
    AcceptedJws, JwsKey, JwsMethod, JwsParams, JwsProof, JwsReplayMemory, ReplayCache, ReplayId,
    sign_jws, sign_jws_rotation, unverified_attached_payload, unverified_rotation_content,
    verify_jws_request, verify_jws_rotation,
};
pub use proof::{JwkSigner, ProofError, Signer, Verifier};
pub use ps256::{Ps256Signer, Ps256Verifier};
pub use rotation::{AcceptedRotation, RotationNonceMemory, RotationProof, verify_key_rotation};
pub use rs256::{Rs256Signer, Rs256Verifier};
pub use rsa_key::{MAX_MODULUS_BITS, MIN_MODULUS_BITS};
pub use verify::{
    Accepted, Expectations, NonceMemory, SignedRequest, VerifyError, verify_request,
    verify_request_with_policy,
};
