//! Key proofing and interaction hashing for GNAP.
//!
//! This crate covers what RFC [9635] calls "Securing Requests from the Client
//! Instance" (§7) plus the interaction hash (§4.2.3). It performs no I/O: it
//! produces and verifies bytes.
//!
//! [9635]: https://www.rfc-editor.org/rfc/rfc9635

pub mod digest;
pub mod hash;
pub mod httpsig;
pub mod proof;
pub mod ps256;
pub mod verify;

pub use digest::{content_digest, verify_content_digest, DigestAlgorithm};
pub use hash::{
    interaction_hash, interaction_hash_named, verify_interaction_hash, HashError, HashMethod,
    InteractionHashInput,
};
pub use httpsig::{parse_signature_params, parse_signatures, LabelledSignature, ReceivedParams};
pub use proof::{ProofError, Signer, Verifier};
pub use ps256::{Ps256Signer, Ps256Verifier};
pub use verify::{verify_request, Accepted, Expectations, NonceMemory, SignedRequest, VerifyError};
