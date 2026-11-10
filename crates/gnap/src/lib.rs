//! GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) and its
//! resource-server connections ([RFC 9767](https://www.rfc-editor.org/rfc/rfc9767))
//! in one dependency.
//!
//! This crate only re-exports the `gnap-*` crates, each under a module. The
//! message types, the registries, the request proofs and the grant-state
//! machine are always there; each protocol role is behind a feature:
//!
//! | Module          | Crate              | Feature       |
//! | --------------- | ------------------ | ------------- |
//! | [`types`]       | `gnap-types`       | always        |
//! | [`registry`]    | `gnap-registry`    | always        |
//! | [`crypto`]      | `gnap-crypto`      | always        |
//! | [`core`]        | `gnap-core`        | always        |
//! | `client`        | `gnap-client`      | `client`      |
//! | `server`        | `gnap-as`          | `server`      |
//! | `rs`            | `gnap-rs`          | `rs`          |
//! | `biscuit`       | `gnap-biscuit`     | `biscuit`     |
//! | `subject`       | `gnap-subject`     | `subject`     |
//! | `net`           | `gnap-net`         | `net`         |
//! | `conformance`   | `gnap-conformance` | `conformance` |
//!
//! The `full` feature enables them all. Depending on a `gnap-*` crate directly
//! gives the same items: the modules here are the crates themselves.
//!
//! ```
//! use gnap::types::GrantRequest;
//!
//! let request: GrantRequest =
//!     serde_json::from_str(r#"{"access_token":{"access":["read"]},"client":"my-client"}"#)?;
//! assert!(request.access_token.is_some());
//! # Ok::<(), serde_json::Error>(())
//! ```
//!
//! These are experimental, unaudited libraries: passing their tests isn't GNAP
//! conformance, and they haven't had an independent security review.

/// GNAP messages, parsed and serialized, with their extension fields.
pub use gnap_types as types;

/// The GNAP IANA registries.
pub use gnap_registry as registry;

/// Request proofs, content digests, and interaction hashes.
pub use gnap_crypto as crypto;

/// Grant-state transitions and response constraints.
pub use gnap_core as core;

/// The client role: grant requests, interaction, continuation, and token management.
#[cfg(feature = "client")]
pub use gnap_client as client;

/// The authorization server role.
#[cfg(feature = "server")]
pub use gnap_as as server;

/// The resource server role: introspection and local proof checks.
#[cfg(feature = "rs")]
pub use gnap_rs as rs;

/// The Biscuit file-access token profile.
#[cfg(feature = "biscuit")]
pub use gnap_biscuit as biscuit;

/// Identity assertions bound to an issuer, an audience, and a session.
#[cfg(feature = "subject")]
pub use gnap_subject as subject;

/// Public-address filtering at an application's network boundaries.
#[cfg(feature = "net")]
pub use gnap_net as net;

/// Selected checks of messages and servers, without certification.
#[cfg(feature = "conformance")]
pub use gnap_conformance as conformance;
