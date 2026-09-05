//! A client presents its public key by value, without pre-registration.
//!
//! ```console
//! cargo run -p gnap-as --example jwk_client --locked
//! ```
//!
//! The AS derives a verifier from the JWK inside the signed request. It has
//! neither the client's private key nor a preconfigured public key. This is
//! an in-process protocol example: no network, persistent storage, resource
//! server or real resource-owner authentication. The policy deliberately
//! grants one synthetic right to any client that proves possession of its key.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, KeyResolver, MemoryStorage, OsNonces, Policy,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_crypto::{Ps256Signer, Ps256Verifier, Verifier};
use gnap_types::{access::AccessItem, client::Client, message::GrantRequest};
use std::cell::Cell;

const GRANT: &str = "https://as.example/gnap";

/// Accepts a well-formed public key, not a self-declared client identity.
struct PresentedKey;

impl KeyResolver for PresentedKey {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        let key = client.as_value()?.key.as_value()?;
        key.validate().ok()?;
        // The AS separately enforces the declared proof method and verifies
        // the request before consulting its authorization policy.
        let verifier = Ps256Verifier::from_public_jwk(key.jwk.as_ref()?).ok()?;
        Some(Box::new(verifier))
    }
}

struct SyntheticRead;

impl Policy for SyntheticRead {
    fn evaluate(&self, _request: &GrantRequest) -> Decision {
        Decision::Approve {
            access: vec![AccessItem::Reference("synthetic-read".into())],
            subject: None,
        }
    }
}

type Server = AuthorizationServer<SyntheticRead, PresentedKey, MemoryStorage, OsNonces>;

struct Direct<'a> {
    server: &'a Server,
    now: Cell<u64>,
}

impl HttpTransport for Direct<'_> {
    type Error = String;

    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        Ok(self.server.handle(&request, self.now.get()))
    }
}

fn server() -> Server {
    AuthorizationServer::new(
        SyntheticRead,
        PresentedKey,
        MemoryStorage::new(),
        OsNonces,
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}

fn exercise(signer: &Ps256Signer) -> Result<(), Box<dyn std::error::Error>> {
    let server = server();
    let wire = Direct {
        server: &server,
        now: Cell::new(1000),
    };
    let request: GrantRequest = serde_json::from_value(serde_json::json!({
        "client": {"key": {"proof": "httpsig", "jwk": signer.public_jwk()?}},
        "access_token": {"access": ["synthetic-read"]}
    }))?;
    let mut client = Session::new(&wire, signer, GRANT);
    let Step::Approved(response) = client.start(&request, 1000)? else {
        return Err("the synthetic policy did not approve the grant".into());
    };
    let issued = &response
        .access_token
        .as_ref()
        .ok_or("no access token")?
        .tokens[0];
    assert_eq!(
        issued.access.as_ref(),
        Some(&vec![AccessItem::Reference("synthetic-read".into())])
    );
    println!("Grant accepted using the public JWK in the request.");

    // Management requests prove the same key even though they no longer carry
    // a client object: the AS resolves the key retained with the grant.
    wire.now.set(1010);
    let rotated = client.rotate_token(None, 1010)?;
    assert_ne!(rotated.value, issued.value);
    wire.now.set(1020);
    client.revoke_token(None, 1020)?;
    println!("The same key rotated and revoked the issued token.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fresh key avoids teaching consumers to reuse a published fixture.
    // Production clients load their independently protected keys instead.
    let signer = Ps256Signer::generate(2048, "ephemeral-client")?;
    exercise(&signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_rotation_and_revocation_resolve_the_presented_jwk() {
        // Public test material from RFC 9421 Appendix B.1.2.
        let signer = Ps256Signer::from_pkcs1_pem(
            include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
            "test-client",
        )
        .unwrap();
        exercise(&signer).unwrap();
    }

    #[test]
    fn an_importable_public_key_does_not_substitute_for_proof_of_possession() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let signer = Ps256Signer::from_pkcs1_pem(
            include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
            "test-client",
        )
        .unwrap();
        let mut public = signer.public_jwk().unwrap();
        let mut modulus = URL_SAFE_NO_PAD
            .decode(public["n"].as_str().unwrap())
            .unwrap();
        // Preserve size and oddness, but present another modulus. The request
        // is signed over this exact JWK: this is not a body-digest failure.
        modulus[1] ^= 1;
        public.insert(
            "n".into(),
            serde_json::json!(URL_SAFE_NO_PAD.encode(modulus)),
        );
        assert!(Ps256Verifier::from_public_jwk(&public).is_ok());
        let request: GrantRequest = serde_json::from_value(serde_json::json!({
            "client": {"key": {"proof": "httpsig", "jwk": public}},
            "access_token": {"access": ["synthetic-read"]}
        }))
        .unwrap();
        let server = server();
        let wire = Direct {
            server: &server,
            now: Cell::new(1000),
        };
        let mut client = Session::new(&wire, &signer, GRANT);
        let error = client.start(&request, 1000).unwrap_err();
        let gnap_client::ClientError::Server(error) = error else {
            panic!("the AS should reject the unproven key: {error}");
        };
        assert_eq!(error.code.as_str(), "invalid_client");
        assert_eq!(server.storage().len().unwrap(), 0);
    }
}
