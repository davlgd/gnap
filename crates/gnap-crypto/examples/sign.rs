//! Signs a GNAP grant request, then verifies its own output.
//!
//! Shows the HTTP message as it goes on the wire: the `Content-Digest`,
//! `Signature-Input` and `Signature` fields of the *Web-Based Redirection*
//! profile (RFC 9635, Appendix C).
//!
//! ```text
//! cargo run -p gnap-crypto --example sign                    # built-in example
//! cargo run -p gnap-crypto --example sign -- request.json    # from a file
//! cat request.json | cargo run -p gnap-crypto --example sign -- -
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};
use gnap_crypto::digest::{content_digest, verify_content_digest, DigestAlgorithm};
use gnap_crypto::httpsig::{sign, verify, Component, Message, SignatureInput, Tag};
use gnap_crypto::proof::Signer;
use gnap_crypto::ps256::Ps256Signer;
use gnap_types::unix_now;
use std::io::Read;

const ENDPOINT: &str = "https://server.example.com/gnap";

/// The example request used when no input is provided.
const DEMO: &str = r#"{
  "access_token": {
    "access": ["dolphin-metadata"]
  },
  "interact": {
    "start": ["redirect"],
    "finish": {
      "method": "redirect",
      "uri": "https://client.example.net/return/123455",
      "nonce": "VJLO6A4CATR0KRO"
    }
  },
  "client": {
    "key": {
      "proof": "httpsig",
      "jwk": {"kty": "RSA", "kid": "gnap-demo", "alg": "PS256", "e": "AQAB", "n": "..."}
    }
  }
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- input ------------------------------------------------------------
    let body = match std::env::args().nth(1).as_deref() {
        None => DEMO.to_owned(),
        Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        }
        Some(path) => std::fs::read_to_string(path)?,
    };

    // --- key --------------------------------------------------------------
    // Ephemeral: a production key is managed elsewhere (RFC 9635 §11.5).
    eprintln!("Generating an ephemeral RSA key…");
    let signer = Ps256Signer::generate(2048, "gnap-demo")?;

    // --- protected fields ---------------------------------------------------
    // §7.3.1 requires computing Content-Digest as soon as the request has
    // content, and covering it with the signature.
    let digest = content_digest(body.as_bytes(), DigestAlgorithm::Sha256);

    let message = Message {
        method: "POST",
        target_uri: ENDPOINT,
        content_digest: Some(&digest),
        authorization: None, // initial request: no token presented
        other: Vec::new(),
    };

    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
        ],
        created: unix_now(),
        keyid: signer.key_id().to_owned(),
        nonce: Some(random_nonce()),
        tag: Tag::Gnap,
    };

    let (sig_input, signature) = sign(&message, &input, &signer, "sig1")?;

    // --- the message as it goes out ---------------------------------------
    println!("POST /gnap HTTP/1.1");
    println!("Host: server.example.com");
    println!("Content-Type: application/json");
    println!("Content-Length: {}", body.len());
    println!("Content-Digest: {digest}");
    println!("Signature-Input: {sig_input}");
    println!("Signature: {signature}");
    println!();
    println!("{}", body.trim());

    // --- replay the verifier's path ---------------------------------------
    eprintln!();
    eprintln!("Verifying the output, from the recipient's side:");

    verify_content_digest(body.as_bytes(), &digest)?;
    eprintln!("  · Content-Digest matches the content (§7.3.1)");

    let raw = sig_input
        .strip_prefix("sig1=")
        .expect("sig1 label expected");
    let b64 = signature
        .strip_prefix("sig1=:")
        .and_then(|s| s.strip_suffix(':'))
        .expect("colon-delimited signature expected");
    let bytes = STANDARD.decode(b64)?;

    verify(&message, &input.components, raw, &bytes, &signer.verifier())?;
    eprintln!("  · PS256 signature valid over the reconstructed base");
    eprintln!(
        "  · algorithm: {} — mandated by both Appendix C profiles",
        signer.algorithm()
    );
    eprintln!();
    eprintln!("The base's @signature-params line is, word for word, the value of");
    eprintln!("the Signature-Input field: that is what keeps both sides from diverging.");

    Ok(())
}

/// A nonce for the `nonce` parameter, recommended by §7.3.1.
fn random_nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("randomness source unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
