# gnap-crypto

HTTP Message Signature proofs, content digests and interaction hashes for GNAP. Use this crate to sign requests and verify the cryptographic binding between a request, its key, its content and any presented token.

The key adapters cover RSA-PSS with SHA-256 (PS256), ECDSA on P-256 (ES256), and Ed25519 (EdDSA). Each can generate a key, import PEM material, and export a public JWK, and `PublicKey::from_jwk` builds the verifier that a public JWK's `kty`, `crv`, and `alg` call for. Key possession doesn't establish identity or authorization.

## Explore request signing

From a source checkout, or an unpacked package:

```bash
cargo run -p gnap-crypto --example sign --locked
cargo test -p gnap-crypto --locked
```

The example constructs and verifies a signed grant request. For a complete client session, use `gnap-client`; for a resource request, its `sign_request` helper handles fresh nonces and token-bound signing.

## Verification boundary

The caller must preserve the signed method, exact URI, headers and content. Network security, trusted key selection, nonce storage and resource policy are separate responsibilities. A valid signature doesn't grant access.

Tests include deliberately public RFC keys, with provenance and notices in [the fixture guide](https://github.com/davlgd/gnap/blob/main/crates/gnap-crypto/tests/README.md). Never use those keys for deployment.

See [architecture](https://github.com/davlgd/gnap/blob/main/docs/architecture.md) and the [support matrix](https://github.com/davlgd/gnap/blob/main/docs/support-matrix.md) for the selected proof profile.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
