# gnap-compliance

Canonical types, crypto helpers and validation functions for [GNAP (Grant Negotiation and Authorization Protocol)](https://www.rfc-editor.org/rfc/rfc9635). Use this crate to build or test any Rust GNAP implementation against the specification.

## Why this crate?

GNAP (RFC 9635) defines a rich JSON data model with polymorphic fields, strict security constraints and cryptographic requirements. Getting every detail right — field names, required vs. optional semantics, key proofing, interaction hashes — is tedious and error-prone.

`gnap-compliance` gives you:

- **Ready-to-use types** that serialize/deserialize exactly like the RFC JSON examples.
- **Validation functions** that enforce MUST-level rules from the spec.
- **Crypto utilities** for HTTP Message Signatures (RFC 9421), Content-Digest (RFC 9530), interaction hashes and JWK handling.
- **71 tests** verified one-by-one against the RFC text, including the official test vector.

## Quick start

Add the crate to your project:

```toml
[dependencies]
gnap-compliance = { path = "gnap-compliance" }
```

Parse a grant response from JSON:

```rust
use gnap_compliance::types::*;
use gnap_compliance::validation::validate_grant_response;

let json = r#"{
    "continue": {
        "access_token": { "value": "80UPRY5NM33OMUKMKSKU" },
        "uri": "https://server.example.com/continue/VGJKPTKC50",
        "wait": 30
    },
    "access_token": {
        "value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
        "manage": {
            "uri": "https://server.example.com/token/PRY5NM33OM4TB8N6BW7OZB8CDFONP219RP1L",
            "access_token": { "value": "B8N6BW7OZB8CDFONP219" }
        },
        "access": [{ "type": "photo-api", "actions": ["read", "write"] }]
    }
}"#;

let resp: GrantResponse = serde_json::from_str(json).unwrap();
validate_grant_response(&resp).expect("RFC-compliant response");
```

## Modules

### `types` — RFC-faithful data structures

All request/response types from RFC 9635, with `serde` attributes matching the JSON field names exactly:

| Type | RFC section |
|------|------------|
| `GrantRequest` / `GrantResponse` | 2, 3 |
| `AccessTokenRequest` / `AccessToken` | 2.1, 3.2 |
| `InteractRequest` / `InteractResponse` | 2.5, 3.3 |
| `ClientInstance` / `ClientDisplay` | 2.3 |
| `SubjectRequest` / `SubjectResponse` | 2.2, 3.4 |
| `ContinueRequest` / `ContinueResponse` | 5 |
| `TokenRotationResponse` / `TokenManagement` | 6.1 |
| `Key` / `KeyRef` / `ProofMethod` | 7.1, 7.3 |
| `GnapError` / `GnapErrorCode` | 3.6 |
| `AccessRight` / `StructuredAccessRight` | 8 |

Polymorphic RFC fields (string-or-object) are modeled as `#[serde(untagged)]` enums: `ClientInstance`, `UserRef`, `KeyRef`, `ProofMethod`, `StartMode`, `AccessRight`, `GnapErrorField`, etc.

### `validation` — MUST-level rule enforcement

```rust
use gnap_compliance::validation::{validate_grant_request, validate_grant_response};
```

Checks include:
- Required fields non-empty (`value`, `access`, `uri`, `nonce`)
- Label presence and uniqueness for multi-token requests/responses
- Bearer flag and key mutual exclusion (Section 3.2.1)
- No duplicate flag values (Section 3.2.1)
- Management token value differs from managed token (Section 3.2.1)
- Error field exclusivity (Section 3.6)
- Interaction finish method validity (Section 2.5.2)
- Client key format requirements (Section 7.1)

### `crypto` — Signatures, hashes, JWK

```rust
use gnap_compliance::crypto::*;
```

**HTTP Message Signatures (RFC 9421 + GNAP)**

```rust
let (sig_header, sig_input) = create_gnap_signature_headers(
    &signing_key, "my-key-id",
    &[("@method", "POST"), ("@target-uri", "https://as.example.com/gnap")],
    1618884475,
);
// sig_input includes tag="gnap" as required by Section 7.3.1
```

- `build_signature_base` / `build_signature_params` — construct signature base per RFC 9421
- `sign_ed25519` / `verify_ed25519` — Ed25519 signing and verification
- `parse_signature_input` — parse and validate `Signature-Input` header (enforces `tag="gnap"`, rejects `alg`)

**Interaction hash (Section 4.2.3)**

```rust
let hash = compute_interaction_hash(
    "client-nonce", "server-nonce", "interact-ref",
    "https://as.example.com/gnap",
    HashMethod::Sha256,
);
```

**Content-Digest (RFC 9530)**

```rust
let digest = compute_content_digest_sha256(body);
verify_content_digest(&digest, body).expect("digest matches");
```

**JWK (RFC 7517 + GNAP constraints)**

```rust
let jwk = Ed25519Jwk::from_signing_key(&key, Some("my-kid".into()));
jwk.validate()?; // Enforces kid required, alg != "none"
let verifying_key = jwk.to_verifying_key()?;
```

### `fixtures` — Embedded RFC examples

JSON strings based on RFC 9635 examples, usable in your own tests:

```rust
use gnap_compliance::fixtures;

let req: GrantRequest = serde_json::from_str(fixtures::GRANT_REQUEST_SINGLE_TOKEN).unwrap();
```

## Tests

```sh
cargo test -p gnap-compliance
```

71 tests organized by RFC section (`rfc9635_section2` through `rfc9635_section7`), covering:

- Deserialization from RFC-style JSON
- Serialize/deserialize round-trips
- Validation of valid and invalid inputs
- Crypto operations (signatures, hashes, JWK)
- The official interaction hash test vector from RFC 9635

## License

Apache-2.0
