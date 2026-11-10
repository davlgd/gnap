# gnap-registry

The 23 IANA registries defined for GNAP by RFC 9635 and RFC 9767, generated from vendored official CSV files. Value registries provide enums; field-name registries provide slices of field names.

Add it with `cargo add gnap-registry`. Its [API documentation](https://docs.rs/gnap-registry) is on docs.rs.

## Use a registry value

```rust
use gnap_registry::KeyProofingMethod;

let known = KeyProofingMethod::from("httpsig");
assert!(known.is_registered());

let extension = KeyProofingMethod::from("example-proof");
assert!(!extension.is_registered());
assert_eq!(extension.as_str(), "example-proof");
```

Unregistered values are retained rather than discarded. Recognizing a name doesn't implement its protocol behavior; the consuming application decides which values it supports.

## Work from source

```bash
cargo test -p gnap-registry --locked
```

Generated Rust is included in the package; consumers don't need to download IANA data or run the generator. Maintainers can reproduce it using the [registry workflow](https://github.com/davlgd/gnap/blob/main/docs/verification.md#iana-registries).

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
