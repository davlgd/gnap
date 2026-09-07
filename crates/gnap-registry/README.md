# gnap-registry

The 23 IANA registries defined for GNAP by RFC 9635 and RFC 9767, generated
from vendored official CSV files. Value registries provide enums; field-name
registries provide slices of field names.

## Use a registry value

```rust
use gnap_registry::KeyProofingMethod;

let known = KeyProofingMethod::from("httpsig");
assert!(known.is_registered());

let extension = KeyProofingMethod::from("example-proof");
assert!(!extension.is_registered());
assert_eq!(extension.as_str(), "example-proof");
```

Unregistered values are retained rather than discarded. Recognizing a name
does not implement its protocol behavior; the consuming application decides
which values it supports.

## Work from source

```sh
cargo test -p gnap-registry --locked
```

Generated Rust is included in the package; consumers do not need to download
IANA data or run the generator. Maintainers can reproduce it using the
[registry workflow](https://github.com/davlgd/gnap/blob/main/docs/verification.md#protocol-tests-and-registries).

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.85 or newer; Apache-2.0.
For source dependencies and the upcoming 0.1.0 publication, see the
[release guide](https://github.com/davlgd/gnap/blob/main/docs/releasing.md).
