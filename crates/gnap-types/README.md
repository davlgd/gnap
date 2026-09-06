# gnap-types

Rust types for GNAP requests, responses, access descriptions, tokens and
resource-server messages. Use them to parse and serialize protocol messages
while retaining extension fields and unregistered values.

## Decode a grant request

```rust
use gnap_types::GrantRequest;

let request: GrantRequest = serde_json::from_str(
    r#"{"client":"my-client","access_token":{"access":["read-notes"]}}"#
).unwrap();
assert!(request.access_token.is_some());
```

The example also uses `serde_json`. Dedicated deserializers handle GNAP's
object/reference and single/multiple forms. Diagnostics identify malformed
fields and relevant protocol rules.

Message shape is not authorization. Signature verification, grant-state rules
and application-specific rights checks belong to other layers.

## Inspect a message from the command line

From a source checkout, or an unpacked package:

```sh
echo '{"client":"my-client"}' | cargo run -q -p gnap-types --example lint --locked -- request
cargo test -p gnap-types --locked
```

See the [integration guide](https://github.com/davlgd/gnap/blob/main/docs/getting-started.md)
for the client, AS and RS roles built on these types.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.85 or newer; Apache-2.0.
For source dependencies and the upcoming 0.1.0 publication, see the
[release guide](https://github.com/davlgd/gnap/blob/main/docs/releasing.md).
