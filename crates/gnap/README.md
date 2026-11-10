# gnap

GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) and its resource-server connections ([RFC 9767](https://www.rfc-editor.org/rfc/rfc9767)) in one dependency. This crate re-exports the `gnap-*` crates, each under a module, with a feature per protocol role.

Add it with the roles you need, for example `cargo add gnap --features client`. Its [API documentation](https://docs.rs/gnap) is on docs.rs.

## Choose the features

| Feature       | Module              | Crate              |
| ------------- | ------------------- | ------------------ |
| always on     | `gnap::types`       | `gnap-types`       |
| always on     | `gnap::registry`    | `gnap-registry`    |
| always on     | `gnap::crypto`      | `gnap-crypto`      |
| always on     | `gnap::core`        | `gnap-core`        |
| `client`      | `gnap::client`      | `gnap-client`      |
| `server`      | `gnap::server`      | `gnap-as`          |
| `rs`          | `gnap::rs`          | `gnap-rs`          |
| `biscuit`     | `gnap::biscuit`     | `gnap-biscuit`     |
| `subject`     | `gnap::subject`     | `gnap-subject`     |
| `net`         | `gnap::net`         | `gnap-net`         |
| `conformance` | `gnap::conformance` | `gnap-conformance` |

`full` enables every role. A module is the crate itself, so depending on a `gnap-*` crate directly gives the same items. The [integration guide](https://github.com/davlgd/gnap/blob/main/docs/getting-started.md#add-the-libraries-to-your-application) shows how to use each role.

These libraries are experimental: passing their tests isn't GNAP conformance, and they haven't had an independent security review.

## Verify

```bash
cargo test -p gnap --locked
```

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
