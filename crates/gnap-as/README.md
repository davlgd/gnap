# gnap-as

The GNAP authorization-server role without a prescribed HTTP framework.
It negotiates grants, drives interaction and continuation, issues and manages
tokens, and provides opt-in resource-server APIs.

## Assemble a server

Create an `AuthorizationServer` with an authorization `Policy`, trusted
`KeyResolver`, transactional `Storage`, nonce generator and endpoint URIs.
Your HTTP adapter passes the request to the corresponding handler and sends
its response without changing signed request bytes.

The [API introduction](https://github.com/davlgd/gnap/blob/main/crates/gnap-as/src/lib.rs)
contains a compiled constructor example and the storage contract. The
[integration guide](https://github.com/davlgd/gnap/blob/main/docs/getting-started.md#authorization-server)
explains how to connect it to clients and resources.

Policy supplies the decisions GNAP leaves to a deployment: owner authentication,
consent, approved rights, lifetimes and trust. The included in-memory storage
does not supply persistence or a production identity system.

## Run a grant

From a source checkout, or an unpacked package:

```sh
cargo run -p gnap-as --example flow --locked
cargo run -p gnap-as --example jwk_client --locked
cargo test -p gnap-as --locked
```

`flow` narrates request, simulated consent, callback validation, continuation,
rotation and revocation. `jwk_client` supplies a public key by value. These
examples use an in-memory transport and synthetic policy, not HTTP servers.

The default encoder produces opaque reference tokens. A trusted `TokenEncoder`
can supply another format; the
[Biscuit application](https://github.com/davlgd/gnap/blob/main/apps/biscuit-files/README.md)
demonstrates it with a separate RS and matching verifier.
See the [support matrix](https://github.com/davlgd/gnap/blob/main/docs/support-matrix.md)
for the exact RS-facing and token-management profiles.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.85 or newer; Apache-2.0.
For source dependencies and the upcoming 0.1.0 publication, see the
[release guide](https://github.com/davlgd/gnap/blob/main/docs/releasing.md).
