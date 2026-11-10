# gnap-as

The GNAP authorization-server role without a prescribed HTTP framework. It negotiates grants, drives interaction and continuation, issues and manages tokens, and provides opt-in resource-server APIs.

Add it with `cargo add gnap-as`. Its [API documentation](https://docs.rs/gnap-as) is on docs.rs.

## Assemble a server

Create an `AuthorizationServer` with an authorization `Policy`, trusted `KeyResolver`, transactional `Storage`, nonce generator and endpoint URIs. Your HTTP adapter passes the request to the corresponding handler then sends the response back, without changing the signed request bytes along the way.

The API documentation shows a compiled constructor and the storage contract. The [integration guide](https://github.com/davlgd/gnap/blob/main/docs/getting-started.md#build-an-authorization-server) connects it to clients and resources.

Policy supplies the decisions GNAP leaves to a deployment: owner authentication, consent, approved rights, lifetimes and trust. The included in-memory storage doesn't supply persistence or a production identity system.

## Run a grant

From a source checkout, or an unpacked package:

```bash
cargo run -p gnap-as --example flow --locked
cargo run -p gnap-as --example jwk_client --locked
cargo test -p gnap-as --locked
```

`flow` narrates request, simulated consent, callback validation, continuation, rotation and revocation. `jwk_client` supplies a public key by value. These examples use an in-memory transport and synthetic policy, not HTTP servers.

The default encoder produces opaque reference tokens. A trusted `TokenEncoder` can supply another format; the [Biscuit application](https://github.com/davlgd/gnap/blob/main/apps/biscuit-files/README.md) demonstrates it with a separate RS and matching verifier. See the [support matrix](https://github.com/davlgd/gnap/blob/main/docs/support-matrix.md) for the exact RS-facing and token-management profiles.

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
