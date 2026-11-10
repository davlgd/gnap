# Getting started

This guide runs a first grant, then shows how to build each protocol role with the libraries. Run the commands from the repository root. The libraries need Rust 1.95 or newer; the HTTP applications are separate Cargo workspaces, whose guides state their own toolchains.

## Run a grant

Clone the repository, then run the `flow` example. It follows a grant through the request, the owner's approval, the callback check, the continuation, the rotation of the token value, and its revocation. The client and the authorization server are the real implementations; the transport, the policy, and the resource owner are simulated, and no resource server is called.

```console
$ cargo run -p gnap-as --example flow

1. The client asks for access (§2)
   It signs the request with its own key; there is no client secret.
  --> POST https://as.example/gnap
  <-- 200 continue, interact

   The AS wants a resource owner to approve. State: pending
   Send the user to: https://as.example/interact/value0002

2. The resource owner approves, elsewhere (§4)
   Once the RO has answered, the AS creates the interaction reference,
   binds it to this grant, and hashes it with both nonces (§4.2.3).
   Send the user back to: https://client.example/callback?hash=5Z8LxOdZ3jYe4SxnkiyTKfqhKFTNopPBLDeVC_MijO8&interact_ref=value0004
   Hash validated; the client will pass the reference on.
   A forged one is refused: untrusted interaction callback: the interaction hash does not validate; the client MUST NOT send the interaction reference to the AS (RFC 9635 §4.2.1)

3. The client continues, and gets its token (§5)
   It must wait out the `wait` period first; calling early earns
   a too_fast error from the AS.
  --> POST https://as.example/continue
      Authorization: GNAP value0003
  <-- 200 access_token

   State: approved. Token issued, good for:
     - Reference("dolphin-metadata")

4. The client manages the token it was issued (§6)
   Management URI: https://as.example/token/value0006
  --> POST https://as.example/token/value0006
      Authorization: GNAP value0007
  <-- 200 access_token
   Rotated: a new value, the same rights (§6.1-M05)
     - Reference("dolphin-metadata")
   And a new management URI to carry on with (§6.1-M04): https://as.example/token/value0010
  --> DELETE https://as.example/token/value0010
      Authorization: GNAP value0009
  <-- 204 (no body)
   Revoked: the AS answered 204, the token is gone (§6.2)

Before revoking it, the client could have called a resource server with
that token (§7.2). This in-memory example does not call a resource server.
```

Read [the example's source](../crates/gnap-as/examples/flow.rs) from top to bottom to see what each protocol message looks like.

## Try smaller examples

```bash
cargo run -p gnap-as --example jwk_client --locked
cargo run -p gnap-crypto --example sign --locked
cargo run -p gnap-biscuit --example file_access --locked
```

- [`jwk_client`](../crates/gnap-as/examples/jwk_client.rs) sends a public key by value, then gets, rotates, and revokes a token
- [`sign`](../crates/gnap-crypto/examples/sign.rs) builds a signed request and verifies it
- [`file_access`](../crates/gnap-biscuit/examples/file_access.rs) attenuates a Biscuit token, then refuses it once its parent is revoked

In `jwk_client`, the policy approves a fixed right, since possessing a key isn't an identity. `file_access` runs no GNAP grant.

To check the shape of a message, pipe its JSON to the `lint` example:

```bash
echo '{"client":"c","access_token":[{"access":["a"]},{"access":["b"]}]}' \
  | cargo run -q -p gnap-types --example lint --locked -- request
```

This request is refused on purpose: several requested tokens need labels. The shape check verifies neither signatures nor authorization.

## Add the libraries to your application

The crates are published on [crates.io](https://crates.io/crates/gnap-client), and their API documentation on [docs.rs](https://docs.rs/gnap-client). A client needs these entries in its `Cargo.toml`:

```toml
[dependencies]
gnap-client = "0.1"
gnap-crypto = "0.1"
gnap-types = "0.1"
serde_json = "1"
```

### Build a client

Implement `HttpTransport::send`, provide a signer, and create a `Session` for the grant endpoint of the authorization server. The [client API documentation](../crates/gnap-client/src/lib.rs) has a compiled example, and the [`jwk_client` example](../crates/gnap-as/examples/jwk_client.rs) connects it to a real authorization server without a network.

Handle the step that the session returns: approval, interaction, or continuation. Validate an interaction callback through the session before you continue the grant, and never forward an unvalidated interaction reference. Pass consistent timestamps, and configure a finish timeout. After a transport failure, don't assume that the server rolled back the operation, and don't retry a mutation blindly.

For an HTTP client, start from the [delegation lab](../apps/delegation-demo/README.md), whose adapter supplies TLS, canonical origins, request bounds, and browser sessions.

### Build an authorization server

Assemble an `AuthorizationServer` with your policy, key resolution, storage, nonce generation, and endpoint URIs. Route each request to its handler without changing the signed method, URI, headers, or body. The [server API documentation](../crates/gnap-as/src/lib.rs) shows the constructor and the transactional storage contract.

Your policy authenticates the resource owner, decides the approved rights, and chooses the lifetimes: proving a client's key doesn't authorize its request. The default encoder issues opaque reference tokens, and a trusted [`TokenEncoder`](../crates/gnap-as/src/encoding.rs) can issue another format, as Biscuit files does with a matching verifier.

### Build a resource server

Choose the path that matches your agreement with the authorization server:

- Opaque tokens: the [resource-server SDK](resource-server-sdk.md), with authenticated introspection
- Biscuit tokens: the [file-profile verifier](../crates/gnap-biscuit/README.md), shown in the [Biscuit files application](../apps/biscuit-files/README.md)

A token format doesn't replace the checks of the request proof, the rights, the lifetime, and revocation. The [architecture](architecture.md) shows how the responsibilities split, and the [support matrix](support-matrix.md) gives the exact profiles.

## Run an HTTP application

Each application has its own manifest:

```bash
cargo run --manifest-path apps/delegation-demo/Cargo.toml --locked
```

Open the address that the application prints. The [delegation lab](../apps/delegation-demo/README.md#run), the [workbench](../apps/conformance-web/README.md#run-and-test), and [Biscuit files](../apps/biscuit-files/README.md#run-locally) explain their configuration. Use only synthetic data with any of them.
