# Getting started

Run commands from the repository root unless a section says otherwise.
The SDK workspace requires Rust 1.85 or newer. The HTTP applications are separate
Cargo workspaces with their own lockfiles and tested toolchains documented in
their guides. Biscuit files requires Rust 1.98 and Unix.

## Follow a grant

After cloning the repository, run the example below. Its output follows a grant
through request, owner approval, callback validation, continuation, token-value
rotation and revocation. Both SDK roles are real; the transport, policy and
resource owner are simulated, and no resource server is contacted.

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

A client and an authorization server using the real protocol implementations,
an in-memory transport, and demonstration policies and keys. Reading
[that example](../crates/gnap-as/examples/flow.rs) top to bottom is the fastest way
to see what the protocol looks like.


## Explore smaller examples

Run each independently:

```sh
cargo run -p gnap-as --example jwk_client --locked
cargo run -p gnap-crypto --example sign --locked
cargo run -p gnap-biscuit --example file_access --locked
```

- [Public JWK client](../crates/gnap-as/examples/jwk_client.rs): supply a public
  key by value, prove possession, obtain a token, rotate it and revoke it.
  The synthetic AS policy approves a fixed right; possession is not identity.
- [HTTP signature](../crates/gnap-crypto/examples/sign.rs): construct a signed
  request and verify it.
- [Biscuit file access](../crates/gnap-biscuit/examples/file_access.rs): issue a
  token, add restrictive checks, authorize its request and reject it after
  parent revocation. This example does not run a GNAP grant session.

To inspect a message's shape, pipe JSON to the linter:

```sh
echo '{"client":"c","access_token":[{"access":["a"]},{"access":["b"]}]}' \
  | cargo run -q -p gnap-types --example lint --locked -- request
```

This input is deliberately rejected because multiple requested tokens need
labels. Shape validation does not verify request signatures or authorization.

## Integrate a protocol role

The examples consume workspace crates through path dependencies. You can use the
same arrangement with a checkout named `gnap` beside your application directory.
For a client, add these entries to your application's `Cargo.toml`:

```toml
[dependencies]
gnap-client = { path = "../gnap/crates/gnap-client" }
gnap-crypto = { path = "../gnap/crates/gnap-crypto" }
gnap-types = { path = "../gnap/crates/gnap-types" }
serde_json = "1"
```

Adjust paths to your checkout. These instructions use source dependencies, not
an assumed crates.io release.

### Client

Implement `HttpTransport::send`, provide a signer, and create a `Session` for
the AS grant endpoint. The [client API introduction](../crates/gnap-client/src/lib.rs)
contains a compiled documentation example; the
[JWK client](../crates/gnap-as/examples/jwk_client.rs) connects it to a real AS
engine without a network.

Handle the returned step: approval, interaction or continuation. Use the session's
callback validation before continuing a grant; do not forward an unvalidated
interaction reference. Pass consistent current timestamps to operations and
configure a finish timeout. After a transport failure, do not assume the server
rolled back the operation or blindly retry a mutation.

For HTTP integration, start from the [delegation application](../apps/delegation-demo/README.md).
Its adapter supplies TLS, canonical origins, request bounds and browser-session
handling that an in-memory example does not provide.

### Authorization server

Assemble `AuthorizationServer` with deployment policy, key resolution, storage,
nonce generation and endpoint URIs. Route incoming requests to its handlers
without changing the signed method, URI, headers or body bytes. The
[AS API introduction](../crates/gnap-as/src/lib.rs) shows the constructor and
explains the transactional storage contract.

Your policy authenticates the resource owner, determines approved rights and
chooses lifetimes. Proving a client's key alone does not authorize its request.
The default token encoder produces opaque references; a trusted
[`TokenEncoder`](../crates/gnap-as/src/encoding.rs) can supply another format.
Biscuit files demonstrates that extension with a matching RS verifier.

### Resource server

Choose a validation path appropriate to the AS/RS agreement:

- For opaque tokens, use [`gnap-rs::Authorizer`](resource-server-sdk.md) with an
  authenticated introspection transport, replay memory and resource policy.
- For Biscuit, use the [file-profile verifier](../crates/gnap-biscuit/README.md)
  and the [three-process application](../apps/biscuit-files/README.md) to see
  local rights checks combined with a signed live authority decision.

A token's format does not replace request-proof, rights, lifetime or revocation
checks. See [architecture](architecture.md) for the boundaries between these
responsibilities and [the support matrix](support-matrix.md) for precise profiles.

## Run an HTTP application

Use an application's own manifest rather than the root workspace command:

```sh
cargo run --manifest-path apps/delegation-demo/Cargo.toml --locked
```

Open the address printed by the application. The
[delegation guide](../apps/delegation-demo/README.md#run) explains its scenarios;
[workbench setup](../apps/conformance-web/README.md#run-and-test) and
[Biscuit setup](../apps/biscuit-files/README.md#run-locally) have separate
configuration instructions. Use only synthetic data in these examples.

Return to the [documentation index](README.md) to choose an interaction,
token-management or resource-server guide.
