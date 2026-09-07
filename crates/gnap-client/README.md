# gnap-client

The GNAP client role over an application-supplied HTTP transport. A `Session`
builds and signs grant requests, checks responses and interaction callbacks,
continues a grant, and manages its issued tokens.

## Integrate a client

Implement `HttpTransport::send`, provide a signer and create a `Session` for
the authorization server's grant endpoint. Handle the returned `Step`, validate
interaction callbacks through the session, and supply consistent timestamps
when continuing or managing the grant.

The [API introduction](https://github.com/davlgd/gnap/blob/main/crates/gnap-client/src/lib.rs)
contains a compiled documentation example. The
[integration guide](https://github.com/davlgd/gnap/blob/main/docs/getting-started.md#client)
connects it to runnable applications.

The transport is synchronous and does not impose an HTTP framework or async
runtime. Your adapter supplies TLS, destination policy, byte preservation and
request bounds. Your application owns browser sessions and user-facing interaction.

## Manage access

The client supports ongoing grants, multiple labelled tokens, value rotation
and opt-in presentation-key changes. It retains token signers separately from
the grant's continuation signer. See the
[multiple-token guide](https://github.com/davlgd/gnap/blob/main/docs/multiple-access-tokens.md)
and [Biscuit example](https://github.com/davlgd/gnap/blob/main/apps/biscuit-files/README.md)
for concrete flows and binding limits.

No mutation retries automatically. An inconclusive exchange does not mean the
server rolled back its operation. A decoded identity assertion is not verified
identity; use the explicit subject-verification path when selecting that profile.

## Verify

```sh
cargo test -p gnap-client --locked
```

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.85 or newer; Apache-2.0.
For source dependencies and the upcoming 0.1.0 publication, see the
[release guide](https://github.com/davlgd/gnap/blob/main/docs/releasing.md).
