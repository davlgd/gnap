# gnap-client

The GNAP client role over an application-supplied HTTP transport. A `Session` builds and signs grant requests, checks responses and interaction callbacks, continues a grant, and manages its issued tokens.

Add it with `cargo add gnap-client`. Its [API documentation](https://docs.rs/gnap-client) is on docs.rs.

## Integrate a client

Implement `HttpTransport::send`, provide a signer and create a `Session` for the authorization server's grant endpoint. Handle the returned `Step`, validate interaction callbacks through the session, and pass consistent timestamps to continue or manage the grant.

The API documentation has a compiled example. The [integration guide](https://github.com/davlgd/gnap/blob/main/docs/getting-started.md#build-a-client) connects it to the runnable applications of the repository.

The transport is synchronous and doesn't impose an HTTP framework or async runtime. Your adapter supplies TLS, destination policy, byte preservation and request bounds. Your application owns browser sessions and user-facing interaction.

## Manage access

The client supports ongoing grants, multiple labelled tokens, value rotation and opt-in presentation-key changes. It retains token signers separately from the grant's continuation signer. See the [multiple-token guide](https://github.com/davlgd/gnap/blob/main/docs/multiple-access-tokens.md) and [Biscuit example](https://github.com/davlgd/gnap/blob/main/apps/biscuit-files/README.md) for concrete flows and binding limits.

No mutation retries automatically. An inconclusive exchange doesn't mean the server rolled back its operation. A decoded identity assertion isn't verified identity; use the explicit subject-verification path when selecting that profile.

## Verify

```bash
cargo test -p gnap-client --locked
```

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
