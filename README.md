# gnap

Rust libraries, example applications and diagnostic tools for the
[Grant Negotiation and Authorization Protocol (GNAP)](https://www.rfc-editor.org/rfc/rfc9635).
Build a client that requests access, an authorization server that negotiates it,
and a resource server that checks both the permission and the key presenting it.

The libraries provide signed grant requests, interaction and continuation,
token management, and resource-server connections. The examples put them to work
with opaque reference tokens and an attenuable Biscuit file-access profile.

GNAP addresses delegated authorization with its own protocol; it is not an
OAuth-compatible API. For the design differences and comparable OAuth
extensions, see [GNAP and modern OAuth](docs/gnap-and-modern-oauth.md).

## Try the applications

| Application | What to try | Run it yourself |
| --- | --- | --- |
| [Delegation lab](https://gnap-delegation.cleverapps.io) | Approve document access, change a grant's rights, request multiple tokens, rotate and revoke access | [Setup and scenarios](apps/delegation-demo/README.md) |
| [Biscuit files](https://gnap-biscuit.cleverapps.io) | Restrict a token locally, read and write with distinct rights, change presentation keys and revoke the parent | [Three-process setup](apps/biscuit-files/README.md) |
| [Diagnostic workbench](https://gnap-conformance.cleverapps.io) | Inspect GNAP messages or exercise an operator-approved AS/RS pair | [Setup and diagnostics](apps/conformance-web/README.md) |

The hosted applications use synthetic data and volatile state. Do not submit
personal data or production credentials. Active network tests require the
endpoint owner's permission and an operator-approved target.

The delegation lab runs its protocol roles in one application, with HTTP
introspection between the RS and AS. Biscuit files runs a separate client, AS
and RS; its signed live-decision channel is specific to that application.
The [example guides](docs/README.md#applications) explain each setup and its limits.

## Run your first grant

Clone the repository and run the narrated client–AS example:

```sh
git clone https://github.com/davlgd/gnap.git
cd gnap
cargo run -p gnap-as --example flow --locked
```

It requests access, simulates resource-owner approval, validates the callback,
obtains a token, then rotates and revokes it. It uses the real SDK roles with
an in-memory transport; it starts no HTTP server.

The SDK workspace requires Rust 1.85 or newer. HTTP applications have separate
toolchain requirements in their guides; Biscuit files requires Rust 1.98 and Unix.
See [Getting started](docs/getting-started.md) for the annotated output,
additional runnable examples and integration instructions.

## Use the libraries

Choose the protocol role you need; the client and AS do not impose an HTTP
framework or async runtime. Your application supplies transport, trust and
authorization policy. The included in-memory stores are useful for examples;
persistent storage and real user authentication belong to the deployment.

| Crate | Purpose |
| --- | --- |
| [`gnap-client`](crates/gnap-client) | Build and sign grant requests, process interaction and continuation, manage tokens |
| [`gnap-as`](crates/gnap-as) | Negotiate grants and expose token management and opt-in RS-facing APIs |
| [`gnap-rs`](crates/gnap-rs) | Authorize opaque-token resource requests using authenticated introspection and local proof checks |
| [`gnap-biscuit`](crates/gnap-biscuit) | Issue, attenuate and verify the Biscuit file-access profile |
| [`gnap-subject`](crates/gnap-subject) | Issue and verify pinned PS256 identity assertions with issuer, audience and session binding |
| [`gnap-types`](crates/gnap-types) | Parse and serialize GNAP messages, preserving extension fields |
| [`gnap-crypto`](crates/gnap-crypto) | Sign and verify HTTP request proofs, content digests and interaction hashes |
| [`gnap-core`](crates/gnap-core) | Apply grant-state transitions and response constraints |
| [`gnap-registry`](crates/gnap-registry) | Use the 23 GNAP IANA registries generated from vendored CSV data |
| [`gnap-net`](crates/gnap-net) | Apply conservative public-IP filtering at application network boundaries |

Start with the [integration guide](docs/getting-started.md#integrate-a-protocol-role)
and [architecture](docs/architecture.md). Generate the Rust API documentation
locally with:

```sh
cargo doc --workspace --no-deps --open --locked
```

## Documentation

The [documentation index](docs/README.md) groups guides by task: interaction,
multiple tokens, resource authorization, downstream delegation, identity
assertions and diagnostics.

The [support matrix](docs/support-matrix.md) describes supported profiles,
optional capabilities and remaining work. The
[evidence index](docs/README.md#support-and-evidence) separates reproducible
tests from dated hosted observations; neither is a blanket conformance claim.

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for development checks, documentation
conventions and the review process. Reproducible integration feedback is welcome.

## License

[Apache-2.0](LICENSE).
