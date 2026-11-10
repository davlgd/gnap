# gnap

Rust libraries, example applications, and diagnostic tools for the [Grant Negotiation and Authorization Protocol (GNAP)](https://www.rfc-editor.org/rfc/rfc9635) and its [resource-server connections](https://www.rfc-editor.org/rfc/rfc9767). Build a client that requests access, an authorization server that negotiates it, and a resource server that checks both the permission and the key presenting it.

GNAP is its own delegated-authorization protocol, not an OAuth-compatible API. To see how its design compares with modern OAuth extensions, read [GNAP and modern OAuth](docs/gnap-and-modern-oauth.md).

> [!WARNING]
> **Experimental, unaudited libraries.** The crates are pre-1.0 and haven't had an independent security review. A minor version can change the public API and raise the minimum supported Rust version.

## What the libraries support

The libraries sign and verify requests with HTTP Message Signatures, the `httpsig` proof method, with PS256, ES256, or Ed25519 keys, and with the `jws` and `jwsd` proof methods, with RS256, ES256, or EdDSA keys. Both GNAP conformance profiles require `httpsig` with PS256. The libraries issue opaque reference tokens, which a resource server checks through authenticated introspection, and an attenuable Biscuit token profile for file access.

The [support matrix](docs/support-matrix.md) gives the state, limits, and tests of each capability, and what the libraries leave out.

## Try the applications

| Application                                                    | What to try                                                                            | Run it yourself                                         |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| [Delegation lab](https://gnap-delegation.cleverapps.io)        | Approve document access, change a grant's rights, request several tokens, rotate them  | [Setup and scenarios](apps/delegation-demo/README.md)   |
| [Biscuit files](https://gnap-biscuit.cleverapps.io)            | Restrict a token locally, read and write with distinct rights, revoke the parent token | [Three-process setup](apps/biscuit-files/README.md)     |
| [Diagnostic workbench](https://gnap-conformance.cleverapps.io) | Inspect GNAP messages, or exercise an operator-approved authorization server           | [Setup and diagnostics](apps/conformance-web/README.md) |

The hosted applications use synthetic data and volatile state: don't submit personal data or production credentials. An active network test needs the permission of the endpoint owner and a target the operator approved.

## Run your first grant

Clone the repository and run the narrated example, which plays a client and an authorization server in one process:

```bash
git clone https://github.com/davlgd/gnap.git
cd gnap
cargo run -p gnap-as --example flow --locked
```

It requests access, simulates the resource owner's approval, validates the callback, obtains a token, then rotates and revokes it. It uses the real SDK roles over an in-memory transport, without starting an HTTP server.

The SDK workspace requires Rust 1.95 or newer. The applications have their own toolchain requirements, in their guides. [Getting started](docs/getting-started.md) annotates the output, and shows more examples and how to integrate each role.

## Use the libraries

Choose the crate for your protocol role. The client and the authorization server impose neither an HTTP framework nor an async runtime: your application supplies the transport, trust decisions, and authorization policy. The in-memory stores serve the examples; persistent storage and user authentication belong to your deployment.

| Crate                                   | Purpose                                                                             |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| [`gnap-client`](crates/gnap-client)     | Build and sign grant requests, follow interaction and continuation, manage tokens   |
| [`gnap-as`](crates/gnap-as)             | Negotiate grants, and expose token management and the opt-in resource-server APIs   |
| [`gnap-rs`](crates/gnap-rs)             | Authorize resource requests with authenticated introspection and local proof checks |
| [`gnap-biscuit`](crates/gnap-biscuit)   | Issue, attenuate, and verify the Biscuit file-access profile                        |
| [`gnap-subject`](crates/gnap-subject)   | Issue and verify identity assertions bound to an issuer, an audience, and a session |
| [`gnap-types`](crates/gnap-types)       | Parse and serialize GNAP messages, keeping extension fields                         |
| [`gnap-crypto`](crates/gnap-crypto)     | Sign and verify request proofs, content digests, and interaction hashes             |
| [`gnap-core`](crates/gnap-core)         | Apply grant-state transitions and response constraints                              |
| [`gnap-registry`](crates/gnap-registry) | Use the 23 GNAP IANA registries, generated from vendored copies                     |
| [`gnap-net`](crates/gnap-net)           | Filter public IP addresses at the network boundaries of an application              |

The crates are published on crates.io, and their API documentation on docs.rs. Start with the [integration guide](docs/getting-started.md#add-the-libraries-to-your-application) and the [architecture](docs/architecture.md). To read the API documentation locally, run:

```bash
cargo doc --workspace --no-deps --open --locked
```

## Documentation

The [documentation index](docs/README.md) groups the guides by task: interaction, multiple tokens, resource authorization, downstream delegation, identity assertions, and diagnostics. The [evidence ledger](conformance/README.md) maps RFC requirements to reproducible tests, without claiming overall conformance. The [changelog](CHANGELOG.md) lists the changes of each release.

## Contribute

[CONTRIBUTING.md](CONTRIBUTING.md) explains how to propose and check a change, the quality the code aims for, and the review process. Reproducible integration feedback is welcome.

## License

[Apache-2.0](LICENSE).
