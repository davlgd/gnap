# gnap

Rust libraries and application examples for the **Grant Negotiation and
Authorization Protocol** ([RFC 9635]). The resource-server connection APIs
defined by [RFC 9767] are planned, not yet implemented.

GNAP is not an extension of OAuth 2.0 and is not compatible with it. It solves
the same family of problems — delegating authorization to a piece of software —
with a different design: a single grant endpoint, negotiation over multiple
steps, and key-bound requests and tokens as the default.

> **Status: work in progress.** A client and an authorization server complete a
> full grant between them — request, signature, interaction, callback,
> continuation, token — with both roles implemented here, and the token it
> issues can be rotated and revoked (§6). The application examples add a real
> HTTP client/AS flow, a co-located protected resource, and a diagnostic
> workbench. These are experimental consumers, not a complete conformance suite
> or an implementation of the RFC 9767 connection APIs.
> See [what is implemented, and what is not](#what-is-implemented-and-what-is-not).

The [support matrix](docs/support-matrix.md) records the selected scope and its
evidence: Biscuit is the structured-token target, signed/encrypted JWTs are
acceptable alternatives, and Macaroon/ZCAP implementations are out of scope for
now. HTTP Message Signatures are preferred; mTLS is an allowed addition.
These are project decisions, not claims that those features are already present.

[RFC 9635]: https://www.rfc-editor.org/rfc/rfc9635
[RFC 9767]: https://www.rfc-editor.org/rfc/rfc9767

## Crates

| Crate | What it does |
|---|---|
| [`gnap-registry`](crates/gnap-registry) | GNAP's 23 IANA registries, generated from the official CSV files |
| [`gnap-types`](crates/gnap-types) | The message data model: serialization, polymorphism, shape validation |
| [`gnap-crypto`](crates/gnap-crypto) | Signing and shared GNAP request verification (`httpsig`, `PS256`), interaction hash, `Content-Digest` |
| [`gnap-core`](crates/gnap-core) | The grant state machine (§1.5): transitions, guards, response checking |
| [`gnap-client`](crates/gnap-client) | The client instance role, over a pluggable HTTP transport |
| [`gnap-as`](crates/gnap-as) | The authorization server role, free of any HTTP framework |
| [`gnap-biscuit`](crates/gnap-biscuit) | A bounded file-access token profile: issuance, attenuation and proof-bound authorization, currently exercised in process |

The workspace forbids unsafe code in its own crates. The protocol roles leave
network and persistent storage I/O to the caller; clock and randomness helpers
use the operating system.

## Try it

Watch a complete grant happen, narrated:

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
[that example](crates/gnap-as/examples/flow.rs) top to bottom is the fastest way
to see what the protocol looks like.

### Applications over HTTP

The standalone applications in `apps/` consume the public library APIs and have
their own dependency locks and toolchain requirements:

- [Delegation demo](apps/delegation-demo/README.md): approve or deny access to a
  synthetic dossier, read its protected resource, rotate a token and check that
  retired tokens are rejected. The AS and RS share volatile storage; there is
  no RFC 9767 introspection endpoint or production user authentication.
- [Web diagnostics](apps/conformance-web/README.md): inspect imported messages
  and run bounded rejection probes against operator-approved AS/RS endpoints.
  Reports distinguish passed, failed and untested checks, with no overall
  certification verdict.

Try the hosted [delegation demo](https://app-05b4e19a-d5da-408d-b524-2d9609e5cd01.cleverapps.io)
and [diagnostic workbench](https://gnap-conformance.cleverapps.io).
These experimental deployments use synthetic data and volatile state. Do not
submit personal data or production credentials. Active probes are restricted to
operator-approved targets, not arbitrary public endpoints.

See the [development methodology](docs/ecosystem-development.md), the consumer
feedback in each application, and the [comparison with modern
OAuth](docs/gnap-and-modern-oauth.md). Benefits are hypotheses to test through
applications, not claims that OAuth lacks its modern security extensions.
The [5 September 2026 validation record](docs/validation-2026-09-05.md) separates
local tests, browser observations and deployed HTTPS checks.

Sign a grant request, then verify it:

```console
$ cargo run -p gnap-crypto --example sign
POST /gnap HTTP/1.1
Host: server.example.com
Content-Type: application/json
Content-Digest: sha-256=:DC/WJVB4sbS8WKJVhQOySoPqzbp558DltPTtXPP7nAo=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=1788020832;nonce="ZhmyT9rY…";keyid="gnap-demo";tag="gnap"
Signature: sig1=:GM+GZxDDHywdtTq9ctfz2Wet/4hAHcsc+73Tu1j9UzI4Sj8fTRSD…:

{ … }
```

Lint a message against the RFC:

```console
$ echo '{"client":"c","access_token":[{"access":["a"]},{"access":["b"]}]}' \
    | cargo run -q -p gnap-types --example lint -- request
REJECTED
  access_token[0]: `label` is required for a multiple token request
  (RFC 9635 §2.1.2 -> invalid_request)
```

The two chain together — the body `sign` produces passes `lint`.

## Design notes

**Error messages cite the RFC.** Every rejection names the field, the section,
and the GNAP error code where one exists. A conformance tool that only says
"invalid" is worth very little to the person who has to fix the message.

**No `#![serde(untagged)]`.** GNAP has eight polymorphic fields (Appendix E), and
`untagged` handles them badly: on a nested error it reports at the outer enum
and loses the offending field, and it silently accepts several RFC violations —
missing labels, duplicate labels, duplicate flags. Each polymorphic field gets
its own `Deserialize` visitor instead. This was measured, not assumed.

**Neither role brings a runtime.** `gnap-client` sends through a trait;
`gnap-as` takes a described request and returns a described response. What
carries the bytes — hyper, axum, a test harness — is the caller's business. The
immediate payoff is that the two roles wire straight together: the interop suite
runs a complete grant with no network at all, both sides being the real
implementations rather than mocks agreeing with each other.

**The transport is a trait, not a dependency.** `gnap-client` describes HTTP
requests and responses as bytes and asks the caller to move them. The
conformance harness this project is built around has to send deliberately
malformed requests — a broken signature, a forbidden field, a replayed
interaction reference — and a well-behaved typed HTTP client fights that. Two
consequences follow: the client is testable with no network, and no runtime is
forced on anyone depending on the crate.

**A client that refuses.** What makes `gnap-client` more than a wrapper around
an HTTP call is what it rejects. An interaction hash that does not validate
never becomes a request (§4.2.1). A bearer token carrying a key is refused
(§3.2.1). A response that changes shape is refused (§3.2.1, §3.2.2). The `wait`
period is enforced before anything leaves (§5). An AS that breaks the rules is
caught rather than followed.

**Some RFC constraints are structural, not checked.** The requested cardinality
travels from request to response in the type (§3.2.1, §3.2.2), so an array
answer to an object request cannot be built. `BoundToken` is a distinct type
from `AccessToken`: it refuses `key` and `manage` while parsing rather than
absorbing them into its extension map, and it refuses the `bearer` flag while
carrying any other, so a bearer continuation token is unrepresentable (§3.1).
`TokenValue` validates the `token68` character set at construction.

Where a requirement turns on something only the deployment knows, the type asks
it to say so. §3.4 lets the AS return subject information "only in cases where
the AS is sure that the RO and the end user are the same party" — a judgement no
library can make. So a policy cannot release subject information without naming
its ground, and the one ground the RFC itself names, interaction, is checked
against what actually happened on that grant. On the other side, subject
information reaches a caller paired with the AS that stated it, because an email
address identifies someone *at one AS* and nowhere else (§3.4).

**Unknown values survive.** GNAP is designed to be extended (Appendix D).
Unregistered registry values are carried in an `Unregistered(String)` variant
rather than rejected, and unknown message fields land in an `extra` map instead
of being dropped. Rejecting them would make the library obsolete on every new
IANA registration.

**IANA registries are vendored, then generated.** The 23 CSV files live in
[`registries/`](registries) and `tools/generate_registry.py` turns them into
code. Generation stays reproducible and offline, and a `git diff` shows exactly
what IANA changed.

The generator uses `rustfmt` from the installed Rust toolchain. CI checks that
the vendored CSV files reproduce the committed artifact before checking for
upstream registry changes.

```console
python3 tools/fetch_registries.py    # refresh registries/*.csv from iana.org
python3 tools/generate_registry.py   # regenerate crates/gnap-registry/src/generated.rs
```

## Conformance

RFC 9635 defines two interoperability profiles in Appendix C — *Web-Based
Redirection* and *Secondary Device*. They are the only normative
mandatory-to-implement sets in the whole specification, and they are what this
project targets.

Development is driven by a requirements base extracted from the RFC XML, where
the RFC Editor tags every BCP 14 keyword in a `<bcp14>` element. That extraction
is reconciled: **every keyword in both documents is either attached to a
requirement or explicitly excluded**. The requirements base and its extraction
tools are local development material, not part of this repository, so that
coverage report cannot be reproduced from a clone alone. Tests and vectors in
the repository cite the requirements they exercise.

Test vectors live in [`vectors/`](vectors) and are consumed directly by the test
suites. The interaction hash and key rotation vectors published by the RFCs are
reproduced byte for byte.

The state machine goes one step further: [`vectors/state-machine.json`](vectors/state-machine.json)
describes this project's model — four states, twelve transitions, nine response
constraints, seven guards and five invariants, each citing the requirement it
comes from. Specification tests read that file and check it against the code.
Invariant tests also enumerate event sequences up to four or five steps using
representative inputs. This bounded exploration does not establish the
invariants for every possible history. Local tests between these two roles do
not establish network interoperability or complete RFC conformance.

## What is implemented, and what is not

The implemented grant flow covers the request (§2), the response (§3), the
interaction the AS drives and the callback it makes (§4), all four continuation
operations (§5) — poll, return from interaction, modify, revoke — the token
management API (§6), and the `httpsig` key proof both roles use (§7.3.1).
The message model also represents resource access rights (§8); interpreting
API-specific rights remains the authorization policy's responsibility.

These parts of the specification are **not** implemented, and nothing here
should be read as covering them:

| Section | What is missing |
|---|---|
| §3.5 | Dynamically issuing a client instance identifier |
| §6.1.1 | Binding a **new key** while rotating a token; it needs the two simultaneous proofs of §7.3.1.1, and the AS answers `key_rotation_not_supported` as §6.1.1-M08 provides for |
| §7.3.2–§7.3.4 | The `mtls`, `jwsd` and `jws` key proofing methods |
| §7.3.1.1 | Key rotation, and with it the `gnap-rotate` signature tag |
| §9.1 | Resource-server-first discovery |
| RFC 9767 | Introspection, resource sets, and the RS-facing API |

The interaction modes the AS drives are `redirect` and, with no finish method,
polling. `app`, `user_code` and `user_code_uri` are modelled in `gnap-types` but
no AS in this workspace starts them.

The AS answers OPTIONS at its grant endpoint with the discovery document from
§9. It announces only its implemented proof method and lack of bound-key
rotation; deployment-dependent capability lists are omitted. Public discovery
requires HTTPS. Local HTTP loopback is an explicit development-only opt-in,
labelled in the response; it is not a protocol exception. No client-side
discovery helper or RFC 9767 discovery service is supplied yet.

The AS currently issues one key-bound token per approval, preserving the
requested object or array shape. `Policy::token_lifetime` can select a positive
duration, advertised as `expires_in`; the default omits it. The demo selects
20 minutes. Successful rotation renews that duration, while a refused rotation
preserves the original timestamp. Resource servers must enforce expiration as
well as proof and rights; the SDK provides `TokenRecord::is_valid_at` for the
time check. Authentication of the resource owner, consent, authorization policy, key
management, durable storage and HTTP adapters belong to the deployment. The
included store is in memory; the client transport interface is blocking.
Grant state and its issued tokens now share one revisioned aggregate. The
storage adapter commits the aggregate and all credential indexes atomically;
stale writes cannot restore a token removed by a concurrent revoke. Policy and
proof verification run outside the store transaction. Custom adapters must
implement the [transactional storage contract](crates/gnap-as/src/lib.rs),
including collision checks, failure reporting and maintenance removal. This
does not add persistence or continuation after grant approval.
Revoked-token records are removed. A later call to the old management URI is
rejected because its key binding can no longer be verified; the idempotent
revocation recommended in §6.2 would require retaining authentication metadata.

The AS's existing token path uses opaque references. The separate `gnap-biscuit`
crate issues and verifies a restricted file-access profile, including local
attenuation, HTTP request proof and a mandatory live-decision callback for
revocation and replay policy. Its
[executable example](crates/gnap-biscuit/examples/file_access.rs) runs in process;
it is not yet an integrated GNAP grant flow, a distributed deployment or an
authenticated revocation transport. JWT, Macaroon and ZCAP implementations are
not supplied. The AS issues neither bearer nor `durable` tokens.

Applications can select a different representation through
[`TokenEncoder`](crates/gnap-as/src/encoding.rs) and
`AuthorizationServer::with_token_encoder`. The default remains opaque. Issuance
and rotation pass only the approved rights, client binding and lifetime to the
encoder; management credentials stay separate. This is trusted deployment
code: the AS cannot verify that a custom format preserves those claims. The
matching RS verifier and any format-native revocation index remain necessary.
An encoder failure during rotation leaves the existing record unchanged;
the hook itself is not a structured-token implementation.

Key objects reach the deployment's `KeyResolver`. For public RSA/PS256 JWKs,
`Ps256Signer::public_jwk` exports a public key and
`Ps256Verifier::from_public_jwk` builds a verifier without prior registration.
The [JWK client example](crates/gnap-as/examples/jwk_client.rs) exercises this
path through grant issuance, rotation and revocation:

```sh
cargo run -p gnap-as --example jwk_client --locked
```

This adapter accepts 2048–4096-bit RSA keys, requires GNAP's `alg` and `kid`,
and checks usage metadata. It rejects private and certificate parameters;
no X.509 conversion or trust service is supplied. A valid key and proof do not
establish a client's identity or entitlement. The example uses an in-process
transport and a synthetic policy, not a network or production identity service.

Subject assertions are represented, not authenticated:
the `id_token` payload is decoded only for within-response consistency checks,
and no ID-token or SAML validation service is provided. Push-finish callbacks
are constructed and validated in protocol tests; sending them over HTTP remains
the adapter's responsibility.

## Roadmap

| | |
|---|---|
| ✅ | Vendored IANA data, message model, `httpsig`/PS256 primitives and interaction hash; not every represented capability has a runtime implementation |
| ✅ | `gnap-core` — the grant state machine (§1.5) |
| ✅ | `gnap-client` — the client instance role, §2 through §5 |
| ✅ | `gnap-as` — the authorization server role, §2 through §5 |
| ✅ | `gnap-as` and `gnap-client` — token management (§6): rotate and revoke |
| ⬜ | Key rotation (§6.1.1, §7.3.1.1) and the remaining key proofing methods |
| ⬜ | `gnap-rs` — RFC 9767, introspection and resource sets |
| 🚧 | HTTP application acceptance tests and bounded web diagnostics; full network conformance harness remains open |

The [support matrix](docs/support-matrix.md) is the detailed capability inventory;
these milestones are not blanket conformance claims for entire RFC sections.

## Working on it

Changes follow the [contribution and review process](CONTRIBUTING.md), including
adversarial review and the maintainer's Copilot review gate before merge.

```console
cargo test                                   # unit, integration and every RFC vector
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps --open       # every public item is documented

python3 tools/check_quotes.py                # selected RFC quotations match the text
python3 tools/check_readme.py                # transcript and available local scope check
```

The last two are worth explaining. The code quotes the RFCs constantly, to say
why it does what it does; a quotation that has drifted lends the authority of
the normative text to a sentence the working group never wrote.
`check_quotes.py` checks double-quoted passages of at least five words in
comments near RFC citations, excluding documentation code blocks. It downloads
missing RFCs and compares the passages after normalising whitespace, quotes,
backticks, emphasis markers and line-break hyphenation. It accepts an explicit
`[...]` elision. This checks selected quotations, not every paraphrase, section
reference or claim of conformance.

`check_readme.py` checks that the transcript above is what the example actually
prints. When the local requirements base is available, it also compares the
section numbers listed as unimplemented with the declared exclusions; otherwise
it reports that check as skipped. It does not verify the meaning of those
sections or prove that every description in this file matches the code.

The layout:

```
crates/          protocol SDK crates and the Biscuit file-profile adapter
registries/      the 23 IANA CSV files, vendored
vectors/         test vectors and the state machine specification
tools/           fetch the registries, and check what the code claims
```

Two files are worth reading before the code:
[`vectors/state-machine.json`](vectors/state-machine.json), which specifies the
grant lifecycle the implementation is checked against, and
[`crates/gnap-as/examples/flow.rs`](crates/gnap-as/examples/flow.rs), which runs
it.

Protocol tests cite RFC requirements in their doc comments, in the form
`GNAP-9635-§3.2.1-M30`. If you add behaviour, name what it comes from.

## Requirements

Rust 1.85 or later, as required by the `httpsig` dependency. Unsafe code is
forbidden in the workspace's own crates; this does not apply to dependencies.

## License

Apache-2.0. See [LICENSE](LICENSE).
