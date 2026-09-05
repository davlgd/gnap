# Building GNAP through real applications

The objective is a reference ecosystem: reusable protocol libraries, applications
that consume their public APIs, and a web-accessible conformance workbench.
This is a development programme, not a claim that every GNAP feature is already
implemented or that a green report certifies an implementation.

The [support matrix](support-matrix.md) records the current product decisions and
implementation evidence. Biscuit is the required structured-token target;
signed/encrypted JWTs are acceptable alternatives, while Macaroon and ZCAP
implementations are out of scope for now. Prefer HTTP Message Signatures; mTLS
is an allowed additional proof method. Delivery follows the
[review and merge process](../CONTRIBUTING.md).

## The feedback loop

1. A consumer developer chooses a concrete user task and attempts it using the
   published README and public APIs, without changing library internals.
2. The developer records reproducible friction: attempted code, missing context,
   misleading documentation, application-specific glue, and observed failures.
3. Library maintainers and a peer reviewer distinguish an application policy from
   a missing reusable primitive. Fixes get regression tests and documentation.
4. The application consumes the fix and repeats the task over real HTTP.
5. A separately developed test runner exercises the application and records the
   exact revision, scenario, observations, and unsupported checks.

The specification remains the source of protocol requirements. Real deployments
test whether the implementation is usable and whether our interpretation survives
transport, application state, consent, and failure conditions.

## First consumers

| Consumer | User task | What it puts under pressure |
| --- | --- | --- |
| `apps/delegation-demo` | Explicitly delegate access to a synthetic shared dossier, use the grant, rotate and revoke access | Client session ownership, consent correlation, transport, token lookup and proof verification |
| `apps/conformance-web` | Import a GNAP message and obtain a scoped diagnostic report; run only explicitly enabled network probes | Diagnostics, malformed input, test evidence and safe public operation |

These applications are separate Cargo workspaces with path dependencies on the
libraries. They intentionally experience the APIs as integrators do. Their
`DEVELOPER_FEEDBACK.md` files are evidence, not merely a list of desired features.

An initial resource server can share storage with its authorization server.
That is a real deployment model, but it is **not** an implementation of the
RFC 9767 introspection API. A later independently deployed resource service will
drive authenticated introspection, discovery and resource registration.

## Acceptance gates

- Extract the shared GNAP verifier before integrating resource proof validation.
  Preserve the existing AS interaction tests unchanged.
- A demonstration must use real GNAP operations for the behaviour it advertises.
  Label simulated identity/consent, volatile storage, and unavailable features.
- Every added feature needs successful and failing examples, reproducible tests,
  peer review, and an explicit scope update. Commit coherent checkpoints.
- Test reports distinguish `pass`, `fail`, and `not-tested`. A check using the
  same parser as the implementation is not an independent parsing oracle.
- Passing our roles against each other, even over HTTPS, does not establish
  interoperability with an unrelated implementation.
- Record efficiency measurements with their conditions: revision, build mode,
  request count, workload, concurrency and environment. Do not invent performance
  claims from a single successful request.

## Safe deployment boundary

Use synthetic data and runtime-generated demonstration keys. Do not embed test
fixture private keys, developer credentials, or private requirement ledgers in a
public application. Browser sessions must be isolated; consent-changing actions
must be protected against cross-site requests. Bound request sizes, processing,
state retention and concurrency. Do not record imported secrets in logs.

The web test runner must not be an arbitrary URL fetcher. Active probes need an
operator-controlled target policy, target consent, bounded responses/timeouts,
redirect restrictions, and protection against private-network and metadata access.
Imported-message diagnostics can be available without permitting outbound probes.

Deploy only the new GNAP applications to the explicitly requested Clever Cloud
test account. Set a dedicated **M build instance for every application** and
verify the setting through the API. Runtime sizing is separate from build sizing.
Do not change unrelated applications. Application IDs and account linkage belong
in local deployment configuration, not reusable source examples.

## Expansion driven by use

After the first applications are actually exercised, use their feedback to choose
the next slices: separate AS/RS introspection, resource discovery and registration,
richer and multiple rights/tokens, further interaction modes, key rotation, and
additional proof methods. Maintain explicit unsupported cases until implemented.

Durable storage, transactions, restart behaviour and operational key management
are required before presenting an application as production-ready. The examples
are not production identity providers.

Comparisons should use modern OAuth and its relevant extensions, not assume that
OAuth lacks proof of possession, rich authorization or decoupled interactions.
See [GNAP and modern OAuth](gnap-and-modern-oauth.md) for sourced comparisons and
scenarios that can actually be demonstrated.
