# Library and application boundaries

The workspace separates protocol roles from the code that connects them to a
network, authenticates users and stores durable state. Start with the
[integration guide](getting-started.md#integrate-a-protocol-role) for runnable
examples; this page explains the contracts behind them.

## Protocol roles

| Component | Provides | Application supplies |
| --- | --- | --- |
| `gnap-client::Session` | Grant requests, response checks, interaction binding, continuation and token management | Signer, synchronous HTTP transport, timestamps and session ownership |
| `gnap-as::AuthorizationServer` | Grant processing, proof verification, state rules and credential management | Authorization policy, trusted key resolution, storage, nonce generation and HTTP routing |
| `gnap-rs::Authorizer` | Opaque-token introspection followed by local request authorization | Trusted transport, replay memory, audience and access policy |
| `gnap-biscuit` | A typed Biscuit file-access profile and request-proof validation | Trusted roots, replay memory and a live authority decision |

The client and AS do not choose an HTTP framework or async runtime. The supplied
client transport interface is synchronous. Network adapters must preserve the
signed method, exact URI, headers and body bytes, validate TLS and control
redirects, response sizes and timeouts. OS-backed clock and randomness helpers
remain distinct from timestamps supplied to protocol operations.

The [delegation lab](../apps/delegation-demo/README.md) co-locates its roles but
uses authenticated HTTP introspection for protected reads. The
[Biscuit application](../apps/biscuit-files/README.md) uses three processes and
a signed application-specific live-decision channel. That channel is not the
RFC 9767 introspection API.

## Messages and extensibility

`gnap-types` represents GNAP's object/reference and single/multiple forms with
dedicated types and deserializers. Diagnostics can identify the offending field
and relevant RFC rule. Shape validation remains distinct from cryptographic
verification, response-to-request checks and application authorization.

Continuation credentials use a separate `BoundToken` type that refuses bearer,
management and explicit-key fields. Access-token request cardinality and labels
are checked when adopting responses. The client validates interaction hashes
before using the returned reference and observes the continuation wait period.

Unknown message fields and unregistered registry values are retained for
extensions. Carrying an extension does not implement its meaning or authorize its
use: the selected handler and application policy still determine acceptance.
The [23 IANA registries](../registries) are generated from vendored CSV files so
changes can be reproduced and reviewed.

## Grants, tokens and storage

`gnap-core` implements the grant-state transitions and response constraints.
The AS stores a grant and its issued tokens as one revisioned aggregate; a
storage adapter must publish the aggregate and credential indexes atomically.
A stale write cannot restore a token removed by a concurrent operation.
See the [AS storage contract](../crates/gnap-as/src/lib.rs) before replacing
the in-memory adapter. Transactional interfaces do not themselves add persistence.

Deployment policy chooses rights, lifetimes, interaction and whether approval
keeps a continuation open. A grant can issue several independently selected
tokens; token management and grant continuation have different lifecycles.
See [multiple tokens](multiple-access-tokens.md) and the
[delegation lab](../apps/delegation-demo/README.md) for concrete flows.

The default encoder issues opaque reference tokens. The trusted
[`TokenEncoder`](../crates/gnap-as/src/encoding.rs) hook receives approved rights,
key binding and lifetime for issuance and rotation; management credentials stay
separate. A custom encoder must preserve these claims and have a matching RS
verifier. The hook is not a generic structured-token validator.

Biscuit attenuation adds restrictions without changing the client's key.
In the file application, rotating or revoking the parent retires its descendants
through live authority state. Token-value rotation and presentation-key rotation
are separate actions. Neither is a substitute for checking rights, proof and
expiry on every resource request.

## Trust and identity

A valid client key and signature prove possession, not the client's identity
or entitlement. The AS resolver and policy decide what to trust and approve.
Resource-owner authentication and consent UI belong to the application; the
public examples deliberately use synthetic identities.

Likewise, decoded subject information is not a verified identity assertion.
The [subject profile](subject-assertions.md) verifies a pinned issuer signature,
audience, time and session binding. Its ID Tokens are identity assertions, not
JWT access tokens.

The [support matrix](support-matrix.md) describes exact implemented profiles and
limitations. The [verification guide](verification.md) distinguishes local tests,
hosted application observations and independent interoperability evidence.
