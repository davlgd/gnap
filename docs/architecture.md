# Architecture

The libraries implement the protocol roles, and leave to your application the network, the authentication of users, and durable storage. This page explains the contract between the two; [Getting started](getting-started.md#add-the-libraries-to-your-application) shows it in runnable examples.

## Protocol roles

| Component | Provides | Application supplies |
| --- | --- | --- |
| `gnap-client::Session` | Grant requests, response checks, interaction binding, continuation and token management | Signer, synchronous HTTP transport, timestamps and session ownership |
| `gnap-as::AuthorizationServer` | Grant processing, proof verification, state rules and credential management | Authorization policy, trusted key resolution, storage, nonce generation and HTTP routing |
| `gnap-rs::Authorizer` | Opaque-token introspection followed by local request authorization | Trusted transport, replay memory, audience and access policy |
| `gnap-biscuit` | A typed Biscuit file-access profile and request-proof validation | Trusted roots, replay memory and a live authority decision |

Neither the client nor the authorization server imposes an HTTP framework or an async runtime, and the client's transport interface is synchronous. Network adapters must preserve the signed method, exact URI, headers and body bytes, validate TLS and control redirects, response sizes and timeouts. The clock and randomness helpers backed by the operating system stay separate from the timestamps that you pass to each protocol operation.

The [delegation lab](../apps/delegation-demo/README.md) runs its roles in one process, but uses authenticated HTTP introspection for protected reads. The [Biscuit files application](../apps/biscuit-files/README.md) runs three processes, linked by a signed live-decision channel of its own, which isn't the introspection API of RFC 9767.

## Messages and extensibility

`gnap-types` represents GNAP's object/reference and single/multiple forms with dedicated types. Its diagnostics name the field and the RFC rule. Checking a message's shape is distinct from verifying its signature, matching a response to its request, and authorizing it.

Continuation credentials use a separate `BoundToken` type that refuses bearer, management and explicit-key fields. Access-token request cardinality and labels are checked when adopting responses. The client validates interaction hashes before using the returned reference and observes the continuation wait period.

Unknown message fields and unregistered registry values are retained for extensions. Carrying an extension doesn't implement its meaning or authorize its use: the selected handler and application policy still determine acceptance. The code of the [23 IANA registries](../registries) is generated from vendored CSV files, so that each change can be reproduced and reviewed.

## Grants, tokens and storage

`gnap-core` implements the grant-state transitions and response constraints. The AS stores a grant and its issued tokens as one revisioned aggregate; a storage adapter must publish the aggregate and credential indexes atomically. A stale write can't restore a token removed by a concurrent operation. See the [AS storage contract](../crates/gnap-as/src/lib.rs) before replacing the in-memory adapter. A transactional interface alone doesn't make the storage behind it persistent across restarts.

Deployment policy chooses rights, lifetimes, interaction and whether approval keeps a continuation open. A grant can issue several independently selected tokens; token management and grant continuation have different lifecycles. See the [multiple-token guide](multiple-access-tokens.md) and the [delegation lab](../apps/delegation-demo/README.md) for concrete flows.

The default encoder issues opaque reference tokens. The trusted [`TokenEncoder`](../crates/gnap-as/src/encoding.rs) hook receives approved rights, key binding and lifetime for issuance and rotation; management credentials stay separate. A custom encoder must preserve these claims and have a matching RS verifier. The hook isn't a generic structured-token validator.

Biscuit attenuation adds restrictions without changing the client's key. In the file application, rotating or revoking the parent retires its descendants through live authority state. Token-value rotation and presentation-key rotation are separate actions. Neither is a substitute for checking rights, proof and expiry on every resource request.

## Trust and identity

A valid client key and signature prove possession, not the client's identity or entitlement. The AS resolver and policy decide what to trust and approve. The authentication of the resource owner and the consent interface belong to the application; the public examples use only synthetic identities on purpose.

Likewise, decoded subject information isn't a verified identity assertion. The [subject profile](subject-assertions.md) verifies a pinned issuer signature, audience, time and session binding. Its ID Tokens are identity assertions, not JWT access tokens.

The [support matrix](support-matrix.md) describes exact implemented profiles and limitations. The [verification guide](verification.md) separates local tests, observations of hosted applications, and interoperability with independent implementations.
