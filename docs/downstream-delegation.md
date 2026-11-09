# Downstream delegation

A resource server can ask the authorization server for a new token, to call another resource server on behalf of the client, as [RFC 9767 §4](https://www.rfc-editor.org/rfc/rfc9767.html#section-4) describes. This guide explains the opaque-token profile that the libraries implement for it, and what the delegation lab shows.

## Two requests, two key bindings

A client calls RS1 with a token bound to the client's key. After authorizing that request, RS1 asks the AS for a different token to call RS2. RS1 acts as a client in this second grant: it identifies itself in `client` and signs with its own key. The incoming token travels in `existing_access_token` in the signed JSON body, never as RS1's authorization credential.

The AS must determine that this incoming token is appropriate for the particular RS making the request. Recognizing an RS's signature alone isn't enough. The derived token is bound to RS1's key, not to the original client's key. RS2 obtains that binding through authenticated introspection and verifies RS1's actual resource request.

The grant request and response use the ordinary GNAP grant endpoint and messages. This mechanism adds no discovery field or separate derivation endpoint. It is distinct from local Biscuit attenuation.

## A bounded profile

These are choices of this project, not requirements of RFC 9767:

- Opaque, key-bound tokens, with `httpsig` and fresh signature nonces
- One downstream hop, to a different resource server: a derived token can't derive another one
- One immediate token, without subject, user information, interaction, or continuation
- A lifetime of at most 60 seconds, within the remaining lifetime of the incoming token
- An application policy that maps an authorized task at RS1 to the rights needed at RS2
- At most eight live derived tokens per incoming token, in the reference store

A request outside this profile is refused, never converted into an ordinary grant. The mapping policy isn't a generic comparison of JSON subsets across APIs. Exceeding the budget of eight derived tokens returns a GNAP error rather than an unavailability, as a resource bound and not a protocol limit.

The reference store separately bounds retained derived grants to 256 across all parents, including grants whose token has been removed. Operators must provide retention maintenance; token expiry alone doesn't purge grant records. The lab runs it, without durable storage.

The lab's task maps a synthetic folder read to a metadata read at RS2. It doesn't authorize arbitrary URLs, arbitrary resource descriptions or an expansion to write access. The client, RS1 and RS2 use distinct keys. Their HTTP paths and AS are configured by the operator.

Registration for introspection doesn't itself enable the requesting role in derivation. The lab admits only RS1 through the derivation resolver; RS2 is registered for introspection but can't request a child. For every admitted requester, the AS's client-key resolver must agree with its RS-key resolver, so the requester can manage the token it receives. A configuration mismatch is refused before inspecting the parent value, without creating a grant.

Unknown, expired, revoked, bearer or wrongly addressed parent tokens, loops and negative policy decisions receive the same generic refusal. The response doesn't disclose whether a submitted value exists in the AS. This isn't a claim of constant-time processing.

## Lifetime and concurrent changes

In this profile, each derived token belongs to a separate grant, whose client is RS1. Creation must commit only while the exact incoming token is still live and the authenticated parent snapshot is current: the store checks its revision in the same transaction that creates the child. This is a storage guarantee, not a claim of network freshness. A conflict retries neither the proof, nor the policy, nor issuance.

The dependency follows the incoming token, not every revision of its grant. Removing, rotating or replacing that token invalidates its derived children atomically. Removing its grant does the same. A pending interaction or a refusal that merely ends continuation doesn't revoke children while the incoming token remains live.

RS1 may delete a derived token through its token-management endpoint using the associated management credential and RS1's proof. This doesn't affect the incoming token. There is no child grant-continuation endpoint in this profile, and rotating a derived token is refused.

These guarantees concern AS state transitions. They don't make a network response atomic with a later revocation: an introspection decision can race a subsequent change. Each protected call performs a fresh check; no positive introspection result is cached.

## Evidence and remaining limits

[SDK tests](../crates/gnap-as/tests/derivation.rs) cover parent retirement, concurrent creation, exact key binding, uniform refusals and storage bounds. [Lab tests](../apps/delegation-demo/src/derivation_tests.rs) send actual HTTP requests through client, RS1, AS and RS2, including cross-audience, wrong-key and replay refusals, finite lifetimes and parent rotation/revocation. The [acceptance script](../tools/smoke_ecosystem.py) also drives the visible metadata action. [Imported-message tests](../apps/conformance-web/tests/derivation_imports.rs) check selected JSON rules, but can't establish these authenticated state or policy properties.

The incoming token, child token, management credential and private keys mustn't appear in browser results, logs or published evidence. Co-located roles using HTTP are useful integration evidence, not independently deployed services or third-party interoperability. Synthetic data and volatile storage don't establish production readiness.
