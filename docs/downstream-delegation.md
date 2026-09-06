# Downstream delegation

This document describes the implemented opaque-token profile for the
[RFC 9767 §4](https://www.rfc-editor.org/rfc/rfc9767.html#section-4) scenario.
The [support matrix](support-matrix.md) remains the implementation inventory;
source and test evidence does not establish a hosted deployment or independent
interoperability.

## Two requests, two key bindings

A client calls RS1 with a token bound to the client's key. After authorizing
that request, RS1 asks the AS for a different token to call RS2. RS1 acts as
a client in this second grant: it identifies itself in `client` and signs
with its own key. The incoming token travels in `existing_access_token` in
the signed JSON body, never as RS1's authorization credential.

The AS must determine that this incoming token is appropriate for the
particular RS making the request. Recognizing an RS's signature alone is not
enough. The derived token is bound to RS1's key, not to the original client's
key. RS2 obtains that binding through authenticated introspection and verifies
RS1's actual resource request.

The grant request and response use the existing GNAP grant endpoint and
message structures. This mechanism adds no discovery field or separate
derivation endpoint. It is distinct from local Biscuit attenuation.

## Our deliberately bounded profile

These are project choices, not additional requirements attributed to RFC 9767:

- Opaque, key-bound tokens; HTTPSig with PS256 and fresh signature nonces.
- One downstream hop, with a different receiving RS. A derived token cannot
  itself be used to derive another token.
- One immediate token, without subject release, user information, interaction
  or an open continuation. Unsupported requests are refused, not silently
  converted into ordinary grants.
- A positive lifetime of at most 60 seconds, also bounded by the incoming
  token's remaining finite lifetime.
- An explicit application policy maps an authorized task at RS1 to the rights
  needed at RS2. This is not a generic JSON subset comparison across APIs.
- At most eight live derived children per incoming token in the reference
  store. Exceeding this profile budget refuses the request with a GNAP error,
  rather than reporting unavailable infrastructure. This is a resource bound,
  not a protocol limit.

The reference store separately bounds retained derived grants to 256 across
all parents, including grants whose token has been removed. Operators must
provide retention maintenance; token expiry alone does not purge grant records.
The demo performs maintenance, but does not supply durable storage.

The demo's intended task maps a synthetic folder read to a metadata read at
RS2. It does not authorize arbitrary URLs, arbitrary resource descriptions or
an expansion to write access. The client, RS1 and RS2 use distinct keys.
Their HTTP paths and AS are configured by the operator.

Registration for introspection does not itself enable the requesting role in
derivation. The demo admits only RS1 through the derivation resolver; RS2 is
registered for introspection but cannot request a child. For every admitted
requester, the AS's client-key resolver must agree with its RS-key resolver,
so the requester can manage the token it receives. A configuration mismatch
is refused before inspecting the parent value, without creating a grant.

Unknown, expired, revoked, bearer or wrongly addressed parent tokens, loops
and negative policy decisions receive the same generic refusal. The response
does not disclose whether a submitted value exists in the AS. This is not a
claim of constant-time processing.

## Lifetime and concurrent changes

In this profile, each derived token belongs to a separate grant, whose client
is RS1. Creation
must commit only while the exact incoming token is still live and the
authenticated parent snapshot is current: the store checks its revision in
the same transaction that creates the child. This is a storage guarantee,
not a claim of network freshness. A conflict does not automatically retry
proof, policy evaluation or issuance.

Our dependency follows the incoming token, not every revision of its grant.
Removing, rotating or replacing that token invalidates its derived children
atomically. Removing its grant does the same. A pending interaction or a
refusal that merely ends continuation does not revoke children while the
incoming token remains live.

RS1 may delete a derived token through its token-management endpoint using
the associated management credential and RS1's proof. This does not affect
the incoming token. There is no child grant-continuation endpoint in this
profile, and rotating a derived token is refused.

These guarantees concern AS state transitions. They do not make a network
response atomic with a later revocation: an introspection decision can race
a subsequent change. Each protected call performs a fresh check; no positive
introspection result is cached.

## Evidence and remaining limits

[SDK tests](../crates/gnap-as/tests/derivation.rs) cover parent retirement,
concurrent creation, exact key binding, uniform refusals and storage bounds.
[Consumer tests](../apps/delegation-demo/src/derivation_tests.rs) send actual
HTTP requests through client, RS1, AS and RS2, including cross-audience,
wrong-key and replay refusals, finite lifetimes and parent rotation/revocation.
The [acceptance script](../tools/smoke_ecosystem.py) also drives the visible
metadata action. [Imported-message tests](../apps/conformance-web/tests/derivation_imports.rs)
check selected JSON rules, but cannot establish these authenticated state or
policy properties.

The incoming token, child token, management credential and private keys must
not appear in browser results, logs or published evidence. Co-located roles
using HTTP are useful integration evidence, not independently deployed
services or third-party interoperability. Synthetic data and volatile storage
do not establish production readiness.
