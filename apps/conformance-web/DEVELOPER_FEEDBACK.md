# Integrator feedback from building the diagnostics application

This feedback comes from implementing a real HTTP consumer, not a claim that an
independent implementation has passed GNAP interoperability tests.

## What worked

- Protocol messages are usable without running an AS or transport framework.
- Explicit polymorphic visitors catch meaningful errors, notably repeating the
  client on continuation, and keep JSON shape aligned with RFC terminology.
- Keeping raw HTTP body bytes and ordered header pairs is the right API shape
  for signature/digest tooling. The application preserves that boundary.
- Pure digest validation fits imported diagnostic use without a cryptographic
  key store or network access.

## Friction demonstrated while implementing this consumer

1. Deserialization is not validation. Each nested type exposes its own selected
   `validate()` method; consumers must discover and call them. A public recursive
   `validate_message(profile, context)` returning structured findings could make
   coverage explicit and prevent forgetting client display, key or token checks.
2. Errors are excellent for local debugging but some embed URIs or values. A
   web service cannot safely return arbitrary `Display` text. Add stable error
   code, field path and redacted public guidance, separately from debug detail.
3. `KeyObject::validate()` verifies selected presentation constraints, not
   mathematical public-key/certificate validity or all private parameter cases.
   Expose validation scope clearly so UI authors cannot equate `Ok(())` with a
   usable and safely presented key.
4. Message shape alone does not check request/response cardinality, state,
   semantics of rights or elapsed time. An importable bounded trace format with
   explicit role, endpoint, exact bytes, observations and redaction would enable
   more useful black-box scenario tests without reconstructing SDK state.
5. SDK shared checks can reproduce SDK bugs. Keep these diagnostics labelled;
   grow independently authored wire-level assertions, published vectors, and a
   second implementation before claiming interoperability or certification.
6. HTTP framework, async integration, body limits and privacy-safe logging are
   integrator responsibilities today. A small official adapter recipe with the
   security boundaries spelled out would remove repeated implementation work.
7. The shared verifier in `gnap-crypto` can be used without constructing a full
   AS. The analyzer intentionally
   leaves proof checks `not_tested` until complete request context, trusted key,
   intended token and explicit clock/replay policies can be supplied safely.

## Discovery increment: independent assertions, shared reference data

The AS discovery profile now consumes imported documents and one bounded OPTIONS
response from an existing operator-approved AS target. It checks raw JSON/HTTP
and endpoint relationships without using the SDK's discovery deserializer or
validator. This avoids proving that a producer and the same validator agree.
It is still not a second GNAP implementation or a certification suite.

The GNAP registry enums are useful independently as reference data; duplicating
their known names would create a second maintenance problem. Subject Identifier
formats are in another IANA registry absent from `gnap-registry`, so this app
currently carries a small documented snapshot for those names only. Unknown
names require external registry review and remain unresolved rather than
becoming automatic normative failures.

Three useful distinctions emerged: absent optional capabilities versus invalid
types; a declared capability versus tested behavior; and a missing capture of
HTTP context versus a bad response. The import envelope now preserves those
distinctions. URL parsers can silently repair malformed inputs, so independent
assertions inspect raw URL characters first and compare the original endpoint
without normalizing it. Local HTTP discovery remains a labelled development
deviation, not a conformant result.
After explicit raw URI syntax prechecks, IPvFuture, numeric ports outside u16
and reg-name forms rejected by WHATWG parsing remain visibly unresolved, not
normative failures inferred from a library error. Passing those prechecks does
not establish all host UTF-8/IDNA or URI production semantics. Exact identity
can still be compared; malformed literals, percent triplets and nondigit ports
fail independently of library acceptance.
The safe import profile additionally rejects userinfo under the recipient
SHOULD in RFC 9110 section 4.2.4, with a policy-specific finding rather than an
invented GNAP MUST. Supplying non-null discovery context to another message
kind now produces an explicit error instead of silently discarding that context.

Tests cover the actual diagnostic routes, fixed outbound OPTIONS request shape,
bounded response adapter, redirects/authentication failures as response fixtures,
malformed documents and redacted reports. These fixture tests do not themselves
make a network round trip or exercise remote capability implementations.

A separate [manual network smoke](LIVE_SMOKE.md) on 2026-09-05 did exercise the
local workbench's real outbound HTTPS OPTIONS path to the deployed test AS:
8 checks passed, none failed, and 5 stayed explicitly untested. The shared
cooldown also rejected a different operation eleven seconds later. Reading the
actual report exposed a small usability issue: the key-rotation declaration
finding now states explicitly when the AS declares that feature unsupported.
This was rechecked over the real network after rebuilding, without changing
the assertions or claiming that any rotation was executed.

## Next increments, after this bounded prototype

Add a complete synthetic client/AS/RS scenario with consent, token binding,
rotation and revocation before adding an unauthenticated arbitrary-target probe.
For third-party self-service probes, add target ownership challenges, immutable
operation plans, distributed quotas, audit records without secrets, a reviewed
egress policy, and tightly scoped synthetic credentials. Authenticated RFC 9767
behavior now has a real HTTP consumer in the delegation demo, but the workbench
does not execute that authenticated scenario against imported targets.

## RFC 9767 imported-message increment

The workbench now independently checks selected JSON rules for RS-facing AS
discovery, introspection requests/responses and RS-facing errors. It reuses the
registry as reference data, not SDK validators as the oracle. Probes, consent
and target allowlists are unchanged. Synthetic fixtures test the diagnostics,
not live interoperability.

- RS-facing errors need their own registry and §3.5 response convention, not
  accidental reuse of core AS errors.
- The normative `iss` requirement must outrank the example that omits it.
  Conversely, examples must not create HTTP 200 or single-header requirements.
- Request `proof` is recommended and `access` optional. Context-free validators
  must not manufacture mandatory fields to simplify implementation.
- Bound/bearer rules need conditional assertions. Caller-declared `RsContext`
  permits comparisons but is not trusted state and cannot override a bearer/key
  contradiction. Outer key shape cannot prove a valid key or token binding.
- Unknown extensions and resource-type semantics remain untested; registry
  membership cannot establish full parameter processing or effective rights.
- Lossy JSON maps and URL normalization can hide ambiguity. Duplicate members
  and parser limitations remain inconclusive; identity compares original strings.

Next evidence requires real signed RS requests with the RS's own key, working
tokens and negative tests for revocation, audience and rights. An application's
`/resource-check` is not automatically RFC 9767 introspection. This increment
introduces no private-key upload or public credentialed probe.
