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
discovery, introspection requests/responses, resource registration
requests/responses and RS-facing errors. It reuses the
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

## Resource registration import feedback

- A `resource_reference` is an access-rights reference, not an access token.
  Reusing token-value validation here would introduce unrelated restrictions.
- Registration delegates access syntax to RFC 9635 §8. Its REQUIRED object
  `type` takes precedence over the incomplete §3.4 example. An empty access
  array must not be rejected merely because a particular AS policy needs rights.
- Token format registry membership and AS/RS compatibility are different
  questions. A current known format or an empty list cannot attest an
  intersection; unknown names need registry review rather than permanent rejection.
  In particular, the SDK's opaque-token deployment policy does not make
  `opaque` an IANA format name: it is absent from this vendored registry.
  The synthetic positive registry fixture uses the registered name `biscuit`;
  it does not claim that any server supports Biscuit registration.
- `token_introspection_required` needs per-RS authorization and actual AS
  capabilities to exercise the required error behavior. An imported boolean
  or endpoint string cannot supply that evidence. No declared context is added
  to these imports as a substitute for an authenticated exchange.
- The response endpoint receives a string-type check only, not discovery's URI
  profile. The report explicitly leaves URI syntax, transport and actual service
  behavior untested. Additional members remain extensions to review, not errors
  introduced by a closed SDK shape.

The new synthetic fixtures exercise these distinctions, nested duplicate-name
ambiguity, parser limits and redacted HTTP reports. They do not attest a running
registration endpoint, RS key ownership or reference persistence. Network probes
and their consent/allowlist policy are unchanged.
