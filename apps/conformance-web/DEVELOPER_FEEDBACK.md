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
egress policy, and tightly scoped synthetic credentials. RFC 9767 coverage must
wait for an actual RS/introspection scenario, not just a UI checkbox.
