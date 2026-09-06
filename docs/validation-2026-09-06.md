# Hosted application validation — 6 September 2026

The [delegation demo](https://gnap-delegation.cleverapps.io) and
[diagnostic workbench](https://gnap-conformance.cleverapps.io) were updated to
[`f8821d0`](https://github.com/davlgd/gnap/commit/f8821d0383561caaa41b88eb10b000c35d602701)
after the reviewed feature branches were merged. This records observations of
that revision, not a claim about every later deployment or full GNAP conformance.

## Deployment and provenance

Clever Cloud reported both applications running that commit, each with a
dedicated **M build instance** and exactly one **XS runtime instance**. Their
existing domains, configured origin and probe allowlists were retained. No new
key material or environment setting was needed. Restarting replaced volatile
sessions, keys, grants and registration state; old demo sessions do not migrate.

The demo's `/health` reported `bootstrap: "ready"`. The workbench's `/health`
returned `ok`. Neither endpoint reports a source revision. A synthetic import
report from the workbench declared the full commit above at UTC Unix
`1788712291`; its live discovery report declared the same revision at
`1788712405`. This is application-reported provenance checked against provider
state, not a cryptographic attestation of remote code.

## Checks actually run

| Execution | Observation |
| --- | --- |
| Existing HTTPS acceptance script at `f8821d0` | 107 observations passed across the demo, its previous hostname alias and the workbench. No failed checks. |
| Added code-consent scenario | Two additional HTTPS flows passed separately: owner allows and client reads; owner denies and client has no usable token. |
| Workbench → hosted AS discovery probe | Nine checks passed, four remained `not_tested`, no failures. Capability execution remained untested by this probe. |
| New captured discovery response | One credential-free OPTIONS response was collected at UTC Unix `1788712167`; six independent assertions passed in an offline replay. |

The existing acceptance script exercises approval and denial, protected reads
through authenticated introspection, token retirement, ongoing-grant changes,
resource registration, downstream metadata access, labelled multi-resource
tokens, alias handling and imported-message diagnostics. Its observations are
application checks, not a count of completed RFC obligations.

The additional scenario in [`tools/smoke_ecosystem.py`](../tools/smoke_ecosystem.py)
uses two independent HTTP cookie stores. It checks the owner's scoped
HttpOnly/SameSite cookie and Secure flag on HTTPS, rejects consent from the
initiating client, checks the displayed rights and rotated form ticket, polls
while a decision is pending, then observes that decision at the original client.
The allowed grant is revoked after its successful read. No code, cookie, ticket
or token is printed. These are real HTTPS exchanges, not a browser-engine test,
a physical-device test or authentication of a real resource owner.

The updated script includes both code flows in its normal `--demo` run:

```sh
python3 -B tools/smoke_ecosystem.py \
  --demo https://gnap-delegation.cleverapps.io \
  --workbench https://gnap-conformance.cleverapps.io
```

Only run this against deployments you control or are authorized to test. The
script creates synthetic sessions and consumes the normal application budgets.
Repeated or concurrent runs can receive 429 responses; exhausting the 64 owner
sessions before their ten-minute expiry can return 503. The script does not
bypass these limits or reinterpret a refused run as a pass.

## Discovery evidence

The [new capture](../conformance/captures/gnap-delegation-discovery-2026-09-06.json)
contains only the public endpoint, the three announced interaction starts
(`redirect`, `user_code`, `user_code_uri`), `httpsig` and
`key_rotation_supported: false`. The demo does not enable bound-key rotation.
The 214-byte response has SHA-256
`40d32b027555b726d87489b785ab738a6be1cad6848012347fc1cff2e9c6fb36`.

The [replay receipt](../conformance/receipts/gnap-delegation-discovery-2026-09-06.json)
was generated from clean commit
[`18987d2`](https://github.com/davlgd/gnap/commit/18987d2dcecb5695b8f947cae5b4aca4c24f0896).
Its six named cases are the active mappings for the same two section 9 source
blocks. The earlier captures and receipts remain available. A replay of captured
bytes is historical evidence; it does not execute announced capabilities or
attest the AS revision. The receipt therefore retains `remote_revision: "unknown"`.

## Boundaries

These two applications still use synthetic identities and volatile state. The
demo's AS and RS roles remain co-located, even where they communicate over HTTP.
This run did not deploy the separate Biscuit services, exercise hosted bound-key
rotation or push delivery, verify browser rendering, or establish C1/C2 profile
completion, independent-vendor interoperability or production readiness.
