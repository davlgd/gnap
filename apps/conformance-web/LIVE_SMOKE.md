# Manual AS discovery network smoke — 2026-09-05

This is a recorded manual observation, not an automated conformance receipt,
certification, or proof of the deployed server's source revision.

## Actual path exercised

Local HTTP caller → locally running workbench → HTTPS OPTIONS to
`https://gnap-delegation.cleverapps.io/gnap` → discovery report.

The target was the **only** configured endpoint (`target_id: 0`, role `as`).
The workbench performed its normal public-DNS address checks, pinned resolution,
certificate/hostname validation, no-proxy transport and redirect refusal. The
local caller did not fetch the target in place of the workbench. No test-only
transport override, credential, or relaxation of the target allowlist was used.
Local HTTP for the diagnostic UI does not make an HTTP AS discovery endpoint
conformant: the endpoint actually tested was HTTPS.

The first observation at **20:01:53 UTC** completed with HTTP 200 from the
analyzer and report provenance `source: live`, harness `0.1.0`, revision
`unknown`, Unix timestamp `1788638513`. The revision remained unknown because
the workbench was running uncommitted implementation work, not a claimed
published build.

Profile migration after this capture: current live OPTIONS reports identify
their `ProbeReport` envelope as `gnap-as-discovery-probe-v1`. The historical
capture preceded this distinction and used `gnap-as-discovery-diagnostics-v1`,
which is now reserved for import reports. This identifier correction does not
change the checks or retroactively constitute a new network observation.

Result: **8 pass, 0 fail, 5 not_tested**, with `certification: false`:

| Checks | Result | Interpretation |
|---|---|---|
| HTTP status, media type, JSON object, unique top-level members | Pass | Expected successful OPTIONS response; HTTP 200 and unique members include explicitly labelled diagnostic-profile rules. |
| HTTPS endpoint syntax and exact queried-URL identity | Pass | The announced URL matches the actual configured HTTPS target. |
| `key_proofs_supported` | Pass | Announced `httpsig` occurs in registry data; its execution was not tested. |
| `discovery-key-rotation-type` | Pass | Boolean `false` declares key rotation unsupported; this is not a successful rotation test. |
| Four other optional capability lists | Not tested | Start modes, finish methods, subject identifier formats and assertion formats were not announced. This is not a missing-required-field failure. |
| Capability behavior | Not tested | No authenticated grant, proof, rotation, client helper, RS discovery or RFC 9767 scenario was executed. |

A different operation (`rejection`) submitted at **20:02:04 UTC**, eleven
seconds later, returned HTTP **429** and the shared cooldown explanation.
This exercised the real route and shared per-process limit, not just a fixture.

A separate direct HTTPS OPTIONS observation at **20:02:05 UTC** confirmed
HTTP 200, `Content-Type: application/json`, `Cache-Control: no-store`,
`Allow: POST, OPTIONS`, and this 137-byte body:

```json
{"grant_request_endpoint":"https://gnap-delegation.cleverapps.io/gnap","key_proofs_supported":["httpsig"],"key_rotation_supported":false}
```

The direct call was supplementary inspection, not substituted evidence for the
workbench network path. Response headers do not attest a git commit, and none
was inferred from them.

## Small correction discovered through use

The original rotation-type finding was correct but explained only the general
meaning of a true declaration, even when this AS sent false. It now explicitly
states that the AS declares key rotation unsupported, while preserving the
distinction between checking a boolean declaration and executing rotation.
A regression assertion covers that wording.

After rebuilding and restarting the local workbench, the real network probe
was repeated at **20:04:45 UTC** (`1788638685`): again **8 pass, 0 fail,
5 not_tested**. The actual network report contained the corrected unsupported
declaration.

## Reproduce

From the repository root, start the workbench in one terminal:

```sh
PORT=38187 \
GNAP_TEST_TARGETS='["https://gnap-delegation.cleverapps.io/gnap"]' \
GNAP_RS_TEST_TARGETS='[]' \
cargo run --manifest-path apps/conformance-web/Cargo.toml --locked
```

The binary binds `0.0.0.0`; keep this temporary development instance off public
networks and stop it with Ctrl-C when finished. The remote AS must remain a
target the operator is authorized to test. In another terminal:

```sh
curl --fail-with-body --max-time 10 --noproxy '*' http://127.0.0.1:38187/health
curl --fail-with-body --max-time 10 --noproxy '*' http://127.0.0.1:38187/api/targets
curl --fail-with-body --max-time 10 --noproxy '*' \
  http://127.0.0.1:38187/api/probe \
  -H 'Content-Type: application/json' \
  --data-binary '{"target_id":0,"consent":true,"operation":"as_discovery"}'
```

Inspect the report, not only HTTP 200 from the analyzer. To observe the shared
cooldown, immediately submit the same envelope with `operation: rejection`;
expect HTTP 429, with no second outbound probe. Allow at least 60 seconds between
successful probes. Limits are per process, not distributed.

## What remains fixtures or untested

- Redirects, authentication refusals, malformed documents, invalid URLs and
  oversized responses are covered by deterministic response/route fixtures;
  this public AS network smoke did not produce those negative remote responses.
- A successful live request is evidence that this particular DNS/TLS/network
  path worked. It does not independently audit every SSRF boundary, TLS setting,
  redirect destination or cancellation interleaving.
- IPvFuture, numeric ports outside u16 and other unsupported URL interpretations
  (including reg-name forms refused by WHATWG parsing) remain explicitly
  unresolved imports after raw syntax prechecks; exact identity is checked
  separately. They cannot be added to the stricter live-target configuration.
- Registry membership is not proof that capabilities work. Optional absence,
  unresolved names and unexecuted behavior must not be combined into a global
  conformance percentage.
- The observations can change as either endpoint is updated. No server source
  revision, other vendor's implementation, full protocol or RS was attested.
