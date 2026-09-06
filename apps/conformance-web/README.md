# GNAP web diagnostics (experimental)

A standalone application consuming the SDK as a real integrator. It analyzes
imported test messages and can send one fixed malformed initial grant request to
an operator-approved AS, or a credential-free GET to an operator-declared
protected RS endpoint. It does **not** certify AS, RS or client conformance.

## Run and test

Run from the repository root. Rust 1.98 is the tested toolchain for this app;
the SDK's MSRV is not a promise for this independently locked HTTP application.

```sh
cargo test --manifest-path apps/conformance-web/Cargo.toml --locked
cargo run --manifest-path apps/conformance-web/Cargo.toml --locked
```

Open `http://localhost:8080`. The process listens on `0.0.0.0:$PORT` (default
8080); `/health` returns `ok`. Do not expose a development instance without a TLS
terminating reverse proxy. Static assets are embedded in the executable.

```sh
curl --fail-with-body http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @apps/conformance-web/fixtures/invalid-continuation.json
```

The stable import envelope is:

```json
{
  "kind": "grant_response",
  "body": "{\"error\":\"invalid_request\"}",
  "headers": [["Content-Type", "application/json"], ["Cache-Control", "no-store"]],
  "content_digest": null
}
```

Core kinds: `grant_request`, `grant_response`, `continue_request`. The eight
RFC 9767 kinds and their optional context are described below. Body is a string,
not an object: digest checks need the original UTF-8 bytes, without JSON
reformatting. Omit `headers` when they were not captured; `[]` explicitly means
none were received. Duplicate header instances remain separate. The optional
`content_digest` is the exact combined field value to test against body bytes;
headers are not automatically interpreted as a signed request.

Reports contain stable per-check identifiers, `pass`/`fail`/`not_tested`, scope,
normative RFC links, remediation text, source (`import` or `live`), harness
version, optional `CC_COMMIT_ID` revision, and UTC Unix observation time. A
network failure is inconclusive and returns HTTP 502, not a conformance failure.
HTTP 200 from the analyzer means analysis completed, **not** that checks passed.
Downloadable reports contain neither the submitted body nor raw server replies.

## Tested scope and its limits

The core-message checks reuse `gnap-types` deserialization and explicitly selected
`validate()` methods, plus `gnap-crypto` Content-Digest verification:

- JSON shape and polymorphism; no repeated `client` in continuation requests.
- Selected key presentation, display URI, interaction finish, continuation URI,
  token, and subject-identifier consistency rules.
- Captured AS response `Cache-Control: no-store` and optional body digest.

These are **shared implementation checks, not an independent oracle**. There is
no claim of complete key validity, extension validation, stateful flow
correctness, signatures, replay detection, assertion authenticity, RS rights
enforcement, authenticated RFC 9767 introspection, or interoperability with another vendor.
Even an empty grant response can pass the JSON shape check; whether it is
appropriate in a particular exchange is outside an isolated message check.
Missing optional material is `not_tested`, never a vacuous pass.

References: [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html),
[RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html).

## RFC 9767 imported-message diagnostics

These eight kinds use direct `serde_json` assertions, **not SDK message validators**.
Only registry data comes from `gnap-registry`; the separately named, optional
digest check still uses `gnap-crypto`. No new network probe or private-key input
is included. No report certifies an AS, RS or client.

| Import kind | Report profile | Optional `rs_context` fields |
| --- | --- | --- |
| `rs_discovery` | `gnap-rs-discovery-import-v1` | `grant_request_endpoint`, `discovery_url` |
| `introspection_request` | `gnap-introspection-request-import-v1` | None |
| `introspection_response` | `gnap-introspection-response-import-v1` | `token_binding`: `bound` or `bearer` |
| `rs_error_response` | `gnap-rs-error-import-v1` | `http_status`: integer 100..599 |
| `resource_registration_request` | `gnap-resource-registration-request-import-v1` | None; even `{}` is rejected |
| `resource_registration_response` | `gnap-resource-registration-response-import-v1` | None; even `{}` is rejected |
| `derivation_request` | `gnap-derivation-request-import-v1` | None; even `{}` is rejected |
| `derivation_response` | `gnap-derivation-response-import-v1` | None; even `{}` is rejected |

`rs_context` is a caller-declared comparison, never evidence of network behavior,
issuer trust or token properties. Inapplicable fields reject the import instead
of being silently ignored. URL strings are limited to 4096 UTF-8 bytes and never
fetched. Omission leaves unobservable conditions `not_tested`; it does not hide
malformed JSON or message contradictions. The UI exposes a separate optional
context section. Rust consumers can name exported `RsContext` and `TokenBinding`.

- **AS discovery for RSs**, [§3.1](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.1):
  required grant endpoint, selected HTTPS/host/no-fragment URL checks, exact
  comparison to a declared client grant endpoint, and declared well-known
  location `/.well-known/gnap-as-rs` on the same scheme/authority. This is not
  metadata about an RS itself. The introspection endpoint is required when the
  AS supports introspection; its absence indicates that introspection is not
  supported. The equivalent rule applies to dynamic resource registration.
  Import does not verify that announced services actually behave as advertised.
  Optional capability arrays may be absent. Known registry names do not prove
  support; unknown names need external registry review and are `not_tested`.
- **Introspection request**, [§§3.2–3.3](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.2):
  required token string and RS identity outer shape, optional access shape and
  recommended `proof` name. Missing `proof` is not a missing-MUST failure;
  missing `access` is allowed. No signature or equality to the original client
  token presentation is verified. Unknown extensions/rights semantics remain
  `not_tested`: a real AS unable to process a supplied request parameter must
  not declare the token active.
- **Introspection response**, [§3.3](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.3):
  required boolean `active`; inactive responses omit every other member. Active
  responses require `access` (an empty array is valid) and `iss`, despite the
  example omitting it. Token `value` is forbidden. Bound tokens require `key`,
  bearer tokens forbid it. The condition is `not_tested` when it cannot be
  determined from a bearer flag or caller context. Bearer plus key always fails,
  regardless of context. Keys are checked only for object/reference shape;
  optional metadata only for selected types, not validity of their claims.
- **RS-facing error**, [§3.5](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.5):
  a single `error` member, string code or object/ASCII code with optional string
  description, the distinct RS error registry, and HTTP 400 compared only when
  declared in context. These are not core AS errors.
- **Resource registration request**, [§3.4](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.4):
  required `access` array and `resource_server` reference or object containing
  `key`. Empty access is not prohibited by this diagnostic. Objects in `access`
  require string `type` under RFC 9635 §8, despite the registration example
  omitting it. Selected standard dimensions are checked, not resource-specific
  semantics, reference resolution or key validity. Optional
  `token_formats_supported` must be a string array of registered token formats;
  unknown values are `not_tested` pending external registry review. An empty
  list can pass the array check but never proves an AS/RS format intersection.
  Omission leaves the format to the AS. `token_introspection_required` is an
  optional boolean, not evidence that the AS offers introspection for this RS.
- **Resource registration response**, [§3.4](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.4):
  required string `resource_reference`, not an access token. No nonempty, ASCII
  or SDK token-value restriction is imposed. Optional `instance_id` and
  `introspection_endpoint` are checked as strings only. Passing these checks
  proves neither that a reference resolves nor that the endpoint is usable.
  Its URI syntax, transport and ownership are outside this response diagnostic;
  the discovery-specific URI checks below are not applied to this field.

Both registration profiles always report `registration-format-compatibility`,
`registration-introspection-support` and `registration-authentication-and-state`
as `not_tested`. A real AS must return an error when it supports none of the
requested token formats or, when the RS requires introspection, does not support
introspection for that RS.
These behaviors and the RS's mandatory identification/signature need an actual
authenticated exchange. Neither imported request nor response proves them.
Extensions are not forbidden, but their registration and semantics remain
untested. No comparison context is accepted for registration imports.

### Downstream derivation imports

[RFC 9767 §4](https://www.rfc-editor.org/rfc/rfc9767.html#section-4) reuses the
GNAP client grant endpoint and grant-message structures: RS1 acts as a client
with **its own key**, not the incoming token's key or the original client's key.
The AS must determine that the presented token is appropriate for use at RS1.
Neither condition can be inferred from an imported `client` or token string.

- `derivation_request` selects a **request for a derived access token**, not all
  possible GNAP grant requests. It requires string `existing_access_token`,
  `client` as a reference or object with key, and `access_token` as an object or
  array under [RFC 9635 §2.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1).
  Each token object requires GNAP `access`; arrays require unique string labels.
  A singleton label is optional. Supplied flags are string arrays without
  repetitions. Unknown flags are not forbidden, but their semantics remain
  untested. Optional `subject`/`interact` objects and `user` object/reference
  receive outer-type checks only. Interaction is not prohibited by the example
  diagram, and this import is not limited to opaque tokens or one downstream hop.
- `derivation_response` checks selected fields of the ordinary grant response,
  not a special RS-facing error format. If `access_token` appears, each object
  requires string `value` and GNAP `access` under
  [RFC 9635 §3.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2).
  A multiple-token response requires unique string labels. Label correspondence
  to the request and object/array agreement are not tested from a response alone.
  Supplied flags cannot repeat; `bearer` plus any `key` member fails. Otherwise
  key is checked only as object/reference. Optional `expires_in` and `manage`
  receive integer/object checks only, not deadline or nested management checks.
  Top-level `continue`, `interact`, `subject`, `instance_id` and `error` also
  receive outer-type checks only, not validation of their contents or combinations.

The response's `derivation-response-value` assertion deliberately checks **string
shape only**: even a string outside token68 can pass that assertion, while
`derivation-token-value-encoding` remains `not_tested`. This is not an acceptance
of that value under the RFC. Parent-token string checks likewise establish no
format, authenticity or validity. Empty rights arrays are not forbidden. Empty
token arrays have an array shape but supply no token to validate; per-token
checks are `not_tested`, not vacuous passes. A response containing only
continuation, interaction, error, or no members never establishes token issuance.

The following checks always remain `not_tested` on both profiles:

- `derivation-proof-and-parent-validity`: key ownership, signature/replay and
  parent validity/equality to the original presentation.
- `derivation-parent-rs-suitability`: the AS's mandatory RS1 suitability decision.
- `derivation-effective-rights-and-audience`: actual authority, consent and
  downstream audience. No universal subset policy is inferred from a demo.
- `derivation-revocation-and-lineage`: parent-child relationships and later
  expiry/revocation. Cascading revocation is not imposed as a blanket §4 rule.
- `derivation-grant-exchange`: state, matching, interaction, continuation, errors,
  nested keys/management, token formats and extension semantics.
- `derivation-token-value-encoding`: token68 and token content validation.

Additional members, including an unrecognized `type_token`, are not prohibited
or interpreted as format negotiation. No comparison context, private-key input,
new HTTP assertion or network probe is added. Imported headers do not authenticate
these messages. Existing size, duplicate-name and parser limits apply unchanged.

Synthetic fixtures: `fixtures/derivation-request.json`,
`fixtures/derivation-response.json`, `fixtures/invalid-derivation-request.json`
and `fixtures/invalid-derivation-response.json`. Their names and tokens are test
data, not captures of an authenticated downstream exchange. The offline table
tests in `tests/derivation_imports.rs` include multi-token, interaction-only,
continuation-only and error-only responses, malformed fields and ambiguity.

### Shared import limits

Imported headers do not create an HTTP 200 or single-Content-Type rule from an
RFC example. Actual HTTP/media behavior remains untested, not certified valid.
In the discovery and active-issuer URI checks, userinfo, including an empty
prefix before `@`, is rejected by the safe
recipient diagnostic profile under RFC 9110 §4.2.4's SHOULD. The finding names
that policy and source explicitly; it is not an additional GNAP MUST.
Duplicate JSON members at any depth make field interpretation inconclusive,
not last-wins or a newly invented GNAP MUST. Number-range/depth limits are also
`not_tested`. URL prechecks reject proven violations such as missing HTTPS/host,
fragments, spaces, non-ASCII IRI characters and malformed percent escapes.
Unsupported URL-library cases (IPvFuture, large numeric ports, some numeric or
percent-encoded hostnames) are inconclusive. Userinfo receives the explicitly
labelled recipient-profile failure described above, not a GNAP MUST failure.
These are selected checks, not a complete URI/HTTP audit.

Synthetic upload fixtures: `rs-discovery.json`, `introspection-request.json`,
`introspection-active.json`, `introspection-inactive.json`, `rs-error-response.json`,
and deliberately failing `invalid-introspection-active.json`, all under `fixtures/`.
Resource registration adds `resource-registration-request.json` and
`resource-registration-response.json`, plus deliberately failing
`invalid-resource-registration-request.json` and
`invalid-resource-registration-response.json` in the same directory.
They contain no usable tokens or private keys. For example:

```sh
curl --fail-with-body http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @apps/conformance-web/fixtures/introspection-active.json
```

Tests in `tests/rs_imports.rs`, `tests/resource_registration_imports.rs` and
`tests/derivation_imports.rs`
exercise the diagnostic oracle, not a deployed AS.
Report time is analysis time, not capture time. State, revocation, effective
rights, trust, RS authorization and actual publication remain `not_tested`;
every report has `certification: false`.

## Bounded live AS/RS probes

The **operator** may set `GNAP_TEST_TARGETS` to a JSON array of at most eight
canonical, exact HTTPS grant endpoint URLs. Default: `[]` (disabled).

```sh
GNAP_TEST_TARGETS='["https://your-owned-test-as.example/gnap"]' \
  cargo run --manifest-path apps/conformance-web/Cargo.toml --locked
```

Setting this configuration is the operator's attestation that they own or have
permission to test these endpoints. There is no automated third-party ownership
verification. Do not configure production endpoints. Public users choose an
index returned by `GET /api/targets` and explicitly consent:

```json
{"target_id":0,"consent":true}
```

Send that JSON to `POST /api/probe`. Exactly one request is sent: `POST` to the
configured grant endpoint, with `Content-Type: application/json`, body `{`, and
no credentials. The report checks a JSON GNAP error without success fields,
error-code membership in its registry snapshot, and `no-store`. A separate
**deployment-policy** check prefers HTTP 4xx; RFC 9635 does not prescribe that
status class. HTTP 200 with a GNAP error is not by itself a GNAP conformance
failure. These probes do not prove successful authentication.

Set `GNAP_RS_TEST_TARGETS` to an additional JSON array of at most eight exact
protected resource URLs, with the same URL restrictions. A RS probe sends one
credential-free GET and checks for 401 or 403. This is an operator-defined
protected-resource policy test, not a claim that every GNAP resource must be
private. A deny-all server also passes. Valid-token access, proof, rights,
audience, introspection and lifecycle remain untested. `/api/targets` includes
the server-selected `role` (`as` or `rs`); public requests cannot change it.
AS and RS share the same process-global cooldown and egress protections.

Safety boundaries: no caller URL, no suffix/wildcard allowlist, no query,
credentials, non-443 port or IP literal; resolve once, reject any private,
metadata, special-use or transition address, or more than 16 addresses, then pin the approved DNS results
for the request. Redirects and environment proxies are disabled. Normal TLS
hostname/certificate validation remains enabled. A conservative public IP policy
may reject legitimate special-purpose addresses. 4-second total probe deadline,
3-second HTTP timeout, 2-second connect timeout, 32 KiB response limit, no
decompression features, one probe per 60 seconds globally **per process**.
Multiple instances need a shared quota before enabling this endpoint at scale.

## Deployment on Clever Cloud

Deploy from the repository root, because dependencies use `../../crates/*`.
Build this application's manifest, not the library workspace alone:

```sh
cargo build --release --locked --manifest-path apps/conformance-web/Cargo.toml
```

Executable: `apps/conformance-web/target/release/gnap-conformance-web`.
Use a Rust-compatible build/runtime image with trusted CA roots and DNS. Set the
build instance to **M**, runtime `PORT` as supplied by the platform, and the
exact operator-owned test endpoint in `GNAP_TEST_TARGETS` and/or
`GNAP_RS_TEST_TARGETS` if probes are wanted.
For a linked Clever Cloud application, set `APP_FOLDER=apps/conformance-web`,
`CC_RUST_BIN=gnap-conformance-web` and `CC_HEALTH_CHECK_PATH=/health`.
No provider-specific app identifiers or credentials are stored in this folder.

## Security and privacy limits

Only synthetic test data. Imports reach the application server; this is not an
offline browser validator. The application has no database, request/body logging,
analytics, storage API, or persistence. Hosting access logs, platform backups,
crash dumps and browser form retention are outside this guarantee. Reports avoid
raw parser error strings because SDK errors can include submitted secrets.

Limits: 64 KiB upload, 32 KiB body string, 64 header pairs, 128-byte header names,
4096-byte header values/digest, no CR/LF in imported headers, 16 in-flight
application requests, 5-second application deadline. Parsing is bounded
synchronous CPU work; there is no detached blocking job surviving cancellation.
Axum/Hyper parse HTTP. Reverse-proxy header/connection/body deadlines and
rate limiting are still required against distributed flooding and slow headers;
the app does not claim general DoS immunity.

UI uses `textContent`, no imported HTML, no externally hosted assets, restrictive
CSP, `no-store` and no credentialed fetches. Do not paste live tokens or private
keys even though reports do not reflect their values. The clear button clears
the visible fields/report, not forensic browser or hosting history.
