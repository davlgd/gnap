# GNAP web diagnostics (experimental)

A standalone application consuming the SDK as a real integrator. It analyzes
imported test messages and can send one fixed malformed initial grant request to
an operator-approved AS, an OPTIONS discovery request to that same AS endpoint,
or a credential-free GET to an operator-declared protected RS endpoint. It does
**not** certify AS, RS or client conformance.

## Run and test

Run from the repository root. Rust 1.98 is the tested toolchain for this app;
the SDK's MSRV is not a promise for this independently locked HTTP application.

```sh
cargo test --manifest-path apps/conformance-web/Cargo.toml --locked
node --test apps/conformance-web/tests/ui/panel_generation.test.mjs
cargo run --manifest-path apps/conformance-web/Cargo.toml --locked
```

The UI regression test uses Node.js (22 in CI), with no npm dependencies.
It exercises the real script with a small DOM test double, not a browser
rendering test. Clearing the report or changing message type prevents a late
response or error from restoring an obsolete result; it does not cancel a
request already sent to the server.

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

Core kinds: `grant_request`, `grant_response`, `continue_request`. The
`as_discovery` kind and the four RFC 9767 kinds, with their optional context,
are described below. Body is a string,
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

The three core message kinds reuse `gnap-types` deserialization and explicitly selected
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

### AS discovery diagnostics (RFC 9635 section 9)

The `as_discovery` kind checks a captured discovery response without fetching
anything, including its URLs. Load the synthetic discovery example in the UI,
or post `fixtures/as-discovery.json` to `/api/analyze`:

```json
{
  "kind": "as_discovery",
  "body": "{\"grant_request_endpoint\":\"https://test-as.example/gnap\",\"key_proofs_supported\":[\"httpsig\"],\"key_rotation_supported\":false}",
  "headers": [["Content-Type", "application/json"]],
  "queried_endpoint": "https://test-as.example/gnap",
  "http_status": 200
}
```

`queried_endpoint` (maximum 4096 UTF-8 bytes) and `http_status` (100..599)
are optional captured context. Without them, only their respective checks are
`not_tested`: malformed JSON or a missing required endpoint still fails.
Non-null discovery context fields supplied for another message kind are rejected
with an explicit envelope error, rather than silently ignored.
`headers` omitted means unobserved; `[]` means a captured response with no
headers. No digest/signature validation is performed for discovery imports.

The discovery profile checks:

- HTTP 200 as this OPTIONS diagnostic profile's success expectation, **not an
  explicit status-code MUST in RFC 9635 section 9**.
- One `application/json` Content-Type and a JSON object. Duplicate top-level
  members fail an explicitly labelled ambiguity profile (RFC 8259 recommends
  unique names); a last-wins interpretation is not used for dependent checks.
- A string `grant_request_endpoint`, HTTPS URL syntax, nonempty host, no
  fragment, and exact identity with the URL queried. Path/query/port are allowed
  in imported documents; URL normalization is not used for comparison. HTTP
  loopback fails even with the SDK's development-only response header.
  After explicit raw syntax prechecks, unsupported URL interpretations are
  `not_tested`: IPvFuture hosts, numeric ports outside u16, and other reg-name
  forms refused by the WHATWG URL parser (for example numeric-looking names).
  The raw grammar prechecks reject literal spaces, raw non-ASCII characters
  (IRIs are not accepted as URIs here), malformed percent triplets, invalid
  literal syntax and nondigit ports before consulting the parser. This is not
  a blanket rejection of percent-encoded UTF-8 or IDNA-encoded hostnames.
  This coverage limit is not full URI
  validation: for example, `%FF.example` matches the reg-name production but
  leaves the separate host UTF-8 production requirements unresolved. It is
  neither certified nor declared invalid merely because reqwest refuses it.
  Exact identity remains checked independently for these unusual URLs. See
  [RFC 3986 section 3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2)
  and [RFC 9110 section 4.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2).
- The safe discovery profile rejects userinfo, including `user@host`,
  `user:password@host` and `@host`. This adopts the recipient **SHOULD** to treat
  userinfo in an untrusted received URI as an error in
  [RFC 9110 section 4.2.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4).
  It is not an invented GNAP MUST or an assumption that a JSON member is an
  HTTP field value. The finding and remediation explicitly identify this policy.
- Optional capability arrays contain strings whose names occur in this build's
  registry data. Absent or empty arrays mean nothing is announced and are
  `not_tested`, not protocol failures. Unknown names are explicitly unresolved
  (`not_tested` with remediation), not silently accepted or definitively rejected
  as unregistered. Malformed arrays, including explicit null, fail.
- Optional `key_rotation_supported` is boolean. Omission means unsupported;
  a declaration of true is **not** proof that rotation works.

These HTTP/JSON/URL assertions are authored independently of the SDK's
`AsDiscovery::validate_for` and deserializer. They still use general JSON/URL
libraries and reuse **data** from `gnap-registry`, not a second GNAP registry
catalogue. Subject Identifier formats are not present in that crate; the eight
names in `src/discovery.rs` were checked against the official IANA registry on
2026-09-05. Review unknown names against the current
[GNAP registries](https://www.iana.org/assignments/gnap/) and
[Subject Identifier Formats](https://www.iana.org/assignments/secevent/#subject-identifier-formats).
Registry membership proves neither feature implementation nor authorization
for a particular client. Extra discovery fields are not validated. No live IANA
fetch occurs while analyzing a message.
This is not a complete HTTP/URI production audit. The live-target configuration
also forbids credentials and never constructs a network request from an
imported endpoint.

Discovery import reports use `gnap-as-discovery-diagnostics-v1` (the `Report`
envelope with `kind` and `independence`). Live OPTIONS reports use
`gnap-as-discovery-probe-v1` (the `ProbeReport` envelope with `target_id`, `role`,
`operation` and `limitations`). These distinct identifiers let consumers select
the correct response shape; both reuse the same discovery checks.
Executing declared
capabilities and a client discovery helper remain untested. RS discovery and
introspection under RFC 9767 are inspected only as imported message shapes in
the next section, never as authenticated behavior. Synthetic fixtures and
response-adapter tests are not evidence that a deployed AS or the complete
protocol has passed.

A separate [manual network smoke](LIVE_SMOKE.md) records the actual local
workbench → deployed HTTPS AS path, observed per-check results, shared cooldown,
reproduction commands and the remaining fixture-only limits. It is a dated
observation, not a source-revision attestation or certification receipt.

References: [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html),
[RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html).

## RFC 9767 imported-message diagnostics

These four kinds use direct `serde_json` assertions, **not SDK message validators**.
Only registry data comes from `gnap-registry`; the separately named, optional
digest check still uses `gnap-crypto`. No new network probe or private-key input
is included. No report certifies an AS, RS or client.

| Import kind | Report profile | Optional `rs_context` fields |
| --- | --- | --- |
| `rs_discovery` | `gnap-rs-discovery-import-v1` | `grant_request_endpoint`, `discovery_url` |
| `introspection_request` | `gnap-introspection-request-import-v1` | None |
| `introspection_response` | `gnap-introspection-response-import-v1` | `token_binding`: `bound` or `bearer` |
| `rs_error_response` | `gnap-rs-error-import-v1` | `http_status`: integer 100..599 |

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

Imported headers do not create an HTTP 200 or single-Content-Type rule from an
RFC example. Actual HTTP/media behavior remains untested, not certified valid.
URI userinfo, including an empty prefix before `@`, is rejected by the safe
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
They contain no usable tokens or private keys. For example:

```sh
curl --fail-with-body http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @apps/conformance-web/fixtures/introspection-active.json
```

Tests in `tests/rs_imports.rs` exercise the diagnostic oracle, not a deployed AS.
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

For discovery on a configured **AS** target, send:

```json
{"target_id":0,"consent":true,"operation":"as_discovery"}
```

This sends one OPTIONS request to the same exact configured grant endpoint,
with no body, authorization, cookies, proof or Origin header. An authentication
middleware denial, unsupported-method response or redirect is reported as a
failed discovery status check, not worked around using credentials or another
URL. The response passes through the same independent discovery assertions as
imports, with actual status/headers and the configured URL as context. Redirect
locations and all server response values are never echoed or followed.
`operation` omitted (or `"rejection"`) preserves the previous API behavior.
An RS target with `"as_discovery"` is rejected before DNS/network activity.

Set `GNAP_RS_TEST_TARGETS` to an additional JSON array of at most eight exact
protected resource URLs, with the same URL restrictions. A RS probe sends one
credential-free GET and checks for 401 or 403. This is an operator-defined
protected-resource policy test, not a claim that every GNAP resource must be
private. A deny-all server also passes. Valid-token access, proof, rights,
audience, introspection and lifecycle remain untested. `/api/targets` includes
the server-selected `role` (`as` or `rs`); public requests cannot change it.
AS rejection, AS discovery and RS rejection share the same process-global
cooldown and egress protections. Existing AS allowlist configuration therefore
authorizes both fixed AS operations; no new caller-controlled destination is added.

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
