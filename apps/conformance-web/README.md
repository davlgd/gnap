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

Kinds: `grant_request`, `grant_response`, `continue_request`. Body is a string,
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

The passive checks reuse `gnap-types` deserialization and explicitly selected
`validate()` methods, plus `gnap-crypto` Content-Digest verification:

- JSON shape and polymorphism; no repeated `client` in continuation requests.
- Selected key presentation, display URI, interaction finish, continuation URI,
  token, and subject-identifier consistency rules.
- Captured AS response `Cache-Control: no-store` and optional body digest.

These are **shared implementation checks, not an independent oracle**. There is
no claim of complete key validity, extension validation, stateful flow
correctness, signatures, replay detection, assertion authenticity, RS rights
enforcement, RFC 9767 introspection, or interoperability with another vendor.
Even an empty grant response can pass the JSON shape check; whether it is
appropriate in a particular exchange is outside an isolated message check.
Missing optional material is `not_tested`, never a vacuous pass.

References: [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html),
[RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html).

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
