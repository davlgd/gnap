# An authenticated scenario driven by the workbench

The web workbench can act as a GNAP client with its own signing key. Its
operator selects an AS/RS pair; the resource owner explicitly approves or
denies a synthetic read on the AS's page. After approval, the workbench checks
access, replay, key binding, rotation and revocation over actual HTTP exchanges.

This is a bounded reference application scenario, not a GNAP certification
service. The reference workbench and AS run as separate processes operated by
the same party and do not share a private key or grant store. The delegation
demo's opaque-token AS and RS remain
co-located; the resource handler calls authenticated introspection with its own
RS key. This example does not yet provide three separately hosted roles.

## Explicit public-key approval

The feature is disabled unless `GNAP_LIFECYCLE_TARGETS` is configured on the
workbench. Set its canonical `GNAP_WORKBENCH_ORIGIN` and an array of at most
four operator-approved pairs:

```json
[
  {
    "name": "Synthetic document service",
    "grant": "https://as.example/gnap",
    "continuation": "https://as.example/continue",
    "interaction": "https://as.example/interact/",
    "management": "https://as.example/token/",
    "resource": "https://rs.example/resource/folder"
  }
]
```

These are configuration examples, not endpoints the service will discover or
approve automatically. The prefixes end with `/` and admit only a single
bounded alphanumeric/base64url segment. The resource representation expected
by the scenario is the demo's synthetic document result. Other application
representations need an explicitly designed test profile, not an arbitrary URL
in a public form. HTTPS targets use canonical DNS hostnames on port 443.

At process startup, the workbench generates a 2048-bit PS256 key. Its public
JWK and thumbprint are available at `/api/lifecycle/key`, together with the
exact callback URI. This is a local application endpoint, not a standardized
GNAP discovery document. No private-key member is returned.

An operator can obtain the demo's registration configuration with:

```sh
python3 -B tools/smoke_lifecycle.py \
  --workbench https://workbench.example --registration-only
```

Set that public JSON array as `GNAP_EXTERNAL_CLIENTS` on the demo, then restart
it. The AS accepts at most eight explicitly configured public keys, each bound
to one exact callback. It checks the actual RSA key material and PS256 metadata,
not just a matching `kid`. It never fetches a key from the workbench or follows
a key URL supplied in a request. A malformed opt-in configuration prevents
startup; its error does not echo configuration contents.

The workbench's private key exists only in process memory. **Restarting the
workbench changes its key and requires public-key reapproval on the AS.** Until
then, requests fail closed. There is no automatic trust update, persistence or
production restart-recovery claim. Existing AS client references retain their
own verification path; presenting an approved external key does not grant one
of those identities.

## What the owner approves

Open `/lifecycle` on the workbench, choose the configured pair and explicitly
authorize the complete test. Follow the link to the AS. Its independent owner
page displays a constant synthetic-client description and the requested read
right; it does not render client-supplied HTML or approve anything on a GET.
Approval or denial requires the owner's separate cookie and one-use form
ticket. Completion is bound to the stored grant and its interaction state.

The external-client profile requests one `synthetic-folder:read` token, with a
300-second lifetime and an implicit binding to the requesting key. Only a
redirect start and redirect finish to the approved callback are accepted.
Identity assertions, multiple tokens, push, user codes, downstream derivation,
extra rights and ongoing modifications are outside this scenario. The grant
closes after the decision; individual token rotation and revocation remain
available. The Documents RS accepts exactly the external 300-second and internal
1,200-second profiles; Reports and Metadata retain their existing policies.

The owner page has an additional 300-second local consent deadline. The SDK's
advertised interaction window is not rewritten: this application may refuse an
interaction earlier under its local policy. Reopening an owner page does not
extend the grant's local deadline.

## Checks and evidence boundaries

The workbench uses `gnap-client` to sign requests, retain grant state and verify
the finish callback. Those are shared SDK behaviors. Separately written
HTTP/JSON assertions inspect actual received bytes, headers and lifecycle
results; they do not call the SDK message validators.

After approval the scenario performs:

1. A successful signed read of the synthetic document resource.
2. Rejection of the identical signed request, with the same nonce and timestamp.
3. Rejection of a request signed by a different key with the same `kid`.
4. Another successful read using the live token and a fresh signature.
5. Token-value rotation, rejection of the old value with a fresh signature,
   and a successful read with the replacement.
6. Token revocation and rejection of the retired value with a fresh signature.

A deny-all service therefore fails the positive controls. A denied consent
instead checks `user_denied` without a token; it does not pretend to have tested
the token lifecycle. A completed scenario may contain failed checks. Network
failures, deadline expiry and unsupported responses are inconclusive, without
erasing failures already observed. No count is a count of completed RFC duties.

Reports contain static check identifiers and explanations, their pass/fail or
untested state, target identifier, observation time and harness provenance.
They exclude tokens, proofs, raw response bodies, owner tickets and callback
references. The pending interaction link is separate from the downloadable
report. Hosting infrastructure and browser history are outside the application's
no-request-body-logging promise.

## Admission and network limits

Each start consumes the same 60-second process-wide cooldown as the existing
unsigned live probes. The workbench admits four active workers and retains at
most eight reports. Work and callbacks expire after five minutes; report cookies
are HttpOnly/SameSite=Lax, Secure on HTTPS, and expire after ten minutes.
Lax permits the expected top-level return from the AS. A callback without the
initiating client's session cannot advance another session.

Each worker has a 16-request budget, including best-effort cleanup. Requests
are restricted to configured methods and exact destinations or bounded management
segments. Redirects, proxies and automatic retries are disabled. Every HTTPS
resolution is checked: at most 16 addresses, all public, pinned for the request
while preserving TLS hostname verification. DNS, connection and body reads have
a shared four-second deadline; response bodies are limited to 8 KiB. Explicit
HTTP loopback configuration is a development-only deviation, never a TLS exception
enabled by a public request. Grant inspection by GET is not exercised.
Continuation respects the AS's wait from receipt of its response, with five
seconds when omitted. Waits above 30 seconds are outside this scenario's profile.

The demo separately bounds external grant capacity, per-key capacity and owner
sessions. Capacity refusal can return HTTP 503; it is not necessarily an outage.
Local limits do not constitute distributed abuse protection. Closing the browser
does not cancel work already authorized, and an outage may prevent cleanup;
short-lived synthetic grants limit that residual state.

For an operator-authorized deployment, the acceptance driver exercises the real
application pair. It simulates the resource owner's explicit form submission
using a separate cookie jar; the workbench itself never submits that form:

```sh
python3 -B tools/smoke_lifecycle.py \
  --demo https://as.example --workbench https://workbench.example --choice allow
```

Use `--choice deny` for the denial path, respecting the shared cooldown. Local,
CI and hosted observations must be reported separately. These checks do not
verify authenticated introspection directly, restart recovery, arbitrary rights,
Biscuit, an independent vendor, browser rendering or complete C1/C2 conformance.
