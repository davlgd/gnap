# Authenticated workbench scenario

The web workbench can act as a GNAP client with its own signing key. Its operator selects an AS/RS pair; the resource owner explicitly approves or denies a synthetic read on the AS's page. After approval, the workbench checks access, replay, key binding, rotation and revocation over actual HTTP exchanges.

It's a bounded scenario, not a GNAP certification service. The workbench and the authorization server run as separate processes, operated by the same party, without sharing a private key or a grant store. The delegation lab keeps its authorization and resource servers in one process, where the resource handler calls authenticated introspection with its own key: the scenario has no three separately hosted roles.

## Approve the workbench's public key

The feature is disabled unless `GNAP_LIFECYCLE_TARGETS` is configured on the workbench. Set its canonical `GNAP_WORKBENCH_ORIGIN` and an array of at most four operator-approved pairs:

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

These are configuration examples, not endpoints the service will discover or approve automatically. The prefixes end with `/` and admit only a single bounded alphanumeric/base64url segment. The scenario expects the synthetic document result of the delegation lab. Other application representations need an explicitly designed test profile, not an arbitrary URL in a public form. HTTPS targets use canonical DNS hostnames on port 443.

At process startup, the workbench generates a 2048-bit PS256 key. Its public JWK and thumbprint are available at `/api/lifecycle/key`, together with the exact callback URI. This is a local endpoint, not a GNAP discovery document, and it returns no private-key member.

An operator gets the lab's registration configuration with:

```bash
python3 -B tools/smoke_lifecycle.py \
  --workbench https://workbench.example --registration-only
```

Set that public JSON array as `GNAP_EXTERNAL_CLIENTS` on the lab, then restart it. The AS accepts at most eight explicitly configured public keys, each bound to one exact callback. It checks the actual RSA key material and PS256 metadata, not just a matching `kid`. It never fetches a key from the workbench or follows a key URL supplied in a request. A malformed opt-in configuration prevents startup; its error doesn't echo configuration contents.

The workbench's private key exists only in process memory. **Restarting the workbench changes its key and requires public-key reapproval on the AS.** Until then, requests fail closed. Trust isn't updated automatically, and nothing persists across a restart. The server's own client references keep their verification path, and an approved external key doesn't grant one of those identities.

## What the owner approves

Open `/lifecycle` on the workbench, choose the configured pair and explicitly authorize the complete test. Follow the link to the AS. Its independent owner page displays a constant synthetic-client description and the requested read right; it doesn't render client-supplied HTML or approve anything on a GET. Approval or denial requires the owner's separate cookie and one-use form ticket. Completion is bound to the stored grant and its interaction state.

The external-client profile requests one `synthetic-folder:read` token, with a 300-second lifetime and an implicit binding to the requesting key. Only a redirect start and redirect finish to the approved callback are accepted. Identity assertions, multiple tokens, push, user codes, downstream derivation, extra rights and ongoing modifications are outside this scenario. The grant closes after the decision; individual token rotation and revocation remain available. The Documents RS accepts exactly the external 300-second and internal 1,200-second profiles; Reports and Metadata retain their existing policies.

The owner page has an additional 300-second local consent deadline. The SDK's advertised interaction window isn't rewritten: this application may refuse an interaction earlier under its local policy. Reopening an owner page doesn't extend the grant's local deadline.

## What the scenario checks

The workbench uses `gnap-client` to sign requests, retain grant state and verify the finish callback. Those are shared SDK behaviors. Separately written assertions inspect the received bytes, headers, and lifecycle results, without the SDK's message validators.

After approval the scenario performs:

1. A signed read of the synthetic document succeeds
2. The identical request, with the same nonce and timestamp, is refused
3. A request signed by another key with the same `kid` is refused
4. A read with the live token and a fresh signature succeeds
5. The token value rotates, the old value is refused, and the new one reads
6. The token is revoked, and its retired value is refused

A deny-all service therefore fails the positive controls. A denied consent instead checks `user_denied` without a token; it doesn't pretend to have tested the token lifecycle. A completed scenario may contain failed checks. Network failures, deadline expiry and unsupported responses are inconclusive, without erasing failures already observed. No count is a count of completed RFC duties.

Reports contain the static identifier and explanation of each check, its state, passed, failed, or untested, the target identifier, the observation time, and the harness provenance. They exclude tokens, proofs, raw response bodies, owner tickets, and callback references, and the pending interaction link stays out of the downloadable report. The application logs no request body, but that promise doesn't cover the hosting infrastructure or the browser history.

## Admission and network limits

Each start consumes the same process-wide 60-second cooldown as the unsigned live probes. The workbench admits four active workers and retains at most eight reports. Work and callbacks expire after five minutes; report cookies are HttpOnly/SameSite=Lax, Secure on HTTPS, and expire after ten minutes. Lax permits the expected top-level return from the AS. A callback without the initiating client's session can't advance another session.

Each worker has a 16-request budget, including best-effort cleanup. Requests are restricted to configured methods and exact destinations or bounded management segments. Redirects, proxies and automatic retries are disabled. Every HTTPS resolution is checked: at most 16 addresses, all public, pinned for the request while preserving TLS hostname verification. DNS, connection and body reads have a shared four-second deadline; response bodies are limited to 8 KiB. Explicit HTTP loopback configuration is a development-only deviation, never a TLS exception enabled by a public request. Grant inspection by GET isn't exercised. Continuation respects the AS's wait from receipt of its response, with five seconds when omitted. Waits above 30 seconds are outside this scenario's profile.

The lab separately bounds external grant capacity, per-key capacity and owner sessions. Capacity refusal can return HTTP 503; it isn't necessarily an outage. Local limits don't constitute distributed abuse protection. Closing the browser doesn't cancel work already authorized, and an outage may prevent cleanup; short-lived synthetic grants limit that residual state.

For an operator-authorized deployment, the acceptance driver exercises the real application pair. It simulates the resource owner's explicit form submission using a separate cookie jar; the workbench itself never submits that form:

```bash
python3 -B tools/smoke_lifecycle.py \
  --demo https://as.example --workbench https://workbench.example --choice allow
```

Use `--choice deny` for the denial path, respecting the shared cooldown. Local, CI and hosted observations must be reported separately. These checks don't verify authenticated introspection directly, restart recovery, arbitrary rights, Biscuit, an independent vendor, browser rendering or complete C1/C2 conformance.
