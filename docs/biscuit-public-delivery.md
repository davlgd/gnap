# Deploy Biscuit files

This guide deploys the three services of [Biscuit files](../apps/biscuit-files/README.md), the client, the authorization server, and the resource server, then runs their acceptance scenario against the hosted origins. It's an operational procedure, not a claim of complete GNAP or Biscuit conformance, and a successful local run doesn't establish hosted behavior.

## Lay out the deployment

The dedicated Clever Cloud demonstration uses three canonical HTTPS origins:

| Role | Origin | Clever alias | Rust binary |
| --- | --- | --- | --- |
| Client | <https://gnap-biscuit.cleverapps.io> | `gnap-biscuit-client` | `client` |
| AS | <https://gnap-biscuit-as.cleverapps.io> | `gnap-biscuit-as` | `as` |
| RS | <https://gnap-biscuit-files.cleverapps.io> | `gnap-biscuit-rs` | `rs` |

These addresses describe the deployment configuration, not an availability guarantee. Each application uses a Build M instance and one XS runtime instance. In particular, don't scale the AS horizontally: its grants and one-use request reservations are volatile process-local state. The RS makes an authenticated HTTPS call to the AS for every locally authorized file request.

Configure each application with `APP_FOLDER=apps/biscuit-files`, `CC_RUSTUP_CHANNEL=1.98.0`, its `CC_RUST_BIN` from the table, `CC_HEALTH_CHECK_PATH=/health`, and `KEY_SOURCE=environment`. Set all three origin variables on every role, exactly as shown, without a trailing slash. Omit `KEY_DIRECTORY`. The platform proxy must preserve the canonical authority and prevent untrusted direct access to the HTTP backend. The build requires that Rust channel to be available on the platform. A successful deployment status isn't an application verdict: check each role's health endpoint, then run the acceptance scenario.

Supply only the role-specific variables listed in the application's [key configuration](../apps/biscuit-files/README.md#deployment-boundaries). Keep actual newlines in PEM values. Use dedicated test keys and private platform configuration, retaining a protected operator backup. Never copy another role's private key, print key material, place it in shell command arguments or commit it. Private environment variables remain accessible to authorized operators; this example doesn't provide production key custody or a KMS integration.

The shared sandbox immediately approves a fixed synthetic policy without human authentication or resource-owner consent. Sessions share the initial client identity and files. Its 64-authority capacity and bounded client worker can be exhausted by other visitors; it isn't a public availability or multi-user isolation benchmark. Don't submit personal data or production credentials.

## Run the acceptance scenario

From the repository root, with permission to create disposable grants, mutate synthetic files and run negative probes on all three services:

```bash
python3 -B tools/smoke_biscuit.py --as https://gnap-biscuit-as.cleverapps.io --rs https://gnap-biscuit-files.cleverapps.io --client https://gnap-biscuit.cleverapps.io --consent
```

The driver checks health, unsigned-request and cross-origin refusal, cookie attributes, a cookie-less session's refusal, allowed reads/writes, forbidden crossed rights, local attenuation, token-value rotation, two presentation-key changes, parent revocation and a fresh independent session. It reads a selected descendant successfully before testing its retirement with a fresh signature. The driver refuses to credit retirement once its conservative timing window is spent. The application signs these probes with the retired token's correct key.

Reports contain only fixed check identifiers and outcomes, never keys, tokens, cookies or server response text. `pass` means this application scenario passed; `fail` identifies the first unmet assertion; `inconclusive` identifies an interrupted exchange or timing limit. Both latter outcomes exit nonzero. There are no automatic retries. Cleanup reports whether revocation was acknowledged for each retained session; `unconfirmed` mustn't be read as successful cleanup. Already revoked sessions need no additional cleanup request.

The acceptance driver uses validated TLS and follows no redirects. It bounds response bodies and socket operations, checks elapsed scenario time before and after requests and allows longer key-generation calls. These checks aren't hard wall-clock preemption. The client also has its own worker and transport limits; a timeout doesn't show whether a mutation completed remotely.

## Test restarts and outages

Run the same command with `--maintenance` in an interactive terminal during an announced test window. This affects other visitors. Keep the driver running and operate the platform from another terminal; it retains its cookies across the three confirmation pauses and never executes deployment commands itself.

1. Restart only the resource server, wait until it's ready, then confirm
2. Stop only the authorization server, check that it's unavailable, then confirm
3. Restart the authorization server with the same configuration, wait until it's ready, then confirm

After the first step, a fresh request with the same authority must succeed. After the second, an otherwise authorized operation must report the RS's status 503. After the third, the old authority must be refused, and a new grant must succeed before the final revocation.

Each confirmation allows five minutes. The driver checks a fifteen-minute scenario budget, shorter than the twenty-minute parent lifetime. Exceeding a timing limit is inconclusive. If interrupted, restore the AS and RS, inspect deployment status, and account for any unconfirmed cleanup; don't leave the shared sandbox stopped. This mode checks a fresh request after RS restart, not replay of identical signed bytes. Exact-request replay across restart and racing RS instances is covered separately by the local Rust process tests.

## Record the evidence

For a public delivery, record the merged Git revision, each platform deployment identifier and runtime/build size, UTC observation times, driver command and sanitized result, maintenance operations, and cleanup outcome in the delivery PR. Keep failed or inconclusive attempts distinct from a subsequent successful run. A health response doesn't identify the deployed revision, which the platform's metadata gives.

The resource results are reported through this project's client, not captured independently on the client-to-RS connection. This driver doesn't establish browser-engine behavior, independent-vendor interoperability, complete Biscuit grammar, public exact-request replay resistance, selective block revocation or RFC 9767 introspection. The signed live-decision endpoint is application-specific, not a standardized Biscuit/GNAP profile. Keep these limits alongside any hosted success report and the [support matrix](support-matrix.md).
