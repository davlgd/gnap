# Delivering the Biscuit example

This guide covers the separate [Biscuit client, AS and RS](../apps/biscuit-files/README.md).
It is an operational acceptance procedure, not a claim of complete GNAP or
Biscuit conformance. A successful local run does not establish hosted behavior.

## Deployment layout

The dedicated Clever Cloud demonstration uses three canonical HTTPS origins:

| Role | Origin | Clever alias | Rust binary |
| --- | --- | --- | --- |
| Client | <https://gnap-biscuit.cleverapps.io> | `gnap-biscuit-client` | `client` |
| AS | <https://gnap-biscuit-as.cleverapps.io> | `gnap-biscuit-as` | `as` |
| RS | <https://gnap-biscuit-files.cleverapps.io> | `gnap-biscuit-rs` | `rs` |

These addresses describe the deployment configuration, not an availability
guarantee. Each application uses a Build M instance and one XS runtime instance.
In particular, do not scale the AS horizontally: its grants and one-use request
reservations are volatile process-local state. The RS makes an authenticated
HTTPS call to the AS for every locally authorized file request.

Configure each application with `APP_FOLDER=apps/biscuit-files`,
`CC_RUSTUP_CHANNEL=1.98.0`, its `CC_RUST_BIN` from the table,
`CC_HEALTH_CHECK_PATH=/health`, and `KEY_SOURCE=environment`.
Set all three origin variables on every role, exactly as shown, without a
trailing slash. Omit `KEY_DIRECTORY`. The platform proxy must preserve the
canonical authority and prevent untrusted direct access to the HTTP backend.
The build requires that Rust channel to be available on the platform. A
successful deployment status is not an application verdict: check each role's
health endpoint, then run the acceptance scenario.

Supply only the role-specific variables listed in the application's
[key configuration](../apps/biscuit-files/README.md#deployment-boundaries).
Keep actual newlines in PEM values. Use dedicated test keys and private platform
configuration, retaining a protected operator backup. Never copy another role's
private key, print key material, place it in shell command arguments or commit
it. Private environment variables remain accessible to authorized operators;
this example does not provide production key custody or a KMS integration.

The shared sandbox immediately approves a fixed synthetic policy without human
authentication or resource-owner consent. Sessions share the initial client
identity and files. Its 64-authority capacity and bounded client worker can be
exhausted by other visitors; it is not a public availability or multi-user
isolation benchmark. Do not submit personal data or production credentials.

## Application acceptance

From the repository root, with permission to create disposable grants, mutate
synthetic files and run negative probes on all three services:

```console
python3 -B tools/smoke_biscuit.py --as https://gnap-biscuit-as.cleverapps.io --rs https://gnap-biscuit-files.cleverapps.io --client https://gnap-biscuit.cleverapps.io --consent
```

The driver checks health, unsigned-request and cross-origin refusal, cookie
attributes, a cookie-less session's refusal, allowed reads/writes, forbidden
crossed rights, local attenuation, token-value rotation, two presentation-key
changes, parent revocation and a fresh independent session. It reads a selected
descendant successfully before testing its retirement with a fresh signature.
The driver refuses to credit retirement once its conservative timing window is
spent. The application signs these probes with the retired token's correct key.

Reports contain only fixed check identifiers and outcomes, never keys, tokens,
cookies or server response text. `pass` means this application scenario passed;
`fail` identifies the first unmet assertion; `inconclusive` identifies an
interrupted exchange or timing limit. Both latter outcomes exit nonzero. There
are no automatic retries. Cleanup reports whether revocation was acknowledged
for each retained session; `unconfirmed` must not be read as successful cleanup.
Already revoked sessions need no additional cleanup request.

The acceptance driver uses validated TLS and follows no redirects. It bounds
response bodies and socket operations, checks elapsed scenario time before and
after requests and allows longer key-generation calls. These checks are not hard
wall-clock preemption. The client also has its own worker and transport limits;
a timeout does not show whether a mutation completed remotely.

## Operator-controlled maintenance

Run the same command with `--maintenance` in an interactive terminal during an
announced test window. This affects other visitors. Keep the driver running and
operate the platform from another terminal; it retains its cookies across the
three confirmation pauses and never executes deployment commands itself.

1. When requested, restart only the RS. Wait for that deployment to be ready,
   then confirm. A fresh request using the existing authority must succeed.
2. When requested, stop only the AS and verify it is unavailable, then confirm.
   An otherwise authorized resource operation must report RS status 503.
3. Restart the AS with the same configuration and wait for readiness, then
   confirm. Its volatile old authority must be refused, and a new grant must
   succeed before final revocation.

Each confirmation allows five minutes. The driver checks a fifteen-minute
scenario budget, shorter than the twenty-minute parent lifetime. Exceeding a
timing limit is inconclusive. If interrupted, restore the AS and RS, inspect
deployment status, and account for any unconfirmed cleanup; do not leave the
shared sandbox stopped. This mode checks a fresh request after RS restart, not
replay of identical signed bytes. Exact-request replay across restart and racing
RS instances is covered separately by the local Rust process tests.

## Recording evidence

For a public delivery, record the merged Git revision, each platform deployment
identifier and runtime/build size, UTC observation times, driver command and
sanitized result, maintenance operations, and cleanup outcome in the delivery
PR. Keep failed or inconclusive attempts distinct from a subsequent successful
run. A health response does not identify the deployed revision; obtain that
from platform deployment metadata.

The resource results are reported through this project's client, not captured
independently on the client-to-RS connection. This driver does not establish
browser-engine behavior, independent-vendor interoperability, complete Biscuit
grammar, public exact-request replay resistance, selective block revocation or
RFC 9767 introspection. The signed live-decision endpoint is application-specific,
not a standardized Biscuit/GNAP profile. Keep these limits alongside any hosted
success report and the [support matrix](support-matrix.md).
