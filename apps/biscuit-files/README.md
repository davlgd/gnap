# Biscuit files

A small GNAP application with three independent processes: an authorization
server, a resource server and a browser-facing client. The AS uses the SDK's
`TokenEncoder` extension to issue real Biscuit tokens. The client can restrict
one locally, then prove possession of its key while presenting that exact
descendant to the RS.

The files are synthetic. The fixed AS policy immediately grants **read notes**
and **write draft** for 1200 seconds to one configured client key. It does not
request resource-owner consent or identify a human user. The two rights remain
separate: read notes does not grant read draft, and write draft does not grant
write notes.

## Run locally

This standalone application requires Unix and Rust 1.98; its key-file setup
relies on Unix permission modes. It does not change the SDK's Rust 1.85 contract.
Run these commands from the repository root:

```console
cargo build --manifest-path apps/biscuit-files/Cargo.toml --locked
export KEY_DIRECTORY="$PWD/apps/biscuit-files/.local"
export KEY_SOURCE=directory
apps/biscuit-files/target/debug/as --init-config "$KEY_DIRECTORY"
```

Initialization generates independent RSA client/RS keys and an Ed25519 Biscuit
root. It creates a private directory and refuses to overwrite an existing one.
It never prints private keys. The directory is ignored by Git.

Set these variables in each of three terminals:

```console
export KEY_DIRECTORY="$PWD/apps/biscuit-files/.local"
export KEY_SOURCE=directory
export AS_ORIGIN=http://127.0.0.1:18101
export RS_ORIGIN=http://127.0.0.1:18102
export CLIENT_ORIGIN=http://127.0.0.1:18103
```

Start one process per terminal:

```console
PORT=18101 apps/biscuit-files/target/debug/as
```

```console
PORT=18102 apps/biscuit-files/target/debug/rs
```

```console
PORT=18103 apps/biscuit-files/target/debug/client
```

Open [the local client](http://127.0.0.1:18103). Start a session, try both allowed
operations and their forbidden counterparts, then restrict the token to notes
for 120 seconds. Reading still works; writing draft no longer does. Rotation
replaces the authority and restores the original approved rights on the new
token. Test the retired descendant: it is denied. Revocation likewise retires
the authority and all its descendants.

Attenuation adds only the profile's typed exact-resource and deadline checks.
Restrictions accumulate, so a later block cannot undo an earlier one. This
preserves the client key; it is not delegation to a new key or RFC 9767
downstream token derivation. Token values, management credentials and private
keys stay in the client process, not in browser storage or API results.
Browser sessions have separate tokens but share the configured client key and
synthetic files; this is not a multi-user identity model.

## A live, one-use resource decision

On every correctly proved, locally authorized file request, the RS calls the
AS's fixed `/resource-check` endpoint. It sends exactly three fields: the native
authority identifier as unpadded base64url, and the nonce and creation time from
the resource signature that the Biscuit verifier actually accepted:

```json
{"authority":"<native authority signature>","nonce":"<accepted resource nonce>","created":1800000000}
```

The RS signs this request with its own preconfigured PS256 key. It uses the
same SDK request-signing helper as the client, without an access token. The AS
verifies method, exact URI, body digest, timestamp and a one-use signature
nonce against that RS key. The client and RS keys must differ.

The response body has just one field:

```json
{"request_allowed":true}
```

The AS also returns `Biscuit-Check-Nonce`, echoing the separate RS-to-AS HTTP
signature nonce, and `Biscuit-Check-Request-SHA256`, containing the unpadded base64url SHA-256
digest of the exact request body bytes. The RS checks both headers and the
strict response shape. TLS authenticates the AS in public deployments; these
correlation headers are not signatures and do not replace TLS.

A unique, live token record must match the authority identifier. Under the same
lock that protects issuance, rotation and removal, the AS checks its lifetime,
derives the client identity from its RSA public modulus/exponent, and reserves
the resource nonce for that key. The reservation is not scoped to `kid`, an
authority or an RS instance: changing any of these must not reopen that nonce.
The AS trusts its configured RS to supply parameters from a successfully proved,
locally authorized request; it does not reverify a resource signature here.

The SDK owns the native-identifier and credential indexes. Its atomic grant
store publishes replacements only against the revision that was read; a stale
snapshot cannot restore an old authority. The application retains only grant
IDs for cleanup and the 64-authority capacity check, both under the same lock.
This adapter is intentionally limited to one token per immediately approved
grant without continuation. Expired or closed grants are removed on store
access, without clearing the client key's resource reservations.

Unknown, ambiguous, expired or removed authorities, repeated resource nonces,
out-of-window creation times and exhausted reservation quotas return false.
Failed channel proof, malformed responses, bad correlation, unavailable clocks
and transport failure never produce an allowed result. Every response is
`no-store`; the RS keeps no positive decision cache. A failed or timed-out file
operation can still spend its nonce, so a retry needs a freshly signed request.

This channel combines a one-use request reservation with **authority-wide
revocation**, not selective revocation of individual attenuation blocks.
Descendants inherit their verified authority's status. No token, descendant
identifier, file content or requested path is sent to the AS. It is an
application channel, not GNAP introspection or complete RFC 9767 support.

## Deployment boundaries

Use three distinct canonical HTTPS origins without a trailing slash. HTTP is
accepted only when an explicit configured origin is loopback. No outbound
redirect is followed, and each transport accepts only its configured origin.
Incoming Host and URI authority must agree with the role's canonical origin;
aliases are refused with 421, not redirected. `Forwarded` and
`X-Forwarded-Host` are not trusted. A TLS-terminating proxy must preserve the
original authority; backend HTTP/HTTPS may differ from the public scheme.

Distribute only these files to each process, through a private, operator-managed
directory identified by `KEY_DIRECTORY`:

| Process | Required files |
| --- | --- |
| AS | `root.key`, `client.jwk`, `rs.jwk` |
| RS | `rs.pem`, `root.pub` |
| Client | `client.pem`, `root.pub` |

The shared initialization directory is a local convenience, not a recommendation
to mount every key into every deployed process. No role loads another role's
private key. Certificate validation remains enabled. Production key custody,
rotation and durable storage are outside this example.

For Clever Cloud, select `KEY_SOURCE=environment` and omit `KEY_DIRECTORY`.
Configure the three public origin variables as above, using the deployed HTTPS
origins. Each application receives only the material listed for its own role:

| Role | Environment variable | Value |
| --- | --- | --- |
| AS | `BISCUIT_AS_ROOT_PRIVATE_KEY_HEX` | Private Biscuit root in hexadecimal |
| AS | `BISCUIT_AS_CLIENT_PUBLIC_JWK` | Complete client public JWK as JSON |
| AS | `BISCUIT_AS_RS_PUBLIC_JWK` | Complete RS public JWK as JSON |
| RS | `BISCUIT_RS_PRIVATE_KEY_PEM` | RS private key as PKCS#8 PEM, with real newlines |
| RS | `BISCUIT_RS_ROOT_PUBLIC_KEY_HEX` | Public Biscuit root in hexadecimal |
| Client | `BISCUIT_CLIENT_PRIVATE_KEY_PEM` | Client private key as PKCS#8 PEM, with real newlines |
| Client | `BISCUIT_CLIENT_ROOT_PUBLIC_KEY_HEX` | Public Biscuit root in hexadecimal |

Use private deployment configuration to supply these values, not repository
files, command examples containing keys, or build logs. Environment mode keeps
the material in process memory and never writes it to disk. Required keys are
validated before the listener starts, and errors never include PEM, JWK, hex
values or parser details. The AS refuses reuse of the same RSA key for client
and RS, regardless of their `kid` labels.

There is no fallback between sources. `KEY_SOURCE=directory` is the default
when the selector is absent and still requires `KEY_DIRECTORY`. Environment
mode rejects `KEY_DIRECTORY`; directory mode rejects recognized key environment
variables. Both modes reject the presence of a recognized key variable owned
by another role, without loading its material into a crypto parser. Missing,
empty, malformed or oversized material stops startup. Use a clean, role-specific
configuration rather than copying one application's entire environment to another.

Each AS/RS accepts at most four active jobs, including bounded body reading,
without an unbounded CPU queue. A worker permit is retained until its blocking
job really finishes, even after client cancellation. Inbound bodies and network
responses are capped at 32 KiB; file writes at 4 KiB; resource-check request
bodies at 384 bytes and accepted decision responses at 64 bytes. Outbound calls time out
after two seconds and body reads after three seconds. The Biscuit verifier adds
its own structural and Datalog limits; those are not hard CPU preemption.

The client has one blocking worker, eight queued commands, at most 64 sessions,
80 actions per session, and a 20-minute session lifetime. Browser mutations
require the exact Origin. After session creation, they also require an HttpOnly,
SameSite=Strict session cookie, Secure under HTTPS. A timed-out command may
still finish; retrying is not an idempotency guarantee. The AS retains at most
64 live authorities. The AS and RS keep separate atomic proof-nonce stores,
each holding at most 4096 entries for 600 seconds. Local proof-nonce stores
refuse new proofs when full or rolled back.
The AS's additional resource reservations have both a 256-entry per-client-key
quota and a 4096-entry global quota. They expire against monotonic `Instant`
time after 600 seconds, never by early eviction to make room. Rotation and
revocation do not erase that key's reservations. The proxy must also bound
connections, headers and ingress rates; these limits are not a general
distributed rate-limiting service.

Resource `created` must be within 300 seconds of AS time, with a stricter
future bound of 90 seconds. This is application policy, not a GNAP requirement.
The deployment budgets at most 60 seconds of AS/RS clock offset; the RS accepts
30 seconds of resource-signature skew, with a further 10-second processing and
clock-adjustment margin. The tested retention invariant is
`600 > 300 + 30 + 60 + 10`. The RS-to-AS channel allows 70 seconds of signature
skew. These choices favor refusal over widening a window.

The AS also compares wall time with a monotonic anchor established by its first
resource check while holding the reservation lock.
A backwards wall clock or a deviation exceeding 10 seconds latches a refusal
until the AS is restarted and **every client obtains a new grant**. A forward
clock jump of more than 10 seconds relative to that anchor also triggers this
latched refusal. Recovery never clears reservations while leaving authorities
active. This guard does not eliminate every possible clock fault. Arbitrary
AS/RS drift outside the stated budget is unsupported; keep host clocks
synchronized rather than treating timestamps as a substitute for clock health.

All grants, authorities, nonces, sessions and file contents are in memory.
An AS restart makes existing authorities unknown and therefore unusable.
A restart of the RS loses its local replay history, but not the AS's
resource reservations. Two RS instances at the same public origin likewise
share that one-use check. Run a single AS: independent AS instances would not
share token records or reservations. File contents themselves are not replicated,
and this is not durable production storage. A live resource check and the
subsequent file operation are not a distributed transaction;
there is a residual race with a concurrent revocation. Authorization is used
immediately for that one request, never retained as a reusable capability.

## Verify the example

```console
cargo test --manifest-path apps/biscuit-files/Cargo.toml --locked
cargo clippy --manifest-path apps/biscuit-files/Cargo.toml --all-targets --locked -- -D warnings
```

The lifecycle tests run the actual AS and client SDK with the native Biscuit
encoder, real request signatures, correlated rights, attenuation deadlines,
rotation and revocation. A separate test starts all three OS processes and
uses HTTP. It checks wrong RS credentials, replay, browser boundaries and an
AS outage after a successful read. It also replays an exact request after an
RS restart, races it against two RS instances at the same public authority,
and verifies that AS restart requires a new grant. Retired-token tests generate a new
signature, so nonce replay is not mistaken for successful revocation.

Additional tests exercise canonical authorities and worker admission after an
HTTP waiter is canceled, configuration through injected lookups, and redacted
malformed-JSON responses. Storage tests cover rotation during a suspended resource
decision, stale writes after revocation or removal, atomic capacity enforcement,
and unavailable storage. An explicitly signed empty PUT is supported: its
`Content-Digest` preserves an empty body through HTTP dispatch, and the RS
clears the selected writable file. A zero Content-Length alone does not imply
message content for an otherwise bodyless management request.
Local HTTP tests do not validate a hosted TLS setup
or constitute independent conformance certification. The public RSA fixture
used by lifecycle tests is the SDK's RFC 9421 fixture; see its
[provenance](../../crates/gnap-crypto/tests/README.md).

The dependency `proc-macro-error2 2.0.1`, brought by Biscuit, currently emits an
upstream future-compatibility warning. It is not suppressed. See the
[Biscuit profile](../../crates/gnap-biscuit/README.md) for the exact supported
grammar, trust rules and dependency boundaries.
