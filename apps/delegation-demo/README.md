# GNAP delegation lab

A real HTTP consumer of this workspace: a web client asks an authorization
server for read access to a synthetic folder and archive, the visitor explicitly consents,
and a resource server verifies a live key-bound token before returning documents.
Rotation and revocation can then be checked by presenting the retired token
with a **fresh valid signature**, which the resource server must reject.
Approval leaves the grant open: poll, reduce its rights, request an extension
with new consent, or revoke the entire grant through its continuation endpoint.

This is a public teaching sandbox, not an authenticated document service or a
claim of full GNAP conformance. No personal data or private key fixtures are used.

## Run

From the repository root, with a recent stable Rust toolchain:

```sh
cargo run --manifest-path apps/delegation-demo/Cargo.toml --locked
```

Open <http://127.0.0.1:8080>. Key generation and resource registration can take
a few seconds; the start button stays unavailable until bootstrap succeeds.
Approve the request, follow the callback, continue after the AS wait period, and
read both resources. Polling the approved grant renews continuation without
issuing another access token or extending that token's lifetime. Keep folder
access only, then try the archive: the RS refuses it. The previous token is
also refused, including for the folder.

Request folder and archive again. The reduced token still works for the folder
while the new consent is pending. Approval replaces all earlier tokens with the
new rights; denial closes continuation but leaves previous tokens under their
own expiration and management lifecycle. To test denial and grant revocation,
use separate grants: a closed continuation cannot later revoke the whole grant.
Token revocation remains available for a retained token after denial.

The separate token controls demonstrate rotation and token-only revocation.
"Revoke the entire grant" instead sends DELETE to continuation and invalidates
every token belonging to it. Retired-token checks use fresh valid signatures.

```sh
cargo test --manifest-path apps/delegation-demo/Cargo.toml --locked
python3 tools/smoke_ecosystem.py --demo http://127.0.0.1:8080
```

The smoke test expects an already running service and creates synthetic
sessions. It drives real HTTP, consent/callback, denial, protected reads, token
rotation/revocation, cross-browser isolation, callback replay and unsigned
resource rejection. The ongoing-grant checks also exercise an approved poll,
downscope, expansion with fresh consent, protected reads while consent is
pending, and grant-wide revocation. The public browser output does not reveal
tokens: unchanged value and issuance time after polling are verified by the
SDK consumer tests, not inferred from the HTTP smoke output. Neither test
suite is a third-party interoperability test.

Listener tests require working IPv4 and IPv6 loopback interfaces. They check
actual socket addresses and local HTTP reachability, including `localhost`;
an unavailable interface is an explicit test-environment failure.
The introspection composition test also starts a real loopback AS/RS router:
it checks separate RS/client keys, both replay caches, rotation and revocation
with fresh signatures, and a 503 resource response when the AS becomes unreachable.

## Deployment contract

- `PORT`: listening port, default `8080`.
- `APP_ORIGIN`: exact externally visible HTTPS origin, no trailing slash, path,
  userinfo, query or fragment. Use its canonical spelling: lowercase hostname,
  without an explicit default port. HTTP is accepted only for localhost development.
  In that mode the app explicitly enables nonstandard HTTP-loopback discovery;
  OPTIONS responses carry `GNAP-Development-Only: insecure-loopback-discovery`.
  Public HTTPS deployments use the strict RFC 9635 discovery checks.
  RS discovery has the same explicit local exception to RFC 9767's HTTPS rule;
  its local responses carry `GNAP-Development-Only: insecure-loopback-discovery`.
  HTTP origins with `127.0.0.1` or `localhost` bind only `127.0.0.1`; `[::1]`
  binds only `::1`, without resolving DNS to choose an interface. Prefer the
  explicit IPv4 address in local examples; `localhost` clients must fall back
  to IPv4 if they try IPv6 first. A local proxy must connect through loopback.
  HTTPS origins bind `0.0.0.0` for the upstream TLS proxy. The app itself serves
  HTTP: the proxy and deployment firewall must block untrusted direct backend
  access. The Host/authority guard is not a network-access boundary or TLS.
  No environment variable overrides this listening policy.
- Binary: `gnap-delegation-demo`; `GET /health` is a liveness probe returning
  HTTP 200 with `status: "ok"` and `bootstrap: "starting"`, `"ready"` or
  `"failed"`. Readiness requires `bootstrap: "ready"`, not HTTP 200 alone.
  `/api/start` returns 503 before readiness, without creating a cookie or grant.
- Clever Cloud: use this app directory as `APP_FOLDER`, a **Build M** instance,
  and exactly one runtime instance. Set `APP_ORIGIN` to its public HTTPS origin.
  The crate has its own `[workspace]` and lockfile; path dependencies require
  the complete repository to be present during build.

The app reconstructs signed target URIs from the configured origin and actual
request target, never from untrusted `Forwarded`/`X-Forwarded-*` headers. Outbound
HTTP only reaches that fixed origin and the protocol's known paths, disables
redirects and environmental proxy configuration, and limits response size/time.

The incoming Host (or HTTP/2 authority) must match the configured origin before
an API or protocol handler runs. Conflicting or malformed authorities are
rejected. Navigation requests to `/`, `/interact/{handle}` and `/callback` on
another hostname receive a temporary 307 redirect to the configured origin,
preserving the path and query without creating or using a session. Other known
routes return 421 on a noncanonical authority, without redirecting signed
requests or forwarding credentials. `/health` remains available independently
of Host for platform probes. This is deployment policy, not a GNAP requirement.

A reverse proxy must preserve the original authority. Its backend connection
may use HTTP even when the public origin is HTTPS, including HTTP/2 cleartext
(h2c) after TLS termination. The app accepts either HTTP scheme on incoming
requests, but always derives signed URIs, redirects and the cookie's Secure
attribute from `APP_ORIGIN`; forwarded headers do not override that configuration.

### Changing the public hostname

Deploy the authority guard before changing `APP_ORIGIN`. Keep the previous
domain attached, add the new domain, then update `APP_ORIGIN` and restart the
reviewed revision. Update the diagnostic workbench's AS/RS target allowlists
to the new origin as well. Wait for instance replacement to finish before
testing: old and new processes can temporarily disagree about the origin.

This does not migrate live sessions. Cookies are host-only, and restarting the
demo discards its keys, grants and tokens. Visitors must start a new synthetic
session; an old browser tab may need to be reloaded, and an old callback cannot
restore a lost session. Do not broaden the cookie's domain to share it across
`cleverapps.io` applications.

After migration, test both the canonical origin and the previous alias:

```sh
python3 tools/smoke_ecosystem.py --demo https://demo.example --demo-alias https://previous.example
```

The single deployment contains three roles, not three independent security
administrations. `gnap-client::Session` exchanges actual HTTP requests with
`gnap-as::AuthorizationServer`. For each resource request, the RS fetches
`/.well-known/gnap-as-rs` from that configured AS, then calls `/introspect` with
a signature from its own pre-registered key. This exercises RFC 9767 discovery,
opaque-token introspection and resource-set registration, not RS self-enrolment,
resource-set management or token derivation.
The RS has no token-store lookup. The AS returns the client public key, not the
RS key; the RS verifies the exact incoming request with the shared SDK verifier.

Only the configured origin and those two exact AS paths, plus
`/register-resources` for startup registration, are reachable through the RS
HTTP adapter. An advertised endpoint elsewhere is refused before
credentials are sent. Redirects and environment proxies are disabled; ordinary
TLS certificate verification remains enabled. Each of the two HTTP calls has a
two-second timeout and an 8 KiB response limit. Every read makes two HTTP round
trips: a discovery GET followed by an introspection POST. There is deliberately
no metadata cache and no positive-token cache; this simple
consumer does not optimize connection reuse or claim high throughput.

The fixed demo profile requires a public PS256 HTTPSig client key, the exact
grant issuer, its two understood read rights and `iat`/`exp` describing a
1,200-second lifetime. Those timestamps are optional in RFC 9767, but not in
this application's profile. Unsupported flags, key parameters and response
extensions fail closed. Refusing additional response fields is a restriction of
this demonstration: RFC 9767 permits additional fields in an active response.
All resource signatures must include a nonempty nonce.

### Registering the two resource sets

After the HTTP server starts listening, one internal task discovers the AS and
registers `[synthetic-folder:read]` and
`[synthetic-folder:read, synthetic-archive:read]` with fresh RS-signed POSTs.
The trusted key registry supplies a stable `RsId` for ownership; a caller's
`kid` or identity string does not establish ownership. Each request requires
introspection and omits `token_formats_supported`, leaving the format to this
opaque AS. Any explicit list without a common registered format, including
`[]`, is refused with HTTP 400; omission and an empty list are not equivalent.

The SDK atomically deduplicates immutable sets by owner and content. The demo
retains at most two sets, with no updates, deletion, TTL or recursive references.
A resource reference is a public name for rights, never an access credential.
The client sends the combined reference initially and on expansion, and the
folder reference on reduction. Policy resolves them before consent or downscope
decisions; issued tokens retain the approved leaf rights, not mutable references.
The UI displays those leaves and keeps its existing controls.

The bootstrap makes at most six attempts within a 120-second monotonic budget,
with up to ten seconds between attempts and fresh signature nonces on every
POST. Transport failures, HTTP 404/5xx, `invalid_resource_server`, missing
capabilities in an otherwise valid discovery document, or an acknowledgement
from another instance can be transient during replacement. Other protocol
refusals, malformed metadata and unexpected endpoints stop the sequence.
Each HTTP call retains its two-second limit; a response completing after the
bootstrap deadline cannot publish references. No browser action triggers or
restarts registration. Exhaustion or a permanent failure exits the process
unsuccessfully with a fixed diagnostic, without logging keys or response bodies.

Before publishing the pair, the co-located supervisor checks both references in
this AS's resource-set registry, including owner and exact leaves. An old process
behind the canonical URL cannot supply an acknowledgement that initializes the
new client incorrectly. This is explicit application coordination, not a GNAP
wire feature: the RS-to-client handoff is in process. The client does not look
up resource sets; protected RS reads still have no access to the token store.

Restart discards keys, grants and sets and reruns the bounded bootstrap. Old
references no longer resolve, and visitors must start new sessions. A platform
may restart a failed process according to its own policy; the application has
no unbounded retry loop. Liveness remains separate from readiness so a proxy
can route bootstrap calls to an instance that has begun listening but is not
yet ready for browser starts. Canonical routing and ordinary TLS verification
must work; there is no loopback proxy bypass for a public HTTPS deployment.

## Security and lifecycle limits

- One ephemeral 2048-bit RSA key represents the client application; browser sessions
  are isolated client references, not independent cryptographic client owners.
  A second, distinct ephemeral RSA key authenticates only the RS to the AS.
  Restart invalidates all keys, grants and tokens. No token values appear in
  the browser or application logs.
- The visitor plays the resource owner; there is no real login, user directory,
  private document upload or identity assurance. Only two fixed read rights
  exist: `synthetic-folder:read` at `/resource/folder` and
  `synthetic-archive:read` at `/resource/archive`.
- Consent is bound to the stable grant ID, exact current request and the
  interaction reference committed by the AS. Completing the interaction must
  succeed before that choice is recorded or its finish redirect is returned.
  Policy reads the choice without consuming it before the grant CAS; a storage
  conflict cannot lose the decision. A previous browser/client approval cannot
  authorize another grant or a later interaction. A PATCH is approved without
  another prompt only when its requested rights are a subset of rights in the
  snapshot's still-live tokens. Otherwise it requests fresh interaction.
- Browser state uses random 128-bit HttpOnly/SameSite cookies, Secure on HTTPS.
  Every HTTP `/api/start` creates a fresh browser identity even when a cookie is
  supplied; older sessions remain subject to their normal retention limits.
  The worker rejects an internal start reusing a live session ID before calling
  the AS or changing registries. This does not revoke any existing token or
  discard consent, and grant identifiers are never reused.
  State-changing POSTs require an exact matching Origin. Callback hashes are
  verified and a callback is consumed once per browser session.
- At most 64 active sessions, a 32-command worker queue, 40 actions per session,
  10 new sessions/minute globally, 16 in-flight AS/protocol operations and
  four separate in-flight RS operations. The separate pools let resource
  workers call the AS in the same process without occupying its worker permits.
  Storage holds at most 256 grant aggregates: saturation returns HTTP 503,
  without evicting grants with live rights to make room for new requests.
  A single client worker serializes session operations; a slow HTTP request can
  hold up all sessions until its 10-second timeout. It is intentionally a bounded
  demonstration, not a throughput benchmark.
- The consent policy chooses a 1,200-second access-token lifetime. The AS
  advertises `expires_in`, records the issuance time and renews it only after
  successful rotation. The AS enforces that SDK deadline during introspection;
  its storage adapter removes expired tokens without waiting for the 30-second
  background sweep. The RS checks the returned expiration before and after
  client-proof verification, and refuses a clock rollback during a read.
  Failed rotations do not extend the lifetime. Browser sessions and pending
  grants retain their separate 20-minute limits; continuation retention starts
  at aggregate creation and is never renewed by a rewrite or failed CAS.
  Expiration of that continuation does not delete an otherwise live token.
  Rotating a token does not
  renew the browser session. Session expiration also removes the accepted
  client reference, so an unexpired token can still become unusable earlier.
- The SDK owns all credential indexes. Aggregate creation, revision-checked
  replacement and maintenance removal are atomic; the application stores only
  continuation-retention metadata. A bounded sweep removes expired tokens and
  empty/expired or revoked aggregates. Removed grant IDs are never reused.
  The AS rechecks the aggregate revision before its introspection decision.
  A read may still complete when revocation happens after that decision:
  HTTP introspection is not a distributed transaction with resource access.
  The next read always performs a new introspection. No result is cached.
  Client-to-AS, RS-to-AS and client-to-RS replay stores are distinct.
  An AS unable to determine activity, including a storage lookup failure,
  returns only `{"active":false}`; the RS refuses that context with 401 without
  claiming intrinsic token invalidity. Failed lookups produce only a static
  operator log message. An incomplete HTTP exchange, malformed response or
  unsupported response profile yields 503 at the resource. Maintenance failures
  before the AS handler runs also return 503. RS authentication errors are
  HTTP 400 at the AS, as required by RFC 9767 §3.5; they are not a resource 401.
  No credential values are reflected in these errors.
  A stale or colliding rotation returns `invalid_rotation`; invalid/colliding
  write candidates outside rotation remain internal server errors.
- Request/response bodies are limited to 64 KiB. State is in-memory only; there
  is no durable store, horizontal scaling, rate-limit fairness guarantee or
  production abuse protection. Never deploy this as a real authorization service.

GNAP capabilities demonstrated here are negotiated interaction/continuation,
approved ongoing grants, PATCH modification with re-consent, grant-wide
revocation, key-bound requests and token lifecycle management. This is not a claim that
OAuth cannot provide consent, fine-grained access or proof-of-possession; an
honest comparison must include OAuth extensions and deployment profiles.

See [DEVELOPER_FEEDBACK.md](DEVELOPER_FEEDBACK.md) for the consumer experience
and the SDK changes this application suggests.
