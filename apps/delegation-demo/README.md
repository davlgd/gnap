# GNAP delegation lab

A real HTTP consumer of this workspace: a web client asks an authorization
server for read access to a synthetic folder and archive, the visitor explicitly consents,
and a resource server verifies a live key-bound token before returning documents.
Rotation and revocation can then be checked by presenting the retired token
with a **fresh valid signature**, which the resource server must reject.
Ordinary approval leaves the grant open: poll, reduce its rights, request an extension
with new consent, or revoke the entire grant through its continuation endpoint.

This is a public teaching sandbox, not an authenticated document service or a
claim of full GNAP conformance. No personal data or private key fixtures are used.

## HTTP push finish

**Start with a server-to-client callback** opens consent in the browser, then
sends the finish notification directly from the AS to the client over HTTP.
The [push guide](../../docs/push-finish.md) explains callback ownership, DNS
pinning, bounded delivery and the distinction between consent and receipt.
Only this deployment's pre-registered callback paths are eligible. There is
one attempt, no automatic retry and no AS polling fallback if it is lost.
This flow closes continuation after issuance; the resource token keeps its
individual lifecycle. It is not a general callback relay or a complete C2
implementation.

## Optional subject disclosure

On an HTTPS deployment, "Start with identity disclosure" requests document
rights plus `opaque`, `iss_sub` and a PS256 `id_token` about one fictional
resource owner. Explicit approval of this exact request releases both; denial
releases neither. No identity is released before interaction. Unlike the other
flows, approval closes continuation: the resource token keeps its own lifetime
and management, but this grant cannot be modified or polled after approval.
Local HTTP refuses this option without affecting the existing flows.
The demo accepts exactly `sub_id_formats: ["opaque", "iss_sub"]` and
`assertion_formats: ["id_token"]`, without extra subject fields, with a single
access-token request and redirect finish. Other subject requests are refused;
this deliberate application policy is not a general limitation of GNAP.
Identity issuance is restricted to this demo's registered browser-client
references, all resolved to its one shared application proof key. A client key
supplied by value cannot request identity, and presenting a known reference with
another key does not authenticate it. The separate resource-server identity cannot
request this subject flow. This demo does not offer open client registration.

The AS generates a dedicated assertion key in memory, separate from every
HTTP proof key. The client pins its public verifier, exact HTTPS issuer and GNAP
endpoint in application configuration. It verifies signature, audience, session
nonce, time and issuer/subject consistency through `Session::verify_subject`.
The audience is the RFC 7638 thumbprint of the application's actual client proof
key; the nonce is the client's retained interaction-finish nonce. These are
agreed application conventions, not new GNAP requirements. No key is fetched
from the assertion. Only verified identity claims reach the page, never the
compact assertion, nonce or private key; an ID Token is not an access token.

Every visitor shares one client key and one fictional subject. Its random
opaque identifier stays stable only for this process and changes after restart;
the `iss_sub` and ID Token name that same fictional subject. This is not a
general pairwise account store. Assertions expire after five minutes. Their
`auth_time` represents the simulated authentication event at sandbox consent,
not authentication of a real visitor. There are no accounts, login, independent
identity provider, complete OpenID Provider or identity renewal/revocation
workflow. This exercises the signed subject-assertion profile, not JWT access
tokens, complete C1/C2 coverage or independent-vendor interoperability.
Assertion expiration is separate from the resource token's twenty-minute
lifetime. An unavailable verified identity at expiration is not an outage or
session revocation: the resource token remains usable under its own checks.

## External workbench clients

External clients are disabled by default. To enable the separate workbench
lifecycle, set `GNAP_EXTERNAL_CLIENTS` to a JSON array of at most eight objects:
each object contains a `jwk` public RSA PS256 key and an exact `callback` URI
ending in `/lifecycle/callback`. An empty array also disables this flow. Invalid
configuration prevents startup; diagnostics identify the entry index without
printing its contents. Supply public keys only: private JWK fields are rejected.

Each public key must contain `kty`, `n`, `e`, `alg: "PS256"` and `kid`, with a
2048–4096-bit modulus. The resolver checks the actual public key and its
metadata, then verifies the client's signature using the configured key. A
matching `kid` alone grants no authority, and no remote key resolution occurs.
The same key material cannot be registered twice under different callbacks.
Callbacks must use canonical HTTPS, with no user information, query or fragment.
For local tests only, an explicit HTTP-loopback `APP_ORIGIN` permits an
HTTP-loopback callback. Other HTTP destinations remain forbidden.

This profile issues one key-bound, opaque `synthetic-folder:read` token for
300 seconds, after manual consent. The initial request contains a client key
by value, a single access-token request and a simple redirect interaction;
finish must use the configured callback. Labels, flags, token formats,
extensions, subjects, user information, multiple tokens, push finish and codes
are outside this profile. It does not offer ongoing grants, expansion or
downstream derivation. Token rotation and individual revocation remain available.
The document RS accepts this exact five-minute lifetime alongside the internal
twenty-minute profile; the reports profile is unchanged.

The owner visits the AS's existing `/interact/{handle}` route in a separate
browser context. GET displays a fixed synthetic-client consent form and never
approves anything. POST requires that owner's separate HttpOnly cookie, a
one-use ticket and the exact AS Origin and Host. The recorded choice is bound
to the grant, request, AS nonce and original deadline. The SDK completes the
interaction transactionally and produces the callback hash and reference;
the workbench only receives that callback, it does not approve consent.
This is still a fictional owner, not a login or a real account-authentication
system.

Local consent expires five minutes after the initial grant, even though the
SDK's generic interaction response advertises its ten-minute upper bound.
The form states the shorter limit; reloads and replacement owner sessions
cannot extend it. The workbench also sets a five-minute finish timeout.
Admission allows at most 32 live external grants in total and four per public
key, including approved grants while their tokens remain live. External owner
state is capped at 64 entries, each lasting at most five minutes, with 120 form
requests per minute and four concurrent form workers. These are sandbox
budgets, not GNAP protocol limits. A POST counts only after finding a live
owner session bound to that handle; malformed forms and invalid tickets from
that session still count. They do not consume the internal browser's
owner-session allowance. Grants, choices and keys live only in this process;
a restart invalidates them. No Biscuit keys are used by this flow.

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

The metadata button exercises one-hop downstream derivation (RFC 9767 §4).
RS1 first verifies the caller's folder read through introspection, then sends a
signed grant request to the configured AS with `existing_access_token` in its
body. The AS explicitly maps that task to `archive-metadata:read` at RS2. This
does not reuse the parent rights or grant archive document access. The child
is bound to RS1's own key, expires within 60 seconds and no later than its
parent, and is presented to RS2 with a fresh signature. RS2 authenticates its
own introspection call with a third key, distinct from the client and RS1.
The UI displays only synthetic metadata and the child's advertised lifetime.
The introspection registry recognizes both RS keys; the separate derivation
requester registry admits only RS1. Enrollment in a role does not authorize
rights: the AS policy still checks the exact parent and the explicit mapping.

This selected profile accepts only one hop, one opaque child token and no
interaction, subject, bearer flag or continuation for that child. The client
cannot use the child, and neither token works at the other's RS. RS1 makes one
signed DELETE attempt against the child's management endpoint after the RS2
attempt, including a refused or failed resource call. An inconclusive cleanup
response gives 503, not success; it does not prove whether deletion happened.
There is no automatic retry. Token-value rotation for children is refused.
Removing the exact parent token, including rotation, revokes its children
atomically in AS storage. This does not make an earlier introspection decision
and a later network read atomic: a concurrent retirement can race a read already
authorized by the AS. Every new read uses introspection; no positive result is
cached. Local Biscuit attenuation is a different mechanism, not this flow.

The two-token button starts a request for several access tokens
([RFC 9635 §2.1.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1.2))
under one consent: a `documents` token for the registered document rights and a
`reports` token for `synthetic-reports:read`, served at `/resource/reports` by a
third RS with its own key. The resource owner may allow the whole request or
only the reports token; in the latter case, the AS issues an array containing
one token
([§3.2.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2.2)). The
grant is approved or refused as a whole; there is no pending state per label.
Each issued token carries its requested label, its own rights and its own
management endpoint. The consent display keeps the requested label even when
only one slot remains. Rotating or revoking one token leaves its sibling in
place, and a token works only at its own RS: the reports token is refused by
the documents RS, by the downstream metadata path and by the AS as a source
for derivation. Every action names the token it targets; nothing falls back to
"the other" token when the named one is missing, and the retired-token check
says which token it presents. A later change is compared with the live token
carrying the same label, never with the union of the grant's rights: narrowing
the documents token needs no new consent, but asking for a label that has no
live token sends the owner a new consent request, and approval replaces the
lot as a whole. This is the application's policy for two fixed labels, not a
general rule of GNAP.

The separate token controls demonstrate rotation and token-only revocation.
"Revoke the entire grant" instead sends DELETE to continuation and invalidates
every token belonging to it. It can also cancel a pending request before consent
or the callback: approval is not required for cancellation. Both cases require
an open continuation and respect the AS wait period. Changing rights, unlike
cancelling the request, requires an approved grant. Retired-token checks use
fresh valid signatures.

```sh
cargo test --manifest-path apps/delegation-demo/Cargo.toml --locked
node --test apps/delegation-demo/tests/ui/requested_rights.test.mjs
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

## Secondary-device flow

Choose **Start on a second screen**. Keep that client page open, then open the
displayed code-entry address in another browser profile or private window. Type
the eight-symbol code there, read the requested rights, and allow or deny the
request. Return to the first page and poll after the displayed wait period.
The client can then read the protected resources only if the owner allowed it.
An early poll stays pending and does not invalidate the consent page.

The client requests `user_code_uri`, conveys the returned URI unchanged, and
negotiates no finish callback. The entry page uses a separate `gnap_owner`
cookie, not the first browser's `gnap_demo` cookie. Neither the code nor an
internal grant handle is placed in a form URL. Decisions require an Origin
matching the configured application, a session-bound form ticket and an
explicit POST. Unknown, malformed and expired codes get the same error message;
no constant-time lookup claim is made. The page never redirects to a client.

This is still a fictional owner, not account authentication: anyone using the
sandbox may play that role. The code is a locator, not proof of identity.
Loopback addresses work only on the machine running the app. A physical second
device needs a reachable HTTPS deployment. The [6 September hosted validation](../../docs/validation-2026-09-06.md)
exercised this flow with two HTTP cookie stores over HTTPS, not a physical device
or a browser engine.
Polling here is not the full C2 profile, which also needs other capabilities.

Owner state is limited to 64 sessions with a fixed ten-minute lifetime. Each
session has five admitted submissions, including malformed input, invalid form
tickets and consent decisions. A rolling shared budget admits at most 60 per
minute, after checking that the owner session exists and has attempts left.
Reloading does not extend the lifetime or reset the budget. Requests with the
wrong origin or bodies over 1 KiB are refused before code lookup and do not
consume those form budgets. Client starts and grant storage retain their own
limits. Acquiring 64 owner sessions can saturate the page for ten minutes;
there is no eviction or claim of production multi-tenant availability. A public
production service needs its own owner authentication and admission policy.

Consent is bound to the displayed request and interaction window, not the
continuation revision, which changes on an ordinary poll. Completion and
decision publication are coordinated so a later poll cannot observe a finished
interaction without its choice. A poll and completion prepared from the same
snapshot can still race: the losing write is refused atomically. No automatic
retry occurs. Check the first screen; if the code is still live, explicitly
submit it again rather than assuming the refusal cancelled the grant. A lost
HTTP response is similarly not proof that an operation did not happen.

The co-located client worker resolves the issued code internally only to track
its grant for cleanup. A separate client would not have that access: its
protocol exchange uses the code, entry URI and signed polling alone. The
consumer tests exercise those browser-facing operations with two independent
HTTP sessions, then a real protected read through introspection. They do not
automate browser rendering, prove owner identity or establish interoperability
with another implementation. See the [SDK guide](../../docs/secondary-device-interaction.md)
for generation, normalization and storage-adapter requirements.

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

One application contains the client, AS and three RS roles, not independent
security administrations. `gnap-client::Session` exchanges actual HTTP requests with
`gnap-as::AuthorizationServer`. For each resource request, the RS fetches
`/.well-known/gnap-as-rs` from that configured AS, then calls `/introspect` with
a signature from its own pre-registered key. This exercises RFC 9767 discovery,
opaque-token introspection and resource-set registration. The metadata action
adds token derivation, not RS self-enrolment or resource-set management.
Neither RS has token-store lookup. The AS returns the key of the token's caller:
the browser application's key for a parent, RS1's key for a child. The receiving
RS verifies the exact incoming request through `gnap-rs::Authorizer`. The
application supplies its HTTP adapter, replay memory and document/metadata/report
policies; it no longer implements the introspection-to-authorization sequence
itself. The [RS SDK guide](../../docs/resource-server-sdk.md) explains how to
reuse that boundary without depending on an AS implementation or its store.

Only the configured origin and those two exact AS paths, `/register-resources`
for startup registration, `/gnap`, `/resource/archive-metadata` and bounded
single-segment `/token/{handle}` management paths are reachable through the RS
HTTP adapter. An advertised endpoint elsewhere is refused before
credentials are sent. Redirects and environment proxies are disabled; ordinary
TLS certificate verification remains enabled. Each call has a two-second timeout
and an 8 KiB response limit. An ordinary folder/archive read makes two HTTP round
trips: a discovery GET followed by an introspection POST. The metadata action
adds a grant POST, an RS2 GET with its own discovery/introspection, then DELETE:
seven internal HTTP exchanges in total. AS, RS1 and RS2 use separate admission
semaphores, so RS1 waiting on RS2 does not occupy an RS2 worker slot. A completed
metadata action exceeding 12 seconds is refused; this elapsed-time check is not
cancellation of blocking calls or a hard end-to-end deadline. There is deliberately
no metadata cache and no positive-token cache; this simple
consumer does not optimize connection reuse or claim high throughput.

The fixed demo profile requires a public PS256 HTTPSig client key, the exact
grant issuer, its two understood read rights and `iat`/`exp` describing a
1,200-second parent lifetime. RS2 instead requires only `archive-metadata:read`
and a positive lifetime no greater than 60 seconds. Those timestamps are optional
in RFC 9767, but not in
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

- The client accepts interaction callbacks for at most five minutes from each
  interaction response, or less if the AS announces a shorter duration. This
  local policy is separate from the AS's ten-minute interaction lifetime and
  the browser's twenty-minute session. It does not discard an already validated
  reference, revoke a grant or add a polling fallback after a refused callback.
  Start a fresh request if the finish window has elapsed. The callback HTTP
  handler keeps its generic error response rather than reflecting untrusted
  callback data. The SDK distinguishes client timeout, AS expiry and a callback
  clock value preceding the interaction response. It does not detect every
  intervening clock change; clock reliability remains the caller's responsibility.
  The [consumer regression](src/finish_timeout_tests.rs) uses the worker's
  session constructor and a real HTTP grant response; it advances the explicit
  callback clock to test acceptance at 299 seconds and refusal at 300. It does
  not wait five real minutes or exercise a browser callback over HTTP.
- One ephemeral 2048-bit RSA key represents the client application; browser sessions
  are isolated client references, not independent cryptographic client owners.
  Three further, distinct ephemeral RSA keys identify RS1, RS2 and the reports
  RS. RS1 also uses its own key as the client of the downstream grant and
  resource request; the reports RS never acts as a client.
  Restart invalidates all keys, grants and tokens. No token values appear in
  the browser or application logs.
- The visitor plays the resource owner; there is no real login, user directory,
  private document upload or identity assurance. Only two document read rights
  exist: `synthetic-folder:read` at `/resource/folder` and
  `synthetic-archive:read` at `/resource/archive`. The separate derived
  `archive-metadata:read` right exposes only a synthetic document count, and
  the `reports` token's `synthetic-reports:read` right at `/resource/reports`
  only a synthetic summary.
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
  four in-flight operations per RS, in separate pools. These let resource
  workers call the AS in the same process without occupying its worker permits.
  Storage holds at most 256 grant aggregates: saturation returns HTTP 503,
  without evicting grants with live rights to make room for new requests.
  The SDK additionally caps active children at eight per exact parent, and
  retained derived grants at 256. Successful per-call deletion releases the
  active-child slot; application maintenance removes retired aggregates.
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
