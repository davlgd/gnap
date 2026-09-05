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

Open <http://127.0.0.1:8080>. The initial key generation can take a few seconds.
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

## Deployment contract

- `PORT`: listening port, default `8080`.
- `APP_ORIGIN`: exact externally visible HTTPS origin, no trailing slash, path,
  userinfo, query or fragment. Use its canonical spelling: lowercase hostname,
  without an explicit default port. HTTP is accepted only for localhost development.
  In that mode the app explicitly enables nonstandard HTTP-loopback discovery;
  OPTIONS responses carry `GNAP-Development-Only: insecure-loopback-discovery`.
  Public HTTPS deployments use the strict RFC 9635 discovery checks.
  HTTP origins with `127.0.0.1` or `localhost` bind only `127.0.0.1`; `[::1]`
  binds only `::1`, without resolving DNS to choose an interface. Prefer the
  explicit IPv4 address in local examples; `localhost` clients must fall back
  to IPv4 if they try IPv6 first. A local proxy must connect through loopback.
  HTTPS origins bind `0.0.0.0` for the upstream TLS proxy. The app itself serves
  HTTP: the proxy and deployment firewall must block untrusted direct backend
  access. The Host/authority guard is not a network-access boundary or TLS.
  No environment variable overrides this listening policy.
- Binary: `gnap-delegation-demo`; readiness: `GET /health`.
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
`gnap-as::AuthorizationServer`; the RS shares the SDK's transactional token indexes with
the AS and calls `gnap-crypto::verify::verify_request`. **No RFC 9767 introspection
endpoint is implemented or simulated.**

## Security and lifecycle limits

- One ephemeral 2048-bit RSA key represents the application; browser sessions
  are isolated client references, not independent cryptographic client owners.
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
  State-changing POSTs require an exact matching Origin. Callback hashes are
  verified and a callback is consumed once per browser session.
- At most 64 active sessions, a 32-command worker queue, 40 actions per session,
  10 new sessions/minute globally, and 16 in-flight protocol/RS operations.
  Storage holds at most 256 grant aggregates: saturation returns HTTP 503,
  without evicting grants with live rights to make room for new requests.
  A single client worker serializes session operations; a slow HTTP request can
  hold up all sessions until its 10-second timeout. It is intentionally a bounded
  demonstration, not a throughput benchmark.
- The consent policy chooses a 1,200-second access-token lifetime. The AS
  advertises `expires_in`, records the issuance time and renews it only after
  successful rotation. The RS checks that SDK deadline on every access and
  removes expired tokens without waiting for the 30-second background sweep.
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
  The RS verifies the signature outside the storage lock, then rechecks the
  aggregate revision and token expiration under the same short lock used by
  mutations. A rotation/revocation committed during verification invalidates
  the stale read; a read already authorized can finish before a later revoke.
  Any change to the aggregate invalidates that snapshot, including a change
  to a sibling token if a future issuance policy supplies several tokens.
  AS/RS replay caches are separate. Unavailable storage returns HTTP 503 (not
  an authentication failure), with no credential values reflected in the error.
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
