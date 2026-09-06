# GNAP delegation lab

A real HTTP consumer of this workspace: a web client asks an authorization
server for read access to a synthetic folder, the visitor explicitly consents,
and a resource server verifies a live key-bound token before returning documents.
Rotation and revocation can then be checked by presenting the retired token
with a **fresh valid signature**, which the resource server must reject.

This is a public teaching sandbox, not an authenticated document service or a
claim of full GNAP conformance. No personal data or private key fixtures are used.

## Run

From the repository root, with a recent stable Rust toolchain:

```sh
cargo run --manifest-path apps/delegation-demo/Cargo.toml --locked
```

Open <http://127.0.0.1:8080>. The initial key generation can take a few seconds.
Approve the request, follow the callback, continue after the AS wait period, and
read the folder. Rotate, test the retired token, read again, revoke, and test
the retired token again. A separate fresh request can demonstrate denial.

```sh
cargo test --manifest-path apps/delegation-demo/Cargo.toml --locked
python3 tools/smoke_ecosystem.py --demo http://127.0.0.1:8080
```

The smoke test expects an already running service and creates two synthetic
sessions. It drives real HTTP, consent/callback, denial, protected reads, token
rotation/revocation, cross-browser isolation, callback replay and unsigned
resource rejection. It is not a third-party interoperability test.

## Deployment contract

- `PORT`: listening port, default `8080`; binds `0.0.0.0`.
- `APP_ORIGIN`: exact externally visible HTTPS origin, no trailing slash, path,
  userinfo, query or fragment. Use its canonical spelling: lowercase hostname,
  without an explicit default port. HTTP is accepted only for localhost development.
  In that mode the app explicitly enables nonstandard HTTP-loopback discovery;
  OPTIONS responses carry `GNAP-Development-Only: insecure-loopback-discovery`.
  Public HTTPS deployments use the strict RFC 9635 discovery checks.
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
`gnap-as::AuthorizationServer`; the RS shares an application token index with
the AS and calls `gnap-crypto::verify::verify_request`. **No RFC 9767 introspection
endpoint is implemented or simulated.**

## Security and lifecycle limits

- One ephemeral 2048-bit RSA key represents the application; browser sessions
  are isolated client references, not independent cryptographic client owners.
  Restart invalidates all keys, grants and tokens. No token values appear in
  the browser or application logs.
- The visitor plays the resource owner; there is no real login, user directory,
  private document upload or identity assurance. Only a fixed read right exists.
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
key-bound requests and token lifecycle management. This is not a claim that
OAuth cannot provide consent, fine-grained access or proof-of-possession; an
honest comparison must include OAuth extensions and deployment profiles.

See [DEVELOPER_FEEDBACK.md](DEVELOPER_FEEDBACK.md) for the consumer experience
and the SDK changes this application suggests.
