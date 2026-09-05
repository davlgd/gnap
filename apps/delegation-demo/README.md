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
  userinfo, query or fragment. HTTP is accepted only for localhost development.
- Binary: `gnap-delegation-demo`; readiness: `GET /health`.
- Clever Cloud: use this app directory as `APP_FOLDER`, a **Build M** instance,
  and exactly one runtime instance. Set `APP_ORIGIN` to its public HTTPS origin.
  The crate has its own `[workspace]` and lockfile; path dependencies require
  the complete repository to be present during build.

The app reconstructs signed target URIs from the configured origin and actual
request target, never from untrusted `Forwarded`/`X-Forwarded-*` headers. Outbound
HTTP only reaches that fixed origin and the protocol's known paths, disables
redirects and environmental proxy configuration, and limits response size/time.

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
  A single client worker serializes session operations; a slow HTTP request can
  hold up all sessions until its 10-second timeout. It is intentionally a bounded
  demonstration, not a throughput benchmark.
- Sessions, application grants and resource access last at most 20 minutes
  from their creation/update; application stores are swept every 30 seconds.
  The RS enforces its own 20-minute token deadline. The current AS SDK does
  **not** advertise `expires_in`; this is a documented application policy, not
  evidence of an SDK expiration feature. Rotation gives the new stored token
  a new deadline. Session expiration also removes the accepted client reference.
- Token lookup, live-state check, signature verification and authorization are
  serialized with index updates. A completed revocation cannot be bypassed by a
  subsequent resource read. AS/RS replay caches are separate.
- Request/response bodies are limited to 64 KiB. State is in-memory only; there
  is no durable store, horizontal scaling, rate-limit fairness guarantee or
  production abuse protection. Never deploy this as a real authorization service.

GNAP capabilities demonstrated here are negotiated interaction/continuation,
key-bound requests and token lifecycle management. This is not a claim that
OAuth cannot provide consent, fine-grained access or proof-of-possession; an
honest comparison must include OAuth extensions and deployment profiles.

See [DEVELOPER_FEEDBACK.md](DEVELOPER_FEEDBACK.md) for the consumer experience
and the SDK changes this application suggests.
