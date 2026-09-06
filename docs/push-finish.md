# HTTP push finish

The delegation lab offers a real server-to-client finish callback. Choose
**Start with a server-to-client callback**, then allow or deny the request.
The browser opens the consent page, but does not carry the finish reference
back to the client. The AS sends the JSON produced by `Finish::Push` unchanged
in an HTTP POST. The client calls `Session::accept_push` to verify the hash
before signed continuation becomes available.

This demonstrates [RFC 9635 §4.2.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-4.2.2)
in one deployment, using real HTTP between roles. It is not independent-vendor
interoperability, a complete C2 profile or a general-purpose callback relay.
The selected scenario requests one document token, without identity disclosure.
After issuance, continuation closes; the token retains its own resource-access,
rotation and revocation lifecycle.

## Callback ownership and network boundary

Before requesting a grant, the client registers a random 128-bit callback ID
with this application. Each URI belongs to one client reference and is bound
to its resulting grant. It is not the browser cookie. Neither the URI nor the
callback body appears in the browser status or event list. Both initial and
continuation policy evaluation reject an unregistered destination or a URI
belonging to another client. An already bound URI cannot start a new grant,
and continuation must match its registered grant ID. This is a deliberately closed registration policy,
not an authenticated registration API for external clients.

The sender additionally requires the exact configured origin and callback path,
without URL normalization, query, fragment or credentials. For HTTPS, DNS must
return between one and sixteen addresses, all accepted by the shared
`gnap-net::public_ip` predicate. Connections use those pinned addresses while
retaining the hostname for TLS verification. Proxies, redirects, automatic
retries and connection pooling are disabled. DNS and the complete exchange fit
within four seconds; connection establishment is limited to two seconds.
Request and response bodies are bounded to 1,024 bytes. At most four outbound
deliveries run concurrently; a full admission limit refuses the attempt.

The existing explicit HTTP development configuration permits only canonical
loopback origins. In that mode the destination is a fixed loopback address;
even `localhost` is not resolved through DNS. It is not a production HTTPS
substitute. No environment variable accepts an arbitrary callback target.

## Delivery is separate from consent

Consent is committed before sending. There is one attempt, consumed once from
the private outbox. A failed request cannot undo that decision, and a browser
disconnect does not cancel an already queued attempt. Process restarts still
lose this volatile state, as they do all other demo grants.

The sender reports `delivered` only after a bounded successful HTTP response,
`refused_before_send` for a local preflight or capacity refusal, and `uncertain`
for other failures or timeouts. A timeout can hide successful receipt: the
client may have validated the callback even while the sender reports uncertain
delivery. The client's separate `received` flag describes hash validation.

The callback window lasts five minutes from local registration and is never
extended by consent, delivery attempts or malformed callbacks. The SDK also
enforces its finish deadline and the AS continuation wait period. The receiver
returns 204 for the first valid callback, 400 with `unknown_interaction` for
invalid JSON or a bad hash, and 404 with the same generic error for unknown,
expired or consumed callback URIs. Oversized bodies receive 413. Registered
callbacks share a sixty-attempt rolling minute limit; unknown IDs do not
consume it. Queue saturation and receiver timeouts return 503 without claiming
that the operation did not happen.

Refreshing `/api/status` only reads local client state. It never substitutes
AS polling for a missing finish callback. If the callback is lost, wait for
expiry or start a fresh grant. A callback validated within its window remains
usable for continuation subject to the grant's own lifetime.

## Evidence

The [transport tests](../apps/delegation-demo/src/push_finish/transport.rs)
exercise destination restrictions, full DNS address-set filtering, exact POST
bytes, redirects, bounded and chunked responses, and deadlines before and
after response headers. The [consumer tests](../apps/delegation-demo/src/push_finish/tests.rs)
exercise the real HTTP sender and receiver, approval, protected resource access,
denial, malformed and replayed callbacks, expiry and destination ownership.
The UI tests execute the actual rendering code with a DOM double, not a browser
engine. Local loopback evidence does not establish hosted TLS delivery.

The normal `--demo` smoke does not include this outbound callback path.
For an explicitly authorized deployment, run the separate push scenario:

```console
python3 -B tools/smoke_ecosystem.py --demo https://gnap-delegation.cleverapps.io --push-only
```

This creates two synthetic grants, tests approval and denial, and checks
resource access and individual revocation. It requires the deployment to
reach its own public HTTPS hostname from the AS process. A working browser
connection alone does not establish that outbound path. The script reports
only fixed check names and outcomes, not callback credentials or bodies.
