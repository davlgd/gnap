# Resource-server SDK

`gnap-rs` checks an opaque access token on a resource server. It asks an explicitly trusted authorization server about the token through authenticated introspection, then verifies the client's proof on the actual resource request. It depends neither on `gnap-as`, nor on an authorization-server store, nor on an HTTP framework.

Two other components look similar and do something else. `gnap-as::ResourceServerApi` serves the endpoints that a resource server calls on the authorization server. `gnap-biscuit::VerifiedToken::authorize` validates the Biscuit profile locally, without introspection.

## What your application supplies

- `TrustedAs`: the exact grant and introspection endpoints your deployment approves
- A `ResourceServer` identity and its signer, agreed with the authorization server
- An implementation of the `gnap-client` `HttpTransport` trait
- A `NonceMemory` that reserves replay nonces atomically
- The access entries a request needs, and an `AccessPolicy`

The SDK derives the well-known discovery address from your grant endpoint, and discovery can't replace either approved endpoint. It refuses user information in an authority, such as `user@host`. The RFC doesn't require that rule, and an `@` in a path or a query stays valid.

The resource server's signer authenticates the introspection request: it isn't the key of the incoming client. The SDK reads the client's key from the authorization server's answer, and a valid request signature alone doesn't establish the token's rights or audience.

The transport is blocking, like the client's. From an async server, call it in a bounded blocking worker rather than on the event loop, and keep the worker's capacity until the blocking work really finishes. The delegation lab shows that arrangement.

## Authorize a request

Pass the original method, absolute target URI, headers, and body to `Authorizer::authorize`, with the required access entries, your `AccessPolicy`, and a clock in Unix seconds. Reconstructing a different URL behind a proxy, or decoding and re-encoding the body, can invalidate the request's signature: build the external URI only from proxy information your deployment approves. Perform the protected operation only when `authorize` returns an `Authorized`, and on the content it carries: the body for `httpsig` and `jwsd`, and the JWS payload for `jws`, whose body is the compact JWS.

For each request, the authorizer fetches the discovery document, then sends an introspection request signed with the resource server's key. It checks the issuer and the endpoints, the response, the required rights, the public key binding, the client's signature and its replay nonce, and the token's time window. It caches neither discovery nor a positive result, so each request makes two exchanges with the authorization server: a choice of this profile, not a requirement of the RFC.

The SDK compares the required access entries with the authorization server's answer by exact inclusion. Interpreting an access entry for your resource remains your application's job: no normalization, no label-derived audience, no implicit expansion.

## Write the access policy

`AccessPolicy::validate` receives a typed `TokenInfo`: rights, issuance and expiry times, an optional `nbf`, the audience, the subject, and the client-instance identifier. It never sees a key, a token value, or the raw response. It can add limits, such as on rights or duration, and return `Denied` or `Unavailable`, but it can't override the checks of the SDK.

The policy runs before the proof is verified and the nonce consumed, so that a request refused by policy can be retried. A caller without a valid proof can therefore trigger the bounded introspection and policy work, but never a successful authorization. The policy mustn't perform the protected operation itself: being called doesn't prove that the caller is authenticated. Profile checks run before the exact rights comparison, which keeps unusable information from the server apart from insufficient permissions.

## Choose the audience policy

The authorization server and the resource server agree on audience identifiers, which the SDK never infers from a registration reference:

- `AudiencePolicy::IntrospectionContext` trusts the server's active decision, and refuses an explicit `aud`
- `AudiencePolicy::Exact(value)` requires the configured value in an `aud` string or string array

## Handle the result

`Denied` covers a malformed presentation, an inactive introspection result, missing rights, a wrong audience, an invalid time or proof, a replay, and a policy refusal. `Unavailable` covers transport errors, unusable responses, an incompatible profile, and a policy that can't decide. Neither carries an upstream body, credential, or transport message. You choose the HTTP status to return, as the delegation lab does with 401 and 503.

An inactive result can mean that the authorization server couldn't determine the token's validity, not that the token is invalid.

## Profile limits

This profile accepts key-bound requests signed with `httpsig` without parameters, with a public PS256, ES256, or Ed25519 key, and a nonempty signature nonce. After `with_jose_proofs`, given a JOSE replay memory, it also accepts the `jws` and `jwsd` proofs, with a public RS256, ES256, or Ed25519 key. The proof method is the one of the introspected key, and a request carrying another method's envelope is refused. The introspection request names `httpsig` when the request carries an HTTP signature, and no method otherwise, since the RFC recommends it without requiring it. The SDK doesn't decode the opaque token: the introspection response must carry integer `iat` and `exp` claims, with `exp` after `iat`. Requiring both dates is a choice of this SDK, not of [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.3).

Token dates get no grace period: `nbf` and `iat` are inclusive, `exp` is exclusive, and a clock that goes backwards refuses access. Three non-decreasing clock readings frame the network work and the proof verification, and the last one must still precede expiry. The signature verifier's 300-second clock-skew allowance doesn't extend a token's validity, and a failed final check can consume a valid proof's nonce.

The SDK decodes `aud`, `nbf`, `sub`, and `instance_id` strictly: `nbf` is an inclusive integer, and a negative, fractional, or null value is refused. It refuses unknown claims, although RFC 9767 permits extensions, and doesn't support bearer tokens, referenced proof keys, the `mtls` proof method, or proof parameters. The `flags` list must be absent or empty: the SDK refuses every flag, registered ones such as `durable` included. It accepts an HTTP 200 JSON response of up to 8,192 bytes with a single `application/json` content type, matched case-insensitively and with parameters allowed, which isn't a complete MIME validation. A missing `key_proofs_supported` list is accepted; a list that's present must include `httpsig`.

## Deployment responsibilities

The transport must authenticate HTTPS, keep the signed URI and bytes intact, refuse redirects, unwanted proxies, and unapproved destinations, and bound buffering, connection time, and total execution. The SDK checks its 8,192-byte limit after receipt, which can't stop an adapter from first allocating a larger body.

The replay memory must reserve nonces atomically for the whole acceptance window of the verifier. Use a shared or durable store when replicas or restart recovery are part of your guarantees: the SDK provides neither a permissive no-op store nor an in-memory default. Keep this namespace apart from the one the authorization server uses to verify introspection requests.

A revocation can race a decision already made, and the next request always gets a fresh one: the SDK reuses no positive result and retries no failure. `TrustedAs::for_local_development` allows plain HTTP on the loopback interface for local tests, as a development exception that keeps exact endpoint matching and never allows HTTP elsewhere.

## What it doesn't do

The crate doesn't introspect Biscuit tokens, register a resource server, derive downstream tokens, choose an authorization server from an untrusted request, or provide a complete production service. The delegation lab enforces stricter limits on top of it: its own rights and durations, and no additional claims. [RFC 9767 §§3.1–3.3](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.1) and [RFC 9635 §§7.2–7.3.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.2) give the protocol rules behind this profile.
