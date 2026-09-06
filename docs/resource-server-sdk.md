# Building a resource server with the SDK

`gnap-rs` supplies the resource-server side of the opaque-token path. It checks
the presented credential through an explicitly trusted AS, then verifies the
client's proof on the actual resource request. It has no production dependency
on `gnap-as`, an AS token store or an HTTP framework.

This is distinct from `gnap-as::ResourceServerApi`, which serves the AS endpoints
called by an RS. It is also distinct from `gnap-biscuit::VerifiedToken::authorize`,
which validates the selected Biscuit profile locally. Adding an introspection
consumer does not make introspection mandatory for Biscuit.

## What an application supplies

- `TrustedAs`: the exact grant and introspection endpoints approved for this
  resource. The SDK derives the well-known discovery address from that configured
  grant endpoint. Discovery cannot replace either approved endpoint.
  Embedded username/password information is refused by this SDK profile.
- A `ResourceServer` identity and its signer, agreed with the AS. This signer
  authenticates introspection; it is not the incoming client's key.
- An existing `gnap-client::HttpTransport` implementation. It must authenticate
  HTTPS, retain the signed URI and bytes, refuse redirects and unwanted proxies,
  constrain destinations, and bound time and response buffering. The SDK checks
  its own 8 KiB JSON limit after receipt; that is not a network streaming limit.
- `NonceMemory` with atomic replay reservations for the accepted signature
  window. Use a shared or durable implementation if replicas or restart recovery
  are part of the deployment guarantee. The SDK does not supply a permissive
  no-op implementation or silently choose an in-memory production store.
- Required access entries and an `AccessPolicy`. The application decides what
  those entries mean for its resource. The SDK requires a nonempty list and
  exact inclusion in the AS response, not a general semantic comparison of
  arbitrary structured access objects.

The transport is blocking, like the existing client transport. An async server
should call it from a bounded blocking worker, not block its event loop. The
delegation lab is an executable example of that arrangement.

## The authorization boundary

The application passes the original method, absolute target URI, headers and
body to `Authorizer::authorize`. Reconstructing a different URL behind a proxy
or decoding and re-encoding the body can invalidate the request's signature.
Only construct that external URI from deployment-approved proxy information.

For each resource request, the authorizer fetches discovery and makes a signed
introspection call with the RS's own key and the presented token. It validates
the exact issuer and endpoints, the response shape, required rights, the public
PS256 key binding, the client's HTTP signature and replay nonce, and the token's
time window. Neither discovery nor positive authorization is cached. Two AS
exchanges per resource request are a deliberate profile choice, not an RFC
requirement. Revocation can race an already completed introspection decision;
the next request always obtains a fresh one.

The application policy receives a typed `TokenInfo`, without the token value,
key or raw response. It may impose additional limits on rights, duration or
the AS's subject and client-instance claims. It can only refuse: returning
`Ok(())` cannot bypass the SDK's proof, trust, time or required-right checks.
The policy runs before proof verification and nonce consumption, preserving
the ability to retry a request refused by local policy. A caller without a
valid proof can therefore trigger this bounded introspection and policy work,
but cannot obtain a successful authorization.
The policy must not perform the protected operation itself: invocation does
not prove that the caller is authenticated. Only the authorizer's final
`Ok(())` permits that operation.

`Denied` and `Unavailable` contain no upstream body or credential. The
application chooses its HTTP response; the demo uses 401 and 503 respectively.
An inactive introspection response may mean the AS could not determine validity.
It does not establish that the token is intrinsically invalid.

## Selected profile and limits

This first reusable authorizer accepts key-bound PS256 HTTP signatures and
requires `iat` and `exp`, with `exp > iat`. Requiring both dates is this SDK
profile's choice, not a requirement of RFC 9767. Token dates have no grace
period: `nbf` and `iat` are inclusive, `exp` is exclusive, and clock rollback
refuses access. The 300-second signature clock-skew allowance does not extend
token validity. Successful authorization checks time again after proof
verification; a late refusal may already have consumed the nonce.

Audience identifiers are agreed between the AS and RS, not inferred from an
RS registration reference. `AudiencePolicy::Exact` requires the configured
identifier in an `aud` string or string array. `IntrospectionContext` instead
relies on the AS's active decision for the authenticated RS and requested
rights; it accepts an omitted audience but refuses any explicit `aud`.

`aud`, `nbf`, `sub` and `instance_id` are decoded strictly. Unknown additional
claims are refused by this profile, although RFC 9767 permits extensions.
Bearer tokens, referenced client proof keys, other proof methods, unknown flags
and parameterized proof methods are not supported by this authorizer. The demo
adds stricter limits: its established rights and durations, and no additional
claims. Its document, report and downstream metadata scenarios retain those
application-specific policies.

HTTP loopback requires the separate `TrustedAs::for_local_development`
constructor. It is an explicit development deviation, not a production TLS
exception. This crate does not register an RS, derive downstream tokens, select
an AS from an untrusted request, or provide a complete production RS service.
