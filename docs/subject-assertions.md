# Identity assertions in a GNAP grant

GNAP can return information about the resource owner alongside access tokens, and the two serve different purposes: a subject assertion identifies a party under an issuer, while an access token authorizes a resource request. Neither replaces the other. [RFC 9635 §3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.4) gives the rules, and refers to the [OpenID Connect ID Token format](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

`gnap-subject` issues and verifies PS256-signed assertions within a bounded profile. It doesn't implement an OpenID Provider, OpenID Connect discovery, JWT access tokens, or encrypted assertions. `gnap-types::Assertion::issuer_subject` only decodes an assertion for consistency checks, and must never authenticate a user.

## Configure the trust

Pair an exact GNAP grant endpoint, an exact HTTPS issuer, and that issuer's dedicated public assertion key in a `gnap_subject::Trust`, and never build this configuration from a received JWT. The issuer can sit at another origin than the authorization server, as an explicit trust decision rather than a discovery result. The delegation lab uses its own HTTPS origin as issuer.

## Verify from a client session

When its signer exports a public JWK, `Session::verify_subject` checks the subject response the session retained, using:

- The endpoint the session actually contacted
- The SHA-256 [RFC 7638 thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html) of its original proof key, of any algorithm, as audience
- Its interaction finish nonce, as the assertion nonce
- Your current time, and your limits on lifetime and age

The audience and nonce mappings are **conventions of this project**, which its authorization server and client agree on: GNAP defines no OAuth `client_id`, and requires neither mapping. A session that only polls, without a finish nonce, can't use this method. Rotating the key of a resource token changes neither the grant key nor the audience of the assertion.

On success, the client returns the checked identity and time claims, with the endpoint of the authorization server that answered. Identify an account by the whole `(AS endpoint, issuer, subject)` triple: an email or an opaque value alone isn't a globally unique account key, a contact address, or a credential. Recheck an assertion when you use it: the result records its expiry, but isn't a self-expiring login session.

## Verification profile

The verifier checks the compact JWS signature before it reads any claim. It accepts only PS256, with a pinned RSA key of 2048 to 4096 bits, and assertions of up to 8,192 bytes. It refuses duplicate top-level JSON members, malformed encodings, critical JOSE extensions, and key material or URLs supplied by the JWT, and fetches no key. A `kid` that's present must match the pinned verifier, so import a PEM key with `with_key_id` when the tokens carry one; without a `kid`, the single configured key applies.

The required claims are `iss`, `sub`, `aud`, `nonce`, `iat`, `exp`, and `auth_time`, and the three dates are nonnegative integer Unix seconds. `auth_time` can't follow `iat`, and `exp` must follow it. A subject has 1 to 255 ASCII characters, and the audience must contain only the configured client identifier. A supplied `azp` must name that same client, and a supplied `nbf` can't be in the future beyond the clock tolerance, which is capped at 300 seconds.

`max_age` bounds both the age of an assertion and its issued lifetime. It isn't the OpenID Connect authentication-request parameter of the same name, and doesn't enforce a recent user authentication.

`Trust::verify_subject` requires exactly one assertion, and each accompanying `iss_sub` identifier must match the verified `(iss, sub)` exactly. That's stricter than GNAP, which allows different identifiers for the same party. Other formats, `opaque` included, aren't verified or returned as verified claims: their link to the identity is a policy decision of the authorization server, which no signature check can discover.

The verifier ignores unknown noncritical claims, without exposing them as trusted data. Errors, and the debug output of a verified identity, leave out claims, nonces, and token values; apply the same care when you log raw GNAP messages.

## Release the identity

The authorization server's `ReleasedSubject` policy stays mandatory. A valid signature doesn't establish that the end user and the resource owner are the same person: the policy must establish a ground for release and authorize the requested disclosure. Assertions that a client sends are untrusted hints, which can't bypass consent in this profile.

The identity option of the delegation lab shows explicit consent for one fictional owner and the lab's shared proof key. It discloses identity only to enrolled client references, and refuses a client key sent by value or a key that impersonates a reference. Its assertion key and opaque identifier are generated in memory at startup, not loaded from test fixtures, and change on restart. The identity grant closes after issuance, and the ID Token never reaches a resource server.

This option isn't user authentication, a pairwise-identifier service, account linking, or independent interoperability.

## Evidence

The [assertion tests](../crates/gnap-subject/tests/id_token.rs) cover issuance, pinned keys, hostile headers and claims, time boundaries, encoding, size, and identity consistency. The [client tests](../crates/gnap-client/tests/flow/subject_assertions.rs) check the binding to the endpoint, key, and nonce through the real session state machine and a scripted transport, without a network, and don't establish full conformance to the C1 or C2 profile.

The [lab tests](../apps/delegation-demo/src/identity/tests.rs) drive its real authorization-server policy and client through an in-memory transport: consent and refusal, closed continuation, wrong recipients and impersonated keys, disclosure, and expiry. That's executable integration evidence, not an identity test over deployed HTTPS or in a real browser engine.
