# Identity assertions in a GNAP grant

GNAP can return information about the resource owner alongside access tokens.
These serve different purposes: a subject assertion identifies a party under an
issuer; an access token authorizes a resource request. Neither substitutes for
the other. The rules are in [RFC 9635 §3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.4),
which refers to the [OpenID Connect ID Token format](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

`gnap-subject` supplies a bounded PS256 issuer and verifier. It does not implement
an OpenID Provider, OpenID Connect discovery, JWT access tokens or encrypted
assertions. `gnap-types::Assertion::issuer_subject` remains a decoding helper
for consistency checks; it must not authenticate a user.

## Trust belongs to the application

Configure an exact GNAP grant endpoint, an exact HTTPS issuer and that issuer's
dedicated public assertion key together, using `gnap_subject::Trust`. Do not
build this configuration from a received JWT. The library permits a separately
configured issuer at another origin; that is an explicit trust decision, not a
discovery result. The demo uses its own HTTPS origin as issuer.

The client convenience method `Session::verify_subject` is available for a
`Ps256Signer`. It checks the retained subject response using:

- the actual endpoint contacted by the session;
- the SHA-256 [RFC 7638 thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
  of its original HTTP proof key as audience;
- its retained interaction finish nonce as the assertion nonce;
- the caller's current time and configured assertion lifetime/age limits.

The audience and nonce mappings are **project conventions**, agreed by this
AS and client. GNAP does not define an OAuth `client_id` or require either
mapping. A polling-only session without a finish nonce cannot use this
convenience method. Rotating a resource token's key does not change the
original grant key or assertion audience.

On success, the client returns only checked identity and time claims, together
with the responding AS endpoint. Use the complete `(AS endpoint, issuer,
subject)` attribution when identifying an account. An email or an opaque value
alone is not a globally unique account key, a contact address or a credential.
Recheck an assertion at the time of use; the result records expiration but is
not an automatically expiring application login session.

## Selected verification profile

The verifier checks the exact compact JWS signature before interpreting claims.
It accepts only PS256 with a pinned 2048–4096-bit RSA key, and caps the compact
assertion at 8192 bytes. Duplicate top-level JSON members, malformed encodings,
critical JOSE extensions and JWT-supplied key material or URLs are refused.
No keys are fetched during validation. A present `kid` must match the pinned
verifier; a PEM import therefore needs `with_key_id` when the token carries one.
An absent `kid` can use the single configured key.

Required claims are `iss`, `sub`, `aud`, `nonce`, `iat`, `exp` and `auth_time`.
This profile requires integral, nonnegative Unix seconds; `auth_time` may not
follow `iat`, and `exp` must follow it. A subject has 1–255 ASCII characters.
The audience must contain only the configured client identifier. If supplied,
`azp` must identify that same client, and `nbf` must not be in the future beyond
the configured clock tolerance. Tolerance is capped at 300 seconds.
`max_age` bounds both assertion age and issued lifetime; it is **not** the
OpenID Connect authentication-request parameter of that name and does not
enforce recent user authentication.

`Trust::verify_subject` requires exactly one assertion. Every accompanying
`iss_sub` identifier must exactly match the verified `(iss, sub)`. This is
stricter than GNAP, which allows different identifiers if they represent the
same party. Other formats, including `opaque`, are not independently verified
or returned as verified claims. Their relationship to the identity is the AS
policy's responsibility, not something a signature check can discover.

Unknown noncritical claims are ignored and not exposed as trusted data.
Returned errors and the verified identity's debug representation omit claims,
nonces and token values. Applications must apply the same care when logging
raw GNAP wire messages.

## Release and demonstration boundaries

The existing AS `ReleasedSubject` policy boundary remains mandatory. Issuing
a valid signature does not establish that the end user and resource owner are
the same person. The policy must establish a release ground and authorize the
requested disclosure. Assertions sent by a client are only untrusted hints;
this profile does not let them bypass consent.

The delegation demo's identity option illustrates explicit consent for one
fictional owner and this application's shared proof key. Identity disclosure
is restricted to enrolled demo client references: a by-value
client key or another key impersonating a reference is refused. Its dedicated
assertion key and opaque identifier are generated in memory, not loaded from
test fixtures. They change on restart. This is not real user authentication,
general pairwise-identifier management, persistent account linking or an
independent-vendor interoperability test. Its identity grant closes after
issuance; the ID Token is never presented to a resource server.

## Evidence

The [assertion tests](../crates/gnap-subject/tests/id_token.rs) cover issuance,
pinned keys, hostile headers/claims, time boundaries, encoding, size and
identity consistency. The [client tests](../crates/gnap-client/tests/flow/subject_assertions.rs)
exercise endpoint, key and nonce binding through the real session state
machine with a scripted transport. They do not exercise a network or establish
full C1/C2 profile conformance.

The [demo tests](../apps/delegation-demo/src/identity/tests.rs) drive its actual
AS policy and client through an in-memory transport: consent and refusal,
closed continuation, wrong recipients and key impersonation, disclosure and
expiry. This is executable integration evidence, not a deployed HTTPS or
browser-engine identity test.
