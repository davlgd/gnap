# GNAP subject assertions

This crate issues and verifies PS256-signed `id_token` assertions carried in
GNAP subject responses. It reuses the workspace's RSA-PSS implementation; it
does not implement a second cryptographic primitive or an OpenID Provider.

The issuer key is supplied by trusted configuration, never by the JWT. The
verifier checks the issuer, audience, expected session nonce and time bounds
before returning an identity. Errors do not contain claims or token values.
Parsing an assertion with `gnap-types` alone does not perform these checks.
When an assertion carries `kid`, it must match the pinned verifier's identifier.
Import that identifier with its public JWK, or configure it with `with_key_id`
when importing a PEM public key. An unidentified PEM key does not accept a
received key identifier merely because its signature happens to verify.

The selected profile requires integral-second `iat`, `exp` and `auth_time`, an
explicit session nonce and one trusted audience. RSA keys must contain
2048–4096 bits. Extra audiences are not trusted implicitly. It does
not accept encrypted assertions, other signing algorithms or self-supplied keys.
Unknown non-critical claims are ignored rather than exposed as verified data.

An assertion is not an access token. Its issuer, subject and authentication time
only mean what the configured issuer's identity and release policy establish.
Applications must retain the GNAP AS attribution, authorize the release of
subject information and bind the expected nonce to the relevant grant.

Use `Trust::verify_subject` to check an entire response against an explicitly
paired AS endpoint, issuer and key. It accepts one assertion and requires each
`iss_sub` identifier to match; opaque identifiers remain the issuer's policy
responsibility. `gnap-client::Session::verify_subject` derives audience and
nonce from the actual session under the documented project convention.
See the [profile and integration guide](https://github.com/davlgd/gnap/blob/main/docs/subject-assertions.md) for
the release policy, context binding, limits and demonstration boundaries.
