# gnap-subject

Issue and verify the PS256-signed `id_token` assertions that a GNAP subject response carries ([RFC 9635 §3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.4)). The crate reuses the RSA-PSS implementation of `gnap-crypto`, and isn't an OpenID Provider.

Add it with `cargo add gnap-subject`. Its [API documentation](https://docs.rs/gnap-subject) is on docs.rs.

## Verify a subject response

Configure a `Trust` that pairs the authorization server's grant endpoint, the issuer, and the issuer's public key, then call `Trust::verify_subject` on the response. The key comes from your configuration, never from the JWT. The verifier checks the signature, issuer, audience, session nonce, and time bounds before it returns an identity, and its errors contain no claim or token value.

From a client, `gnap-client::Session::verify_subject` derives the audience and the nonce from the session itself. Parsing an assertion with `gnap-types` alone performs none of these checks.

## Limits of the profile

The profile requires integer `iat`, `exp`, and `auth_time` claims, an explicit session nonce, a single trusted audience, and an RSA key of 2048 to 4096 bits. A `kid` in the assertion must match the pinned key's identifier: import it with the public JWK, or set it with `with_key_id` for a PEM key. Encrypted assertions, other algorithms, and keys supplied by the token are refused.

An assertion isn't an access token, and its claims mean only what the issuer's identity and release policy establish. The [identity guide](https://github.com/davlgd/gnap/blob/main/docs/subject-assertions.md) explains the trust configuration, the client conventions, the release policy, and every limit.

```bash
cargo test -p gnap-subject --locked
```

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
