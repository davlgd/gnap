# gnap-rs

An opaque-token resource server for GNAP, without an authorization-server store
or a prescribed HTTP runtime. It builds on the existing GNAP client transport,
request signer, PS256 JWK importer and HTTP Message Signature verifier.

`Authorizer` makes an authenticated introspection request with the RS's key,
then verifies the incoming resource request with the client key returned by
the trusted AS. Those keys serve different roles. A valid request signature
alone does not establish the token's rights or audience.

## Integrating a resource endpoint

1. Configure `TrustedAs::new(grant_endpoint, introspection_endpoint)` with exact
   HTTPS endpoints approved by the deployment. The standard RS discovery URL
   is derived from the grant endpoint. Discovery cannot replace either pin.
   Authority userinfo is refused by this SDK; `@` in a path or query is not
   userinfo and remains valid. This restriction is not an extra RFC URL rule.
2. Supply the preregistered `ResourceServer` identity and corresponding signer,
   an `HttpTransport`, and atomic incoming-request `NonceMemory`.
3. Select `AudiencePolicy::IntrospectionContext` when the AS's active decision
   for this authenticated RS and requested rights establishes audience. This
   mode accepts only omission of `aud`. Alternatively, `Exact(value)` requires
   a string or string-array `aud` containing that exact configured value. The
   SDK never infers an audience from a registration reference.
4. Call `authorize` with the actual request, nonempty required rights, an
   application `AccessPolicy`, and a Unix-seconds clock. Only `Ok(())` permits
   the application operation.

`AccessPolicy::validate` receives typed rights, issuance and expiration times,
optional `nbf`, audience, subject and client-instance identifier. It receives
neither keys nor raw token values. The policy may return `Denied` or
`Unavailable`; it cannot override the SDK's checks. It runs before client proof
verification and nonce reservation, so it must not perform the protected
operation or treat invocation as proof that the caller is authenticated.
Application profile checks run before exact required-right membership, preserving
the distinction between unusable AS information and insufficient permissions.

The application remains responsible for interpreting its own access descriptions.
Exact JSON membership is deliberately not a universal GNAP rights calculus.
There is no automatic normalization, label-derived audience or implicit expansion.

## Profile and failure boundary

Every successful authorization performs discovery GET and introspection POST;
neither result is cached. The SDK accepts HTTP 200 JSON responses up to 8,192
bytes, with exactly one `application/json` Content-Type field. Media type matching
is case-insensitive and permits parameters; it is not exhaustive MIME validation.
Omitted `key_proofs_supported` is accepted; a supplied list must include `httpsig`.

This profile requires a public PS256 JWK, parameter-free `httpsig`, a nonempty
signature nonce, and mandatory integer `iat`/`exp` with `exp > iat`. Token time has
no skew allowance. Three monotonically nondecreasing clock reads bracket network
work and proof verification; the final reading must still precede expiration.
The signature verifier allows 300 seconds of clock skew.

The optional introspection fields `aud`, `nbf`, `sub` and `instance_id` are
strictly decoded. `nbf` is an inclusive integer Unix timestamp; negative,
fractional and null values are refused. Unknown active-response extensions,
nonempty flags, bearer tokens, key references and proof parameters are outside
this profile. These restrictions are SDK choices, not extra RFC requirements.

`Denied` covers malformed presentation, inactive introspection, missing rights,
wrong exact audience, invalid time/proof, replay and policy refusal. An inactive
response can mean the AS could not determine validity; it is not proof that the
token is intrinsically invalid. `Unavailable` covers transport errors, unusable
responses, profile incompatibility and policy-reported inability to decide.
Diagnostics contain no token values or underlying transport messages. The caller
chooses the HTTP response; the crate does not require a particular framework.

## Deployment responsibilities

The transport must authenticate HTTPS, preserve signed bytes, refuse redirects
and unapproved destinations, and bound buffering, connection duration and total
execution. The SDK's post-receipt size check cannot prevent an adapter from first
allocating an oversized body. Async applications should retain bounded-worker
capacity until blocking work really finishes.

Replay memory must reserve nonces atomically and retain them for the verifier's
complete acceptance window. Provide persistence or shared state when accepting
requests across restarts or replicas. Do not share this incoming-resource replay
namespace with the AS's verification of RS introspection requests.

`TrustedAs::for_local_development` separately permits HTTP loopback for local
testing. This is a development deviation, not an RFC exception. It leaves exact
endpoint matching in place and never permits HTTP on arbitrary hosts.

A revocation can race delivery after the AS's decision. No positive result is
reused for a later request, and no failure automatically retries. A failed final
clock check can leave a valid proof's nonce consumed.

This crate does not introspect Biscuit tokens or replace `gnap-biscuit`'s local
validation, attenuation and live-decision contract. It supplies no registration
or derivation client, dynamic trust discovery, bearer mode, or persistent store.
See [RFC 9767 §§3.1–3.3 and 6.2–6.4](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.1)
and [RFC 9635 §§7.2–7.3.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.2)
for the protocol rules behind this bounded profile.

## Verification

The crate's signed-request tests use scripted AS responses without `gnap-as`.
They cover trust substitution, proof/key separation, replay, clocks, audiences,
policy refusal and unusable HTTP responses. The delegation demo consumes this
API over real HTTP; those consumer tests are separate evidence, not independent
implementation certification. Rust 1.85 is the minimum supported version.

```console
cargo test -p gnap-rs --locked
cargo clippy -p gnap-rs --all-targets --locked -- -D warnings
```
