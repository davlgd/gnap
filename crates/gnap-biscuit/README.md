# GNAP Biscuit file profile

This crate issues real Biscuit tokens, lets their holders attenuate them locally,
and verifies GNAP HTTP Message Signatures before authorizing file requests. It
implements the application profile `gnap-biscuit-file-v1`, not the whole Biscuit
language or every GNAP token capability.

Run the in-process token-issuance and resource-authorization example with:

```console
cargo run -p gnap-biscuit --example file_access --locked
cargo test -p gnap-biscuit --locked
```

The example creates fresh root and PS256 client keys, issues one read right,
adds resource and deadline checks, signs the attenuated token's request, accepts
it, then revokes its parent and rejects a freshly signed descendant request.
It has no HTTP server or live deployment. Its in-memory live callback checks
revocation and reserves nonces for its single configured client key. Both its reservation set
and local nonce filter are limited to that single process and short run.
It uses `gnap_client::sign_request` for fresh signature nonces, but does not run
the `gnap-as` grant flow or the `gnap-client` session API.

## Access and proof contract

Each `FileRight` is one exact HTTP(S) resource URI paired with `read` (GET) or
`write` (PUT). URI strings are never normalized. Fragments and embedded
credentials are rejected. A GNAP access description uses this profile's exact
`type`, one `locations` value and one `actions` value; every other dimension,
extension, reference or unknown action is rejected. Multiple rights remain a
union of pairs: read A plus write B never grants write A or read B.

These URI checks validate syntax, not network transport. HTTP strings are
accepted so local examples can describe their endpoints; this is not an HTTPS
exception in GNAP. A hosted adapter must require HTTPS for public GNAP endpoints
and reconstruct the public request URI correctly behind TLS termination.

The authority block contains exactly these singleton facts, plus 1–32 distinct
`right(resource, action)` facts:

| Fact | Value |
| --- | --- |
| `gnap_profile` | `gnap-biscuit-file-v1` |
| `gnap_issuer` | Configured AS grant URI |
| `gnap_audience` | Configured RS URI |
| `gnap_jwk` | JSON string containing the complete public PS256 JWK |
| `gnap_proof` | `httpsig` |
| `gnap_iat` | Integer Unix issuance time |
| `gnap_exp` | Integer Unix exclusive expiry time |

Times must fit a nonnegative signed 64-bit integer, with issuance before expiry.
The root key ID is required in the Biscuit envelope and resolved only from a
locally configured key map. No URL, certificate or token claim triggers a fetch.
The complete client JWK is validated by `gnap-crypto`: matching a `kid` alone
does not establish possession of the RSA key.

An added block contains one or two checks of these exact forms only:

```text
check if resource("https://files.example/notes/demo.txt");
check if time($now), $now < 1800000000;
```

Checks intersect; even a later, more generous deadline cannot undo an earlier
one. The client's key and authority rights do not change. Added facts, rules,
explicit trust scopes, third-party blocks and arbitrary expressions are
rejected, including otherwise valid Biscuit features. This prevents authority
claims from being confused with facts contributed by a holder. The authorizer
uses request-derived resource/action facts and an authority-trusting allow rule.

`VerifiedToken` is not an authorization decision. On each `authorize` call it
requires exactly one `Authorization: GNAP <value>` matching its own encoded token
value, then verifies the actual request and its proof coverage. Signing a parent
while presenting a descendant, or vice versa, fails. This profile requires a
nonce. The caller must supply an atomic, correctly scoped nonce store; follow
the retention requirements in `gnap_crypto::NonceMemory`.
The nonce requirement participates in signature selection: a nonce-less first
signature does not hide a later signature that satisfies the profile.

The authentication scheme is case-insensitive and accepts HTTP's one-or-more
space separator. The encoded token itself remains an exact, case-sensitive
comparison, including any final base64 padding.

The caller independently configures expected issuer and audience. A fallible
clock is read before proof verification and again after evaluation and the live
decision. The final check rejects backwards time, expired authority or
attenuation deadlines, and signatures that became stale during processing.
Applications must use the authorization result immediately for the same request;
it is not a capability to cache or reuse for another operation.

## Revocation and boundaries

The mandatory callback receives `(&[Vec<u8>], &gnap_biscuit::ReceivedParams)`:
Biscuit's native revocation identifiers for every block, including all ancestors,
and the authenticated parameters of the signature actually accepted. It runs
after cryptographic and Datalog checks. A rejected first signature never supplies
its nonce or timestamp to this decision; applications must not reparse the first
signature header to reconstruct those parameters.

The callback returns `LiveDecision::Allowed`, `Denied` or `Unavailable`. `Denied`
covers both revocation and a refused central one-use nonce reservation, and maps
to `Error::Denied`. Unknown state must return `Unavailable`. The callback receives
no access token. Its authenticated parameters let a deployment combine live
revocation checks with an atomic, correctly scoped central replay decision.
Scope a shared reservation store by the trusted resolved client key, not by
the `keyid` string alone: different keys can use the same identifier, and the
same key can be configured under more than one identifier.

The local nonce memory remains the first replay filter. On its own, a volatile
store loses protection when the RS restarts; durable/shared state or a central
one-use decision must retain that protection for the full signature acceptance
window. This crate supplies the callback boundary, not that persistent service.
It caches no positive decision. A proved nonce or central reservation may be
consumed even if a later availability or final-clock check denies access.

A deployed RS needs an authenticated, current revocation channel and must retain
state at least through the corresponding token lifetime. The callback is only
an integration boundary, not an implementation of GNAP introspection. Local
attenuation is also **not** [RFC 9767 downstream token derivation](https://www.rfc-editor.org/rfc/rfc9767.html#section-4):
that flow asks an AS for a new token bound to the requesting RS for another RS.
Local attenuation here preserves the original client key. This crate does not
implement that exchange, mTLS, JWTs, token management or AS grant policy.

## Resource limits and dependencies

`inspect` performs bounded decoding and profile checks without signature
verification or Datalog evaluation. Its result is unauthenticated. The same
preflight runs before `VerifiedToken` invokes Biscuit verification.

- At most 16 KiB decoded token bytes; the encoded length is capped before decode.
- At most 16 blocks including authority; block format version 3 only.
- At most 39 authority facts (7 singletons and 32 rights), no authority checks,
  and no facts or rules in added blocks; at most 2 checks per added block.
- At most 128 custom symbols across the token, 4096 bytes per symbol, and
  2048 bytes per resource, issuer or audience URI.
- Only expected scalar terms: at most two terms per authority fact, one body
  predicate/term per check, and exactly three operations for a deadline.
  Nested terms, closures, external calls and arbitrary expressions are refused.
- Explicit Datalog limits: 128 facts, 10 iterations and 20 ms.

The protobuf decoder's own recursion limit remains enabled. Byte bounds apply
before protobuf parsing; counts and term restrictions are checked after bounded
decoding and before conversion/evaluation. Datalog time limits are checked by
the engine and **are not hard preemption**. A network service must bound ingress,
worker count and queue length, and hold its worker permit until execution really
finishes; a response timeout alone does not stop CPU work. TLS, request-body
limits, canonical reverse-proxy URI reconstruction and persistent nonce and
revocation storage belong to that service.

This uses the published `biscuit-auth = 6.0.0` with defaults disabled and
`regex-full,datalog-macro` enabled. The macro feature is used for parameter-bound
checks and also avoids a reproduced missing `ToAnyParam` import in the release
when that feature is disabled. The upstream `regex-full` feature is enabled
explicitly; this profile still rejects regex checks. `prost 0.10` matches the release's
generated schema and permits inspection before evaluation. No unpublished git
revision is used. The workspace lock keeps dependencies compatible with Rust
1.85. Upstream's `proc-macro-error2 2.0.1` emits a future-compatibility warning;
it is not suppressed or described as a demonstrated runtime vulnerability.

The tests exercise native chains and real RSA signatures. They cover tampering,
root selection, same-`kid` key substitution, exact token presentation, live
revocation, deadlines, rights correlation and structural rejection of hostile
blocks. They are regression/self-interop tests, not independent certification.
Public RSA fixture provenance is recorded in `gnap-crypto/tests/README.md`.

Protocol references: [GNAP key formats](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.1),
[GNAP HTTP signatures](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.1),
[Biscuit specifications](https://doc.biscuitsec.org/reference/specifications.html),
and [Biscuit Datalog trust rules](https://doc.biscuitsec.org/reference/datalog.html).
