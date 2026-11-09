# Changelog

This file lists the changes to the published crates that affect their users, crate by crate, with what you need to change. The crates aren't released yet, so every change sits under *Unreleased*, and the versions follow [semantic versioning](https://semver.org/) from the first release.

## Unreleased

### gnap-client

**Breaking:** `Session<'a, T, S>` becomes `Session<T, S>`, and owns its transport and its signer. A call such as `Session::new(&transport, &signer, endpoint)` keeps compiling. Where you named the type, write `Session<&Transport, &Ps256Signer>`, or pass an `Arc` to keep a session in long-lived state.

**Breaking:** `Session::rotate_key` takes the replacement signer as a `SharedSigner`, which is an `Arc<dyn Signer + Send + Sync>`, and `Session::rotate_key_owned` is gone. The replacement must therefore be `Send + Sync + 'static`, so that a session can move between threads: move the new signer into the `Arc`, or wrap a reference that lives for the whole program.

**Breaking:** a response must carry exactly one `Content-Type` field naming `application/json`, as RFC 9635 §3 requires: the session refuses a missing field.

**Breaking:** a session drives one grant: once the session has accepted a GNAP answer to a start, another `Session::start` is refused before anything is sent, since it would replace the local state of a grant the AS holds. An inconclusive start, lost at the transport or answered unusably, restores the local state and can be tried again, though the AS may already have created a grant, so that a retry can create a second one. Start another grant in a new session.

A session proves its requests with the method its `client.key` declares: `httpsig` as before, or `jws` and `jwsd`, for which the proof takes no parameters, the JWK has to import as a public key with the signer's `alg` and `kid`, and the first request's proof has to verify under it before it leaves. A key named by reference keeps `httpsig`. `rotate_key` changes such a key with nested JOSE proofs, which it checks under the current and the new JWK before sending, and `sign_request` keeps proving with `httpsig`.

`HttpTransport` is implemented for `&T`, `Box<T>`, and `Arc<T>`. `Session::verify_subject` takes a signer of any supported algorithm, requiring `S: JwkSigner` instead of `Borrow<Ps256Signer>`, and a key change accepts a public PS256, ES256, or Ed25519 JWK.

### gnap-as

**Breaking:** `Nonces::next` returns `Result<String, NonceError>`, so an implementation wraps its value in `Ok`. When a draw fails, no partial grant or token state is published: grant, continuation, and management requests get a 500, a resource registration a 503, and an interaction completion an `InteractionError`. A nonce reserved by the request's proof stays consumed, and `OsNonces` no longer panics.

**Breaking:** `Decision::Approve` applies to a request for one token or for none. When the request holds several, the server refuses it as a configuration fault: select them with `Decision::ApproveTokens`. A request for no token, which asks only for subject information, gets no token, and an approval that grants it rights, or releases neither a token nor a subject, is refused too.

**Breaking:** a grant, continuation, or management request that carries a body and a repeated `Content-Type` field is refused.

**Breaking:** a grant request with an unknown user reference is first authenticated: one whose proof fails gets `invalid_client`, and `Policy::recognises_user` runs only after the proof, as no policy callback runs before it.

`AuthorizationServer::with_jose_proofs` accepts the `jws` and `jwsd` proofs for grant, continuation, and token management requests, for a client key sent by value as a JWK, and announces them in discovery. Such a proof has to verify under both the key the resolver approves and the JWK, whose thumbprint scopes its replay protection, and the server reserves it in a store implementing the new `JwsReplayStore` trait, which `MemoryStorage` does, holding at most `MAX_JWS_PROOFS` proofs. A key change of a token bound to a JOSE key, after `with_key_rotation`, carries the nested proofs of RFC 9635 §7.3.3.1 and §7.3.4.1: the previous key's and the new key's both verify, and are reserved together, and a proof cut from the request fails rather than rotating the value. `KeyResolver::resolve_token_key` accepts by default a parameterless `jws` or `jwsd` key that `PublicKey::for_jws` imports. `handle_grant_with_derivation` serves an attached JWS within `MAX_GRANT_BODY_BYTES` as an ordinary grant request.

`OsNonces` draws each symbol from a 64-character alphabet, without the bias of the former 62-character one. The `Debug` output of `MemoryStorage` shows counts only, and that of a stored record hides its continuation and management credentials, nonces, interaction handle and references, and user code. `MAX_GRANT_BODY_BYTES` names the body bound of the derivation and key-rotation handlers; the HTTP adapter still bounds ordinary grant requests. The default token-key resolution, the resource-server registry, the derivation handler, and a key change accept public ES256 and Ed25519 JWKs as well as PS256 ones. A key change checks these built-in algorithms early, and leaves a JWK of any other algorithm to the configured resolver.

### gnap-crypto

**Breaking:** every `Ps256Signer` and `Ps256Verifier` constructor refuses an RSA modulus outside 2,048 to 4,096 bits, the PEM imports and `Ps256Signer::generate` included.

**Breaking:** `PublicKey` has an `Rs256` variant and is `#[non_exhaustive]`: a `match` on it needs a wildcard arm. `PublicKey::for_httpsig` refuses an algorithm outside `HTTPSIG_ALGORITHMS` before decoding the key, so its error names the algorithm. `MIN_MODULUS_BITS` and `MAX_MODULUS_BITS` are no longer in the `ps256` module: use them from the crate root.

`MIN_MODULUS_BITS` and `MAX_MODULUS_BITS` are public, and `Signer` is implemented for `&S`, `Box<S>`, and `Arc<S>`.

`Rs256Signer` and `Rs256Verifier` sign and verify `RS256`, with the RSA bounds of `PS256`. `HTTPSIG_ALGORITHMS` and `JWS_ALGORITHMS` say which algorithms each proof method takes, `PublicKey::for_jws` imports a key for the JOSE proofs, and `PublicKey::is_builtin_for_httpsig` tells a built-in `httpsig` key from one to leave to a resolver. The `jws` module signs and verifies the `jws` and `jwsd` proofs of RFC 9635 §§7.3.3–7.3.4 and their key rotations, with `sign_jws`, `sign_jws_rotation`, `verify_jws_request`, and `verify_jws_rotation`, and reserves each accepted proof in a `JwsReplayMemory`, such as the bounded `ReplayCache`. `unverified_attached_payload` reads, without verifying it, the payload a server needs to find the key of a first request, and `unverified_rotation_content` the content of an attached key rotation. The crate now depends on `gnap-types`, whose URI and access-token grammars the JOSE proofs apply, and `VerifyError::Unsigned` reads the same for every proof method.

`Ed25519Signer` and `Ed25519Verifier` sign and verify `EdDSA` with Ed25519, which RFC 9421 calls `ed25519`, and `Es256Signer` and `Es256Verifier` sign and verify `ES256`, its `ecdsa-p256-sha256`. `PublicKey::from_jwk` imports a public JWK and selects its verifier from `kty`, `crv`, and `alg`, and `PublicKey::for_httpsig` accepts the algorithms that `httpsig` allows. The `JwkSigner` trait exports a signer's public JWK and its thumbprint. `Signer::algorithm` and `Verifier::algorithm` return the JWA name of the algorithm, which the server compares with the `alg` of the presented key.

### gnap-core

The `Debug` output of a `Grant` counts its spent interaction references without showing them.

### gnap-types

**Breaking:** the `object_or_reference!` macro is no longer exported, since it only declares this crate's types.

**Breaking:** `HttpRequest::json_body` replaces any `Content-Type` field already set, instead of adding a second one. To build a message whose media type disagrees with its body, set `body` directly.

`HttpRequest::has_json_content_type` and `HttpResponse::has_json_content_type` check the media type of a JSON message. The `Debug` output of `TokenValue` hides the value, and that of the interaction and continuation messages hides their finish nonces, interaction references, and user codes. The message types implement `Eq` where every field does.

### gnap-registry

**Breaking:** the `impl_registry_traits!` macro is no longer exported, since it only declares this crate's types.

### gnap-rs, gnap-biscuit, and gnap-subject

`gnap-rs` accepts a token bound to a public ES256 or Ed25519 key as well as a PS256 one. The client key of the Biscuit file profile and the signature of an identity assertion remain PS256.

The three crates name their security bounds as constants, such as `MAX_RESPONSE_BYTES` and `MAX_CLOCK_SKEW` in `gnap-rs`, and `MAX_CLOCK_SKEW_SECONDS` and `MAX_SUBJECT_BYTES` in `gnap-subject`.
