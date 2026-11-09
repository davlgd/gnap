# Changelog

This file lists the changes to the published crates that affect their users, crate by crate, with what you need to change. The crates aren't released yet, so every change sits under *Unreleased*, and the versions follow [semantic versioning](https://semver.org/) from the first release.

## Unreleased

### gnap-client

**Breaking:** `Session<'a, T, S>` becomes `Session<T, S>`, and owns its transport and its signer. A call such as `Session::new(&transport, &signer, endpoint)` keeps compiling. Where you named the type, write `Session<&Transport, &Ps256Signer>`, or pass an `Arc` to keep a session in long-lived state.

**Breaking:** `Session::rotate_key` takes the replacement signer as a `SharedSigner`, which is an `Arc<dyn Signer + Send + Sync>`, and `Session::rotate_key_owned` is gone. The replacement must therefore be `Send + Sync + 'static`, so that a session can move between threads: move the new signer into the `Arc`, or wrap a reference that lives for the whole program.

**Breaking:** a response must carry exactly one `Content-Type` field naming `application/json`, as RFC 9635 §3 requires: the session refuses a missing field.

`HttpTransport` is implemented for `&T`, `Box<T>`, and `Arc<T>`.

### gnap-as

**Breaking:** `Nonces::next` returns `Result<String, NonceError>`, so an implementation wraps its value in `Ok`. When a draw fails, the operation publishes nothing and fails with a 500, or a 503 for a resource registration, and `OsNonces` no longer panics.

**Breaking:** `Decision::Approve` applies to a request for one token or for none. When the request holds several, the server refuses it as a configuration fault: select them with `Decision::ApproveTokens`. A request for no token, which asks only for subject information, gets no token, and an approval that grants it rights is refused too.

**Breaking:** a grant, continuation, or management request whose body has a repeated `Content-Type` field is refused.

`OsNonces` draws each symbol from a 64-character alphabet, without the bias of the former 62-character one. The `Debug` output of `MemoryStorage` shows counts only, and that of a stored record hides its continuation and management credentials, nonce, interaction handle and reference, and user code; the request and the token it holds keep their own `Debug` output. `MAX_GRANT_BODY_BYTES` names the bound on a grant or key-rotation body.

### gnap-crypto

**Breaking:** every `Ps256Signer` and `Ps256Verifier` constructor refuses an RSA modulus outside 2,048 to 4,096 bits, the PEM imports and `Ps256Signer::generate` included.

`MIN_MODULUS_BITS` and `MAX_MODULUS_BITS` are public, and `Signer` is implemented for `&S`, `Box<S>`, and `Arc<S>`.

### gnap-types

**Breaking:** the `object_or_reference!` macro is no longer exported, since it only declares this crate's types.

**Breaking:** `HttpRequest::json_body` replaces any `Content-Type` field already set, instead of adding a second one. To build a message whose media type disagrees with its body, set `body` directly.

`HttpRequest::has_json_content_type` and `HttpResponse::has_json_content_type` check the media type of a JSON message. The `Debug` output of `TokenValue` hides the value, and the message types implement `Eq` where every field does.

### gnap-registry

**Breaking:** the `impl_registry_traits!` macro is no longer exported, since it only declares this crate's types.

### gnap-rs, gnap-biscuit, and gnap-subject

The three crates name their security bounds as constants, such as `MAX_RESPONSE_BYTES` and `MAX_CLOCK_SKEW` in `gnap-rs`, and `MAX_CLOCK_SKEW_SECONDS` and `MAX_SUBJECT_BYTES` in `gnap-subject`.
