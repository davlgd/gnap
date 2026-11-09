# gnap-rs

Check opaque GNAP access tokens on a resource server. `gnap-rs` asks a trusted authorization server about the token through authenticated introspection ([RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.3)), then verifies the client's proof on the actual resource request. It needs neither an authorization-server store nor a particular HTTP framework.

## Integrate a resource endpoint

1. Configure `TrustedAs::new` with the exact HTTPS grant and introspection endpoints your deployment approves
2. Supply the resource server's identity and signer, an `HttpTransport`, and a replay `NonceMemory`
3. Choose an `AudiencePolicy`, and write an `AccessPolicy` for the rights your resource needs
4. Call `Authorizer::authorize` with the original request, and perform the operation only on `Ok(())`

The resource server's signer authenticates the introspection request, while the client's key comes from the authorization server's answer: a valid request signature alone doesn't establish the token's rights or audience. Each request makes a discovery and an introspection exchange, with no positive result cached. Run `cargo doc -p gnap-rs --open` for the API documentation and a complete example.

## Responsibilities and limits

Your transport authenticates HTTPS, keeps the signed bytes intact, refuses redirects and unapproved destinations, and bounds buffering and time. Your replay memory reserves nonces atomically, and must be shared or durable when you run replicas or need restart recovery.

The profile accepts `httpsig` signatures with public PS256 keys, and introspection responses with integer `iat` and `exp` claims. It doesn't support bearer tokens, Biscuit introspection, registration, or derivation. The [resource-server guide](https://github.com/davlgd/gnap/blob/main/docs/resource-server-sdk.md) explains the access policy, the audience policies, the failure cases, and every limit of the profile.

## Verification

The tests script the authorization server's responses, without `gnap-as`, and cover trust substitution, the separation of proof and key, replay, clocks, audiences, policy refusals, and unusable responses. The delegation lab uses this crate over real HTTP, which is separate evidence, not a certification of independent implementations.

```bash
cargo test -p gnap-rs --locked
```

Part of [gnap](https://github.com/davlgd/gnap). Rust 1.95 or newer; Apache-2.0.
