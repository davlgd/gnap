# Application consumer feedback

## Task attempted

Build a browser-accessible folder delegation application using only the public
GNAP crates for protocol state, signatures, callbacks and authorization-server
behavior. Keep the UI/application policy outside the SDK. Exercise actual HTTP,
not the in-process transport from the existing example.

## What worked

The narrated `gnap-as/examples/flow.rs` made initial grant/interaction/
continuation/management sequencing discoverable. `Ps256Signer::generate` avoids
shipping a private key from a published test fixture. `Session` rejects premature
continuation and validates callbacks. `HttpRequest`/`HttpResponse` are easy to
adapt to Axum/reqwest without inventing a crypto layer. The shared verifier now
allows a real protected resource to reuse exactly the AS's signature checks.

## Reproducible friction and application workarounds

| Task | Public API friction | Application workaround / suggested SDK work |
| --- | --- | --- |
| Keep grants across browser requests | `Session<'a,T,S>` borrows its transport and signer; a normal self-contained app state cannot own all three without a self-reference | One owning worker holds shared signer/transport and a map of borrowed sessions; document an owned-session or snapshot/resume pattern |
| Connect async HTTP handlers | `HttpTransport::send` is blocking | A bounded dedicated worker drives client exchanges; AS/RS use bounded blocking tasks; provide a maintained HTTP adapter example |
| Bind consent to a grant | `Policy::evaluate_after_interaction` receives the request but no grant identifier or authenticated consent context | Distinct client reference per browser session indexes synthetic decisions; real apps need a documented robust grant/RO correlation design |
| Serve a resource | `TokenStore` only exposes management-handle lookup | Application supplies an atomic token-value secondary index and shares it with the RS; no introspection claim |
| Share a store | Implementing external `TokenStore` for `Arc<MyStore>` triggered Rust orphan rules | This feedback produced SDK blanket implementations for `Arc<T>` and `&T`; the application now implements the traits on its own store and shares it directly, with no wrapper |
| Enforce token lifetime | AS approval policy cannot configure returned `expires_in`; TokenRecord carries no issuance time | Local RS deadline plus session lifetime; SDK should expose minted-token lifetime policy and authoritative timestamp |
| Clean up a public demo | Default memory grant/token stores have no public sweep API | Local grant/token maps with TTL and periodic sweep; nonce caches remain the SDK implementation |
| Make an actual HTTP adapter | `HttpRequest.body` is `Option<Vec<u8>>`, and signatures distinguish content from absence; continuation URI is exactly `/continue`, not necessarily a handle path | Adapter preserves body presence and registers the advertised exact URI; SDK network integration tests should lock down both |
| Sign a protected resource request | `Session` has management signing helpers but no public resource-request builder | Compose the public `Message`, `SignatureInput`, `sign` helpers; suggest a safe bound-token request builder, not copied signature logic |
| Survive restart or scale out | Client session has no persistence/export contract; store operations have no fallible transactional result | Explicitly single-instance ephemeral demo; do not market durable/scalable readiness |

## Scope and next consumer experiments

The real resource read, key proof and retired-token rejection are implemented,
but all components run under one application operator and one ephemeral client
key. Next useful experiments are a separately operated RS, independently built
client, real authenticated resource-owner consent, bounded durable persistence,
and network fault/retry tests. A second team should implement those from public
documentation without copying this application's internals.

This application was built by a separate consumer agent in the same development
effort, not an unrelated vendor. Compile/test and live observations must be
reported separately. No usability score or performance advantage is inferred
from a successful scenario.
