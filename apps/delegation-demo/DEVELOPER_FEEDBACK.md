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
| Serve a resource | The former `TokenStore` exposed only management-handle lookup | Fixed through `GrantStore::lookup(GrantSelector::AccessToken)`: the SDK atomically indexes the grant and tokens. The application no longer duplicates credential indexes. The RS verifies proof outside the store lock and rechecks the snapshot revision/expiration before authorizing; no introspection claim |
| Share a store | Earlier external-trait implementations for `Arc<MyStore>` triggered Rust orphan rules | SDK blanket implementations for `Arc<T>` and `&T` support the fallible `GrantStore` contract; the application implements it on its retention adapter and shares that directly |
| Enforce token lifetime | The original AS policy could not configure `expires_in`, so the RS maintained a separate deadline that a record rewrite could accidentally renew | Fixed through `Policy::token_lifetime`, `TokenRecord::issued_at` and its deadline/validity helpers. The demo requests 1,200 seconds and stores no duplicate token deadline; session lifetime remains separate |
| Clean up a public demo | Transactional aggregates need atomic removal of all indexes, without permitting stale CAS resurrection | Fixed through `GrantStore::remove(id, revision)`. A bounded application sweep keeps only continuation-retention metadata; token validity comes from the SDK record. A 256-aggregate cap refuses new grants with HTTP 503 without evicting live rights; nonce caches remain the SDK implementation |
| Make an actual HTTP adapter | `HttpRequest.body` is `Option<Vec<u8>>`, and signatures distinguish content from absence; continuation URI is exactly `/continue`, not necessarily a handle path | Adapter preserves body presence and registers the advertised exact URI; SDK network integration tests should lock down both |
| Sign a protected resource request | The original SDK required consumers to compose `Message`, `SignatureInput` and `sign` themselves | Fixed through public `gnap_client::sign_request`, now used by both `Session` and this demo. It binds the exact token and URI, generates a fresh nonce and refuses conflicting security headers; transport and audience policy remain the caller's responsibility |
| Survive restart or scale out | Client session still has no persistence/export contract | Store operations now return explicit errors and replace whole aggregates with revision-checked CAS. This demo remains single-instance and ephemeral; transactions alone are not durable/scalable readiness |

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

The transactional-adapter regression tests retain the earlier resource checks
and exercise saturation, independent continuation/token deadlines, failed CAS,
atomic purge and stale-snapshot rejection. A deterministic clock hook commits
rotation or revocation between resource snapshot lookup and proof verification;
this tests the application interleaving, not an independent protocol validator.
Route tests distinguish unavailable storage (503) from invalid token/proof (401)
and check that the synthetic credential is not reflected. These local tests do
not establish distributed-storage behavior or a new live deployment result.
