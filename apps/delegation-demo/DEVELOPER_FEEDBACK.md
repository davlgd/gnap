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
| Bind consent to a grant | The old `Policy::evaluate_after_interaction` hook had no grant identifier or authenticated consent context | Fixed by `EvaluationContext`: choices are tied to a GrantId, the exact request and the committed interaction reference. Client-key resolution is a separate registry. Tests reject cross-grant, cross-client, stale-reference and changed-request consent |
| Continue after approval | The one-shot example could not exercise modifications or grant-wide revocation | `keep_grant_open`, contextual policy evaluation and `Session::revoke_grant` now support a real ongoing grant. A poll does not reissue tokens; a reduced set is observable at a second resource; expansion requests fresh consent. Reapproval replaces all old tokens atomically; denial closes continuation without silently revoking them |
| Distinguish a failed preparation from a refused grant | A server configuration failure used to carry a terminal GNAP error even when no grant update had been committed; the client consequently closed a continuation that the AS had kept | Internal configuration failures now use a non-GNAP text response. A real Session/AS regression checks unchanged local and stored state after an encoding failure, then a fresh retry. Valid GNAP errors still carry their protocol meaning: RFC 9635 does not make a particular HTTP status a substitute for reading the response, and a response without continuation does not authorize another continuation call |
| Serve a resource without access to AS storage | The first consumer used the SDK token index directly, so it could not exercise the RS/AS protocol boundary | The opaque RS now discovers the configured AS and calls RFC 9767 introspection over HTTP with a separate pre-registered RS key. It verifies client proof locally using the returned client key. The AS still owns its transactional indexes; the RS no longer reads them |
| Interpret an introspection refusal | `active:false` includes an AS unable to determine activity; it is not proof of intrinsic token invalidity | The RS refuses access without inventing a cause. Network failures and unusable responses are separate 503 errors; static storage-failure logs aid the AS operator without exposing credentials. No global failure counter rewrites concurrent responses |
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
rotation or revocation after the introspection response and before local proof
verification. That already-decided read can complete; a new read is refused.
This explicitly tests the network decision boundary rather than implying an
atomic transaction across AS and RS. Route tests distinguish an unavailable
AS exchange (503) from an inactive context or refused token/proof (401)
and check that the synthetic credential is not reflected. These local tests do
not establish distributed-storage behavior or a new live deployment result.

The socket-level composition test uses actual discovery and signed introspection
HTTP, rejects client-key impersonation of the RS and RS-key impersonation of the
client, checks replay independently on both channels, then rotates and revokes
tokens and stops the AS. A second HTTP fixture checks redirects, response size
and timeouts. Malformed replies, untrusted discovered destinations,
missing or overflowing deadlines and clock rollback have local regression tests.
The explicit 1,200-second timestamp profile and fixed two-right vocabulary are
application choices, not new RFC requirements. Discovery and two short-lived
HTTP connections per read are sufficient for this bounded consumer, not an
efficiency result or a recommendation for a high-throughput service.

The ongoing-grant consumer tests use the actual client Session, AS policy and
resource verifier, including a sibling token inserted through the store to
check whole-aggregate replacement and revocation. They honor the real five-second
continuation waits rather than future-date issuance against application wall
time. They also verify that a token retains its value and issuance timestamp
after polling, that expired rights cannot justify an automatic downscope, and
that denial of an extension leaves the previous token manageable. Browser HTTP
smoke checks complement these local SDK exchanges; neither is independent
conformance certification or real resource-owner identity assurance.
