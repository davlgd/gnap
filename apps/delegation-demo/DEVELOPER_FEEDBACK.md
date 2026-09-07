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

Callback lifetimes also need a client-side policy: an AS can omit its optional
duration or announce one longer than the application wants to wait.
`Session::with_finish_timeout` now gives this consumer a positive five-minute
maximum without extending an earlier AS deadline. A real HTTP grant test uses
the same configured session constructor as the browser worker, then advances
the callback clock across the local limit. This is distinct from the worker's
twenty-minute session cleanup; the SDK does not cancel remote grants on timeout.

| Task | Public API friction | Application workaround / suggested SDK work |
| --- | --- | --- |
| Keep grants across browser requests | `Session<'a,T,S>` borrows its transport and signer; a normal self-contained app state cannot own all three without a self-reference | One owning worker holds shared signer/transport and a map of borrowed sessions; document an owned-session or snapshot/resume pattern |
| Connect async HTTP handlers | `HttpTransport::send` is blocking | A bounded dedicated worker drives client exchanges; AS/RS use bounded blocking tasks; provide a maintained HTTP adapter example |
| Bind consent to a grant | The old `Policy::evaluate_after_interaction` hook had no grant identifier or authenticated consent context | Fixed by `EvaluationContext`: choices are tied to a GrantId, the exact request and the committed interaction reference. Client-key resolution is a separate registry. Tests reject cross-grant, cross-client, stale-reference and changed-request consent |
| Continue after approval | The one-shot example could not exercise modifications or grant-wide revocation | `keep_grant_open`, contextual policy evaluation and `Session::revoke_grant` now support a real ongoing grant. A poll does not reissue tokens; a reduced set is observable at a second resource; expansion requests fresh consent. Reapproval replaces all old tokens atomically; denial closes continuation without silently revoking them |
| Distinguish a failed preparation from a refused grant | A server configuration failure used to carry a terminal GNAP error even when no grant update had been committed; the client consequently closed a continuation that the AS had kept | Internal configuration failures now use a non-GNAP text response. A real Session/AS regression checks unchanged local and stored state after an encoding failure, then a fresh retry. Valid GNAP errors still carry their protocol meaning: RFC 9635 does not make a particular HTTP status a substitute for reading the response, and a response without continuation does not authorize another continuation call |
| Serve a resource without access to AS storage | The first consumer used the SDK token index directly, so it could not exercise the RS/AS protocol boundary | The opaque RS now discovers the configured AS and calls RFC 9767 introspection over HTTP with a separate pre-registered RS key. It verifies client proof locally using the returned client key. The AS still owns its transactional indexes; the RS no longer reads them |
| Call a downstream API as an RS | Reusing the incoming token would preserve the wrong key binding and audience | `GrantRequest::existing_access_token`, the signed derivation handler and `DerivationPolicy` now issue a distinct RS1-bound child for RS2. The app explicitly maps folder reading to metadata reading, limits one hop and checks the returned profile. It uses the public request/response types and `sign_request` directly, rather than a browser-interaction `Session`; fixed destinations, response validation and per-call cleanup remain application work |
| Publish a child without racing parent retirement | An independent grant insertion cannot check the exact parent token atomically | `DerivedGrantStore::create_derived` verifies the parent revision/value/lifetime at commit. The retention adapter delegates under its external maintenance lock and records the child only after success. Parent retirement cascades in SDK storage; RS reads still have the documented network decision race |
| Keep derivation optional for other consumers | Adding child creation to the base storage trait broke the separate Biscuit application's ordinary store, even though that application does not enable derivation | `DerivedGrantStore` now extends the base trait only for stores offering this capability. The derivation handler requires it at compile time; ordinary handlers do not. Paired documentation tests check activation with and without that bound |
| Issue and manage several tokens under one consent | The consumer could only ask for one token, so labels, per-token rights and independent management (RFC 9635 §§2.1.2, 3.2.2) were never exercised end to end | `Decision::ApproveTokens` lets the policy approve requested slots independently, including only the second one; the client checks that returned labels are the requested ones and rotates or revokes by label. The application keeps the flow's mode explicit, selects tokens by label with no fallback, compares a modification with the live token of the same label rather than the grant's union, refuses a partial approval when the current request has no reports slot, and keeps a retired token together with its label |
| Interpret an introspection refusal | `active:false` includes an AS unable to determine activity; it is not proof of intrinsic token invalidity | The RS refuses access without inventing a cause. Network failures and unusable responses are separate 503 errors; static storage-failure logs aid the AS operator without exposing credentials. No global failure counter rewrites concurrent responses |
| Request reusable sets of rights | Literal rights in the first client hid the resource-registration boundary | The RS now registers two immutable sets over signed HTTP. The client receives their public references in process and uses them in initial requests and PATCH. The AS resolves references before consent/downscope and freezes approved leaves in tokens. A reference alone never grants access |
| Start through a canonical URL during process replacement | The proxy can route bootstrap calls to an older instance with different ephemeral keys or incomplete capabilities | One bounded supervisor retries only explicit transient outcomes, signs every request afresh and checks returned sets against the local AS registry before publishing both references. Deduplication permits a retry after a committed registration whose response was lost. This co-location check is application coordination, not a portable GNAP discovery guarantee |
| Share a store | Earlier external-trait implementations for `Arc<MyStore>` triggered Rust orphan rules | SDK blanket implementations for `Arc<T>` and `&T` support the fallible `GrantStore` contract; the application implements it on its retention adapter and shares that directly |
| Enforce token lifetime | The original AS policy could not configure `expires_in`, so the RS maintained a separate deadline that a record rewrite could accidentally renew | Fixed through `Policy::token_lifetime`, `TokenRecord::issued_at` and its deadline/validity helpers. The demo requests 1,200 seconds and stores no duplicate token deadline; session lifetime remains separate |
| Clean up a public demo | Transactional aggregates need atomic removal of all indexes, without permitting stale CAS resurrection | Fixed through `GrantStore::remove(id, revision)`. A bounded application sweep keeps only continuation-retention metadata; token validity comes from the SDK record. A 256-aggregate cap refuses new grants with HTTP 503 without evicting live rights; nonce caches remain the SDK implementation |
| Make an actual HTTP adapter | `HttpRequest.body` is `Option<Vec<u8>>`, and signatures distinguish content from absence; continuation URI is exactly `/continue`, not necessarily a handle path | Adapter preserves body presence and registers the advertised exact URI; SDK network integration tests should lock down both |
| Sign a protected resource request | The original SDK required consumers to compose `Message`, `SignatureInput` and `sign` themselves | Fixed through public `gnap_client::sign_request`, now used by both `Session` and this demo. It binds the exact token and URI, generates a fresh nonce and refuses conflicting security headers; transport and audience policy remain the caller's responsibility |
| Survive restart or scale out | Client session still has no persistence/export contract | Store operations now return explicit errors and replace whole aggregates with revision-checked CAS. This demo remains single-instance and ephemeral; transactions alone are not durable/scalable readiness |

## Scope and next consumer experiments

The real resource read, key proof and retired-token rejection are implemented,
but its internal client sessions share one ephemeral key. The separate workbench
can use its own explicitly approved key; both applications remain under the same
operator. Further experiments include a separately operated RS, an independently
implemented client, real authenticated resource-owner consent, bounded durable persistence,
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
The explicit 1,200-second parent timestamp profile and fixed two-right vocabulary are
application choices, not new RFC requirements. Discovery and two short-lived
HTTP connections per read are sufficient for this bounded consumer, not an
efficiency result or a recommendation for a high-throughput service.

The downstream consumer adds a separate metadata vocabulary and a maximum
60-second child lifetime bounded by the parent. Socket tests exercise an actual
Session grant, signed RS1 derivation, RS2 introspection/proof, wrong audiences
and keys, replay, request-body tampering, refused child rotation and parent
rotation/revocation cascade. Repeated completed reads delete their children;
injected refusal/outage and lost cleanup replies verify one DELETE attempt and
no false success. Separate AS/RS1/RS2 worker pools avoid a same-pool nested-call
deadlock. These are co-located local tests, not a public deployment, a throughput
result, or independently operated RS interoperability. AS-mediated derivation
does not implement local Biscuit attenuation.

The two-token flow adds a third RS key and one more synthetic right. Socket
tests drive a real Session and the browser worker over HTTP through the full
lot, a partial approval of the reports token, cross-RS refusals of each token,
per-label rotation and revocation with the sibling and its derived child left
in place, a narrowing PATCH approved without consent, a widening PATCH that
returns to the owner and replaces the lot, a partial approval refused when the
current request does not request reports, the retired-token check naming and
targeting the right token after a rotation followed by a PATCH, and grant
revocation. Policy tests cover slot resolution, refusals of other labels,
rights, shapes and flags, and the per-label modification comparison. The two
labels and their rights are this application's vocabulary, not a GNAP
requirement; the AS still issues one lifetime for every token of a lot.

Resource-registration tests use real local HTTP for startup, readiness gating
and explicit-format refusal. Injected elapsed time and transport failures cover
the six-attempt limit, deadline and rollback refusal, lost-response deduplication,
partial failure and old-instance acknowledgements. Both wire forms of
`invalid_resource_server` are tested; missing discovery capabilities may retry,
while a supplied unexpected endpoint stops before sending credentials. The
ongoing-grant consumer now requests the registered references and retains its
leaf-right, re-consent, token-replacement and revocation assertions. None of
these observations establishes durable storage or a successful public rollout.

The ongoing-grant consumer tests use the actual client Session, AS policy and
resource verifier, including a sibling token inserted through the store to
check whole-aggregate replacement and revocation. They honor the real five-second
continuation waits rather than future-date issuance against application wall
time. They also verify that a token retains its value and issuance timestamp
after polling, that expired rights cannot justify an automatic downscope, and
that denial of an extension leaves the previous token manageable. Browser HTTP
smoke checks complement these local SDK exchanges; neither is independent
conformance certification or real resource-owner identity assurance.
