# GNAP and modern OAuth: what this ecosystem should demonstrate

Comparison checked on **2026-09-05**. This is a design and evaluation guide, not
a claim that this workspace already implements every feature described below.
AS means authorization server; RS means resource server.

## Use a contemporary baseline

Compare against OAuth deployments following the [OAuth Security BCP,
RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), with authorization code
and PKCE where applicable, and the extensions needed for the scenario. Do not
use the implicit flow, password grant, or unrestricted bearer tokens as a
stand-in for everything OAuth can do.

**OAuth 2.1 is still work in progress**, not a published RFC: the IETF
Datatracker currently lists
[draft-ietf-oauth-v2-1-16](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/16/)
as an active Internet-Draft. Its consolidation of the framework is not the
entire OAuth extension ecosystem. Record the draft version when comparing it;
do not silently treat future revisions as the same baseline.

Our working hypothesis is that GNAP's integrated grant lifecycle can make some
applications easier to build and reason about. That is an engineering hypothesis
to test with independent implementers, not a measured result or a security
guarantee. GNAP is a separate protocol, not a wire-compatible OAuth upgrade.

## Eight comparisons worth testing

| Concern | GNAP mechanism | Modern OAuth counterpart | What we should establish |
|---|---|---|---|
| Evolving authorization | A continuing grant can be updated and re-evaluated through its continuation API. [RFC 9635 §5](https://www.rfc-editor.org/rfc/rfc9635.html#section-5) | Authorization and refresh flows, plus extensions such as [RAR](https://www.rfc-editor.org/rfc/rfc9396.html) and [Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html), support related workflows, but are not that same continuation contract. | Whether one explicit grant lifecycle reduces application coordination. Do not call a rights-changing update simple token refresh. |
| Interaction choices | Interaction start and finish capabilities are negotiated separately within the grant. [RFC 9635 §2.5](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.5) | [Device Authorization](https://www.rfc-editor.org/rfc/rfc8628.html) supports constrained devices; [OpenID CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) supports decoupled authentication and poll/ping/push delivery. CIBA is an OpenID specification, not an IETF RFC or an exact GNAP equivalent. | Reuse across browser and device applications, not a claim that OAuth requires a browser redirect everywhere. |
| Proof of possession | Key-bound access tokens are the default; bearer tokens remain possible. [RFC 9635 §11.9](https://www.rfc-editor.org/rfc/rfc9635.html#section-11.9) | [DPoP, RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html), and [mTLS, RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), already sender-constrain OAuth tokens. DPoP is not itself client authentication. | Consistency and usability of key binding throughout our APIs. Token theft resistance is not exclusive to GNAP. |
| Signed request integrity | The HTTPSig method covers the full target URI and, when present, content digest and token authorization. [RFC 9635 §7.3.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.1) | [DPoP §4.2 and §11.7](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.7) do not protect the request body or URI query; TLS provides message integrity. [JAR](https://www.rfc-editor.org/rfc/rfc9101.html) protects authorization-request parameters, not arbitrary RS request bodies. | A concrete difference in signed coverage, alongside the cost of preserving signed bytes across HTTP adapters and proxies. HTTPSig does not replace TLS. |
| Rich rights and backchannel requests | Structured access descriptions and references travel in the grant request. [RFC 9635 §8](https://www.rfc-editor.org/rfc/rfc9635.html#section-8) | [RAR, RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html), carries typed authorization details; [PAR, RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), submits authorization requests directly to the AS. | Policy integration and documentation quality. Neither structured JSON nor backchannel submission is uniquely GNAP; application-specific rights still need semantics. |
| Multiple tokens | A grant can request multiple labeled tokens, with partial issuance. [RFC 9635 §2.1.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1.2) | [Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html) select target resources; [Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html) can obtain downstream tokens. Neither defines GNAP's labeled token-array response. | Whether one negotiation simplifies an application using several APIs without producing an overprivileged shared token. |
| Discovery and RS relationships | RS-facing discovery, introspection, resource-set registration and downstream token derivation have defined interfaces. [RFC 9767 §§3–4](https://www.rfc-editor.org/rfc/rfc9767.html#section-3) | OAuth has [introspection](https://www.rfc-editor.org/rfc/rfc7662.html), [AS metadata](https://www.rfc-editor.org/rfc/rfc8414.html), [protected resource metadata](https://www.rfc-editor.org/rfc/rfc9728.html), and [token exchange](https://www.rfc-editor.org/rfc/rfc8693.html). This is not an exhaustive comparison of other profiles. | Discoverability and cross-vendor RS integration. Do not present introspection, resource-first discovery or delegation as GNAP inventions. |
| Lifecycle management | Per-token management and grant continuation are separate protocol interfaces. [RFC 9635 §§5–6](https://www.rfc-editor.org/rfc/rfc9635.html#section-6) | OAuth has [token revocation](https://www.rfc-editor.org/rfc/rfc7009.html) and refresh-token security guidance in [RFC 9700 §4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14). Access-token replacement, refresh-token rotation and changing signing keys are different operations. | Whether the distinction is clear to developers and survives storage, concurrency and retry failures. |

## What is actually available here

Baseline: local pre-publication revision `8510bd0`, before the ecosystem work
described in this document. That history is not included in the public
repository; this section records the starting point, not the current feature set.
The [README scope](../README.md#what-is-implemented-and-what-is-not) is the place
to check subsequent implementation changes.

- Local client/AS tests exercise initial requests, redirect interaction,
  callbacks, polling, grant updates and revocation, HTTPSig/PS256, and token-value
  rotation and revocation. The narrated [flow example](../crates/gnap-as/examples/flow.rs)
  uses in-memory transport, not a network deployment.
- The message model represents rich rights and multiple-token requests, but
  the AS issues only one bound token per approval. It does not assign an
  expiration duration. An array containing one token is not a multi-token demo.
- There is no RS, RFC 9767 endpoint implementation, deployed conformance service,
  durable store or production HTTP adapter in that baseline. Other interaction
  start modes and changing the token's signing key are not implemented.
- Consent, user authentication, application authorization semantics and key
  provisioning are deployment responsibilities, not supplied by a signature
  verifier. Local tests do not establish independent interoperability.

## Application experiments, not marketing demos

These are proposed acceptance scenarios. Their presence here does not mean
they already run. Use synthetic data and isolated test credentials throughout.

| Experiment | Observable success and negative cases | Baseline gap to close |
|---|---|---|
| Document workspace with progressive privileges | Start read-only; request editing when the user selects Edit. Record a new approval decision, reject editing before approval, and reject a stale callback after the request changes. | Web adapter, consent UI, actual document RS and application policy. |
| Browser and terminal clients for the same API | Complete browser approval, then operate a terminal client without a callback listener. Record polling limits and cancellation; later add a genuine secondary-device code flow. | Network clients first; code-based interaction is a separate unimplemented step. |
| Request-integrity laboratory | Change only the body, query, method or authorization value after signing; each invalid presentation is rejected. Replay an otherwise valid request and present the token with a different key. | RS integration and a network adversarial runner, not just a signing example. |
| Synthetic expense approval | Request approval of one expense with an amount ceiling; deny another expense or a larger amount even with a valid signature. Show the effective approved rights to the user. | Explicit rights schema, policy and enforcement at the RS. |
| Two-service dashboard | Obtain separately labeled document and calendar tokens. Handle partial approval, reject cross-service use, and revoke one without disabling the other. | Actual multi-token issuance, two RSs and lifecycle enforcement. |
| Registered resource and downstream worker | Register a resource set, discover the AS, introspect a token, then obtain a narrower downstream token for a worker. Reject an unauthorized RS and a broader downstream request. | RFC 9767 implementation and deployment-specific trust/policy configuration. |

For each experiment, ask an implementer who did not write the library to start
from a clean checkout and its public documentation. Record commands attempted,
documentation gaps, confusing types/errors, required workarounds, and whether
the SDK exposed every required operation. A coordinated sub-agent is a useful
first consumer, but not independent third-party interoperability evidence.

Measure integration time, code outside the SDK, failed attempts, HTTP round
trips, latency percentiles and throughput only in an identified environment.
Publish workload, concurrency, key/proof choices, warm-up, build configuration,
storage and network topology. Do not attribute Clever Cloud deployment size or
one favorable measurement to a protocol-level performance advantage. An OAuth
comparison needs the same task and comparable security properties; absent that
implementation, report GNAP measurements alone.

## What a public conformance result may claim

Reports should identify the tested role, endpoint, declared profile, proof
method, specification/version, harness version, timestamp and individual test
outcomes. Separate normative failures, unsupported optional features, harness
limitations and deployment-policy failures. Provide reproducible, redacted
traces; never publish tokens, private keys, personal data or consent secrets.

A successful scenario means that scenario passed. It is not complete GNAP
certification, a production security audit, or proof that every untested
combination works. Test endpoints only with their operator's authorization;
isolate outbound requests so a public test UI cannot become an SSRF or scanning
service. Keep destructive lifecycle tests on disposable grants and resources.
