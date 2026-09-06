# GNAP scope and support matrix

Decision recorded on **5 September 2026**. The initial code inventory used
[e84e47c](https://github.com/davlgd/gnap/commit/e84e47caedf66f5a472e076f9b3489d5517ef346),
the code snapshot audited before this matrix was added. That reference records
the initial audit, not the current branch head. The rows below track subsequent
implementation changes and their evidence. Documentation changes do not turn a
planned feature into an implemented one. Update the relevant rows with each
implementation change and link its tests and application evidence.

## Product decisions

- **Biscuit is a required project target.** Support means issuance, validation
  and an application exercising attenuation, not merely recognizing its name.
- **Signed and encrypted JWTs are acceptable alternatives.** They may be added
  for a concrete integration; neither is implemented today, and they do not
  replace the Biscuit objective.
- **Macaroon and ZCAP implementations are outside the current scope.** Their
  registry names remain available as reference data. Do not remove or silently
  reinterpret unknown extension values to enforce a product roadmap.
- **HTTP Message Signatures (`httpsig`) are the preferred proof method.** The
  existing PS256 implementation remains the starting point.
- **mTLS is an allowed additional proof method**, not a prerequisite for the
  next application. It needs a real TLS client-certificate trust boundary;
  accepting an untrusted forwarded certificate header is not mTLS support.
- Other proof methods are deferred from the next milestone. This is a delivery
  priority, not a claim that GNAP forbids them.

Opaque reference tokens remain the existing test baseline. Their presence does
not add another structured-token implementation to the selected target list.

The first distributed application must not force every token through a shared
AS/RS store or assume introspection is the only validation path. Biscuit needs
an explicit mapping of GNAP rights, audience, expiry and key binding to its
authorization policy. Attenuating a token does not automatically rebind it to a
different client's or resource server's key. Local validation also needs an
explicit revocation policy; it cannot learn about revocation without receiving
updated information. These are integration requirements to design and test,
not an already standardized Biscuit/GNAP profile implemented by this project.

## Reading the matrix

The **RFC condition** and **project decision** columns answer different questions.
An optional mechanism still has mandatory rules when it is selected. A feature
required by this project is not necessarily required by GNAP.

- **C1/C2 required**: a capability required by the Web-Based Redirection or
  Secondary Device interoperability profile in RFC 9635 Appendix C. Appendix C
  permits a functioning subset for clients in the circumstances it describes;
  AS profile claims require the profile's full capability set. Required support
  for a capability does not mean it appears in every grant response.
- **Conditional**: the cited section's requirements apply when that message,
  endpoint, format or behavior is used. This is not a blanket obligation to
  implement every GNAP option.
- **Deployment responsibility**: the protocol leaves the identified choice or
  integration to the deployment; this does not exempt it from security checks.

Implementation states are **implemented and tested**, **partial**, **model only**,
or **missing**. A source link supports a description of an API or a gap; only a
test or recorded execution supports a claim that a behavior was exercised.
There is no overall conformance score. This is a capability-level inventory, not
yet an exhaustive ledger of every MUST, SHOULD and MAY in both RFCs.

The [public normative ledger](../conformance/README.md) supplies a reproducible
source inventory for that next level of review. It preserves each BCP14 marker,
its context and the profile capability lists, without treating an extracted
block or a passing test of the ledger itself as a completed protocol obligation.

## Token formats and behavior

Formats are agreed between the AS and RS. The registered names and announcement
points are defined by [RFC 9767 §2.2 and §5.3](https://www.rfc-editor.org/rfc/rfc9767.html#section-2.2).
GNAP does not require every implementation to support every registered format.

| Capability | RFC condition | Project decision | Current state and evidence |
| --- | --- | --- | --- |
| Biscuit access tokens | Conditional on selecting the format; RFC 9767 §2.2 | Required target | **Partial**: [gnap-biscuit](../crates/gnap-biscuit/README.md) supplies a restricted file profile with issuance, structural checks, chain verification, local attenuation and proof-bound resource authorization. [Tests](../crates/gnap-biscuit/tests/file_profile.rs) and an [in-process example](../crates/gnap-biscuit/examples/file_access.rs) exercise the implementation. No integrated GNAP AS flow, deployed separate RS or authenticated revocation channel is supplied yet. This is an application profile, not support for every Biscuit feature. |
| Signed JWT access tokens (`jwt-signed`) | Conditional on selecting the format; RFC 9767 §2.2 | Allowed alternative | **Model only**: registry name. No JWT issuer or validator supplied. |
| Encrypted JWT access tokens (`jwt-encrypted`) | Conditional on selecting the format; RFC 9767 §2.2 | Allowed alternative | **Model only**: registry name. No JWE issuer or decryptor supplied. |
| Macaroon and ZCAP access tokens | Conditional on selecting the format; RFC 9767 §2.2 | Outside current scope | **Model only**: names remain in the registry; no executable implementation is advertised. |
| Opaque reference access tokens | Conditional; RFC 9767 §2.2 permits AS/RS agreement on token representation | Existing test baseline | **Implemented and tested**: AS-issued values, protected resource lookup and retired-token rejection in the [HTTP acceptance script](../tools/smoke_ecosystem.py); shared volatile store and one application key, not introspection. |
| Key-bound tokens | Default binding rules in [RFC 9635 §3.2.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2.1) | Required target | **Implemented and tested**, for the current reference-token path: wrong-key and replay tests in [the demo](../apps/delegation-demo/src/main.rs), and [shared verifier tests](../crates/gnap-crypto/tests/verify_request.rs). |
| Bearer tokens | Conditional on the `bearer` flag; RFC 9635 §3.2.1 | Deferred as a served application mode | **Partial**: [type tests](../crates/gnap-types/tests/conformance.rs) reject bearer plus key; the AS never issues bearer tokens. |
| `durable` flag | Optional response flag; RFC 9635 §3.2.1 | Deferred pending a consumer scenario | **Model only** for issuance: the AS emits no flags. `durable` concerns continued token usability after rotation or grant modification, not persistent storage or immunity from expiry/revocation. |
| Multiple access tokens | Conditional on array request/response forms; [RFC 9635 §§2.1.2, 3.2.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1.2) | Planned application capability | **Partial**: labels and cardinality are [tested](../crates/gnap-types/tests/conformance.rs); the AS issues only one token per approval. |
| Token expiration | `expires_in` is optional in [RFC 9635 §3.2.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2.1); validity checks apply when expiry is set | Required project policy for hosted examples | **Implemented and tested** for the reference-token path: optional [policy duration](../crates/gnap-as/src/policy.rs), issuance timestamps and fail-closed [time checks](../crates/gnap-as/tests/storage.rs). [Interop tests](../crates/gnap-as/tests/interop.rs) cover announced lifetime, renewal and unchanged records on refusal. The demo selects 1,200 seconds and rechecks expiry and aggregate revision after proof verification under its storage lock. Refusing rotation after expiry is SDK policy, not a GNAP requirement. |
| Token value rotation and revocation | Conditional on offering the management API; [RFC 9635 §6](https://www.rfc-editor.org/rfc/rfc9635.html#section-6) | Required target | **Implemented and tested** for the current token path in [AS interop tests](../crates/gnap-as/tests/interop.rs) and the HTTP acceptance script. Repeated revocation is not idempotent after authentication metadata is removed. |
| Changing a token's bound key | Conditional on supporting key rotation; [RFC 9635 §6.1.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-6.1.1) | Planned, distinct from changing the token value | **Missing**: the AS rejects the operation. Low-level rotation vectors do not establish an operational rotation flow. |

A JWT carried as an access token is not the same feature as the `jws` or `jwsd`
request proof methods. Likewise, an `id_token` assertion is not automatically a
JWT access token. Signature primitives alone implement neither token format.

## Proofs, keys and interaction profiles

Profile requirements below come from [RFC 9635 Appendix C](https://www.rfc-editor.org/rfc/rfc9635.html#appendix-C).
Neither complete profile conformance nor independent implementation
interoperability is currently claimed.

| Capability | RFC condition | Project decision | Current state and evidence |
| --- | --- | --- | --- |
| `httpsig`, without additional parameters | C1/C2 required; [§7.3.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.1) defines proof checks | Preferred and required target | **Implemented and tested**: [GNAP HTTPSig vectors](../crates/gnap-crypto/tests/httpsig_gnap.rs), [verifier tests](../crates/gnap-crypto/tests/verify_request.rs) and the HTTP demo. Caller-supplied key resolution and replay policy remain necessary. |
| PS256 request signatures | C1/C2 required | Required baseline | **Implemented and tested**: `sign_and_verify_with_ps256` in the HTTPSig tests. This is not JWT support. |
| Public request-signing helper | SDK ergonomics for RFC 9635 §§7.2–7.3.1, not a separate protocol capability | Required consumer improvement | **Implemented and tested**: [`sign_request`](../crates/gnap-client/src/signing.rs) signs exact request targets and optional tokens without imposing JSON or a transport. `Session` and the reference-token demo use it. [Real PS256 tests](../crates/gnap-client/tests/signing.rs) exercise replay, tampering, body presence and conflicting headers. TLS, audience and token/key selection remain application responsibilities. |
| mTLS | Conditional if selected as a proof; [§7.3.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.2) | Allowed additional implementation | **Model only**: proof name exists; no GNAP client-certificate adapter or live mTLS scenario. |
| `jwsd` and `jws` request proofs | Conditional if selected; [§§7.3.3–7.3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.3) | Deferred from the next milestone | **Model only**, no proof adapters. JWT access-token alternatives do not change this status. |
| JWK key representation and resolution | C1/C2 require the JWK representation and key algorithm information; [§7.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-7.1) | Required target | **Implemented and tested** for public RSA/PS256 keys: [import/export tests](../crates/gnap-crypto/tests/ps256_jwk.rs) cover encoding, size, metadata and exact signature key ID. The [JWK client example](../crates/gnap-as/examples/jwk_client.rs) derives a verifier through `KeyResolver`, then exercises issuance, rotation and revocation without pre-registration. This bounded bare-key adapter does not supply other algorithms, certificate trust or client identity. |
| Certificate and certificate-thumbprint keys | Conditional on selecting `cert` or `cert#S256`; §7.1 | Deferred unless needed by the mTLS consumer | **Model only**: representation fields are present; no X.509 parsing/trust adapter supplied. A certificate representation is distinct from an mTLS proof. |
| Browser redirect start and finish | C1 required; [§2.5 and §4.2.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-4.2.1) | Required target | **Implemented and tested** in [client tests](../crates/gnap-client/tests/flow.rs), AS interop tests and the HTTP acceptance script. Browser consent is synthetic. |
| Client interaction-finish deadlines | [RFC 9635 §4](https://www.rfc-editor.org/rfc/rfc9635.html#section-4) recommends suitable finish timeouts; `interact.expires_in` is optional in §3.3 | Required client lifecycle work | **Partial**: [callback tests](../crates/gnap-client/tests/flow.rs) exercise the advertised deadline for redirect, push and parsed callbacks, clock rollback and one-time acceptance. Wider deadline arithmetic preserves legal long lifetimes. Callback APIs take an explicit clock value. No configurable client maximum is supplied when the AS omits a duration; applications must bound their sessions if needed. |
| `user_code` and `user_code_uri` start | C2 required; [§2.5.1](https://www.rfc-editor.org/rfc/rfc9635.html#section-2.5.1) | Planned secondary-device milestone | **Model only**: no AS implementation starts these modes. |
| `app` interaction start | Conditional if negotiated; §2.5.1 | Deferred from the next milestone | **Model only**: no application-launch flow. |
| `push` interaction finish | C2 AS capability; [§4.2.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-4.2.2) | Planned secondary-device milestone | **Partial**: `the_push_finish_method_yields_a_json_callback` in AS interop tests and client `accept_push` tests. The application must send the HTTP callback and enforce SSRF protections; no hosted push scenario exists. |
| Polling without a finish callback | Conditional on the negotiated interaction; [§5.2](https://www.rfc-editor.org/rfc/rfc9635.html#section-5.2) | Supported baseline | **Implemented and tested** in AS/client flow tests. This does not supply missing C2 AS capabilities. |
| SHA-256 interaction hash | C1/C2 required; [§4.2.3](https://www.rfc-editor.org/rfc/rfc9635.html#section-4.2.3) | Required target | **Implemented and tested** against [interaction-hash vectors](../crates/gnap-crypto/tests/interaction_hash.rs); additional implemented hashes are not additional profile requirements. |
| Opaque subject identifiers | C1/C2 required capability; [§3.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.4) | Required target | **Partial**: subject consistency checks in type/client tests; identity and release decisions come from the deployment policy. No production identity service supplied. |
| `id_token` assertions | C1/C2 required capability; §3.4 | Required profile work, separate from access-token formats | **Partial**: [subject consistency tests](../crates/gnap-types/tests/conformance.rs) exercise decoding. [`issuer_subject`](../crates/gnap-types/src/user.rs) deliberately does not verify the JWT signature. No assertion issuer/verifier integration supplied. |
| SAML assertions | Conditional when requested/returned; §3.4 | Deferred from the next milestone | **Model only**: carried as a string; no SAML validator. |

## Protocol lifecycle, RS connections and public diagnostics

| Capability | RFC condition | Project decision | Current state and evidence |
| --- | --- | --- | --- |
| Grant request, response and continuation | Requirements within the selected flow in [RFC 9635 §§2–5](https://www.rfc-editor.org/rfc/rfc9635.html#section-2) | Required target | **Implemented and tested**, with the limits above: [AS/client interop](../crates/gnap-as/tests/interop.rs), [state vectors](../vectors/state-machine.json), and the HTTP acceptance script. No claim that every option in those sections is implemented. |
| Atomic grant and token updates | Secure state tracking in [RFC 9635 §1.5](https://www.rfc-editor.org/rfc/rfc9635.html#section-1.5); concurrency mechanism is an implementation choice | Required lifecycle foundation | **Implemented and tested**: one [revisioned aggregate](../crates/gnap-as/src/storage.rs) atomically owns the grant, its tokens, their lookup indexes and a shared namespace preventing access, management and continuation credentials from colliding or changing roles. [Concurrent management tests](../crates/gnap-as/tests/concurrent_management.rs) reproduce and prevent resurrection during DELETE/rotation; [failure tests](../crates/gnap-as/tests/storage_failures.rs) cover unpublished responses on store errors. The reference store is single-process and volatile; custom adapters must implement the same transaction contract. |
| Modification and revocation of an approved grant | Conditional on an ongoing grant; [RFC 9635 §§5.3–5.4](https://www.rfc-editor.org/rfc/rfc9635.html#section-5.3) | Required lifecycle capability | **Implemented and tested** for the selected replacement policy: opt-in ongoing grants, polling without token reissuance, PATCH re-evaluation and atomic replacement on approval, and DELETE of the entire grant. [SDK lifecycle tests](../crates/gnap-as/tests/ongoing.rs), [concurrent updates](../crates/gnap-as/tests/concurrent_management.rs), and the [demo consumer](../apps/delegation-demo/src/ongoing_tests.rs) exercise these paths. Old tokens remain live during pending interaction; a refusal closing continuation is not token revocation. No `durable` token retention or persistent storage is supplied. |
| API-specific rights | [RFC 9635 §8](https://www.rfc-editor.org/rfc/rfc9635.html#section-8) defines representation; API semantics belong to the deployment | Required for each example | **Partial**: reference and structured rights are modeled/tested; the demo enforces separate synthetic folder and archive read rights, including downscope and expansion with renewed consent. This is not a generic policy engine. |
| Client instance identifier issuance | Optional response capability in [RFC 9635 §3.5](https://www.rfc-editor.org/rfc/rfc9635.html#section-3.5) | Planned after a concrete client-registration use case | **Missing**: no dynamic identifier issuance. |
| Client-facing AS discovery | The client MAY request discovery with OPTIONS; the AS MUST then return the JSON document specified by [RFC 9635 §9](https://www.rfc-editor.org/rfc/rfc9635.html#section-9) | Required AS response | **Implemented and tested** for the AS response: [interop tests](../crates/gnap-as/tests/interop.rs) exercise exact endpoint identity, JSON, capabilities and absence of state changes; [type tests](../crates/gnap-types/tests/conformance.rs) check HTTPS endpoint syntax. The [demo router](../apps/delegation-demo/src/main.rs) serves OPTIONS and rejects noncanonical aliases. HTTP loopback requires an explicit, labelled development deviation. No client discovery helper or RS-first §9.1 flow is supplied. |
| RS-facing discovery | Optional API component; [RFC 9767 §§3, 3.1](https://www.rfc-editor.org/rfc/rfc9767.html#section-3) | Planned distributed application | **Missing**. Do not advertise unsupported formats or proof methods. |
| Authenticated token introspection | Optional API component; [RFC 9767 §§3.2–3.3](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.2) define authentication and response rules | Planned distributed application | **Missing**. Demo store lookup is not this protocol. A structured token does not make this API mandatory or prohibited. |
| Resource-set registration | Optional API component; [RFC 9767 §3.4](https://www.rfc-editor.org/rfc/rfc9767.html#section-3.4) | Planned resource registration scenario | **Missing**, including format requirements communicated by the RS. |
| Downstream token derivation | Conditional on the RS/AS supporting the mechanism; [RFC 9767 §4](https://www.rfc-editor.org/rfc/rfc9767.html#section-4) | Planned delegation scenario | **Missing**: AS-mediated derivation and local Biscuit attenuation are distinct paths to exercise, not interchangeable implementations. |
| Imported-message diagnostics | Project tooling, not an RFC certification scheme | Required tool | **Partial**: original message checks share SDK parsers. [AS discovery checks](../apps/conformance-web/tests/discovery.rs) inspect HTTP context, JSON and exact endpoint identity without the SDK validator; registry data remain shared. Missing optional fields and unsupported URL interpretations are explicitly untested. Profile rules such as HTTP 200 and userinfo refusal are distinguished from GNAP requirements. |
| Active AS/RS probes | Project tooling; endpoint-owner authorization required | Required tool, initially operator-approved targets only | **Partial**: bounded rejection probes and AS OPTIONS discovery, with [probe tests](../apps/conformance-web/src/probe.rs), [earlier live observations](validation-2026-09-05.md) and a [real discovery network smoke](../apps/conformance-web/LIVE_SMOKE.md). Neither rejection nor discovery probes exercise a full authenticated flow or prove that announced capabilities work. |
| Arbitrary third-party self-service tests | Project tooling and deployment security | Deferred until ownership, quotas and egress safeguards exist | **Missing**. Adding an endpoint to a public form must not create an unrestricted scanner. |
| Durable storage, real RO authentication and restart recovery | Deployment responsibilities; requirements depend on the advertised deployment guarantees | Required before claiming production readiness | **Missing** as supplied services. The current examples remain synthetic, single-instance and volatile. |

## Delivery sequence and acceptance

1. Keep this scope and evidence inventory public, and use the
   [review and merge process](../CONTRIBUTING.md) for each subsequent change.
2. Let a consumer built from the public documentation drive bounded-token
   lifetime, safe resource-request signing and client-state improvements.
3. Build the first separated client/AS/RS application, with no shared process
   state. Integrate Biscuit using an identified implementation/version and a
   documented rights/key-binding policy. Keep the existing reference-token path
   as a comparison; add JWT alternatives only with a concrete consumer need.
4. Extend the web workbench with authenticated lifecycle scenarios and wire-level
   assertions authored separately from SDK validators. Publish redacted evidence,
   limitations and negative cases alongside successful paths.
5. Expand discovery, registration, multiple resources/tokens, secondary-device
   interaction and downstream delegation through individually reviewed slices.

A slice is ready only after its positive and negative tests pass, its application
scenario works where applicable, the documentation states the actual support
level, Claude's adversarial findings are reconciled, and the PR's Copilot review
and CI satisfy the merge gate. A coordinated consumer agent is useful feedback,
not evidence of independent-vendor interoperability. No release may claim all of
GNAP, either complete interoperability profile or production readiness on the
strength of this matrix alone.
