# Diagnostic workbench: developer feedback

This feedback comes from a real HTTP consumer, not from independent GNAP interoperability tests.

## What worked

- Protocol messages are usable without an authorization server or a transport framework
- Polymorphic visitors catch meaningful errors, such as a client repeated on continuation
- The JSON shape follows the RFC's terminology
- Raw body bytes and ordered header pairs are the right shape for signature and digest tools
- Digest validation works offline, without a key store or network access

## Open friction

Deserialization isn't validation. Each nested type exposes its own selected `validate()` method; consumers must discover and call them. A public recursive `validate_message(profile, context)` returning structured findings could make coverage explicit and prevent forgetting client display, key or token checks.

Errors are excellent for local debugging but some embed URIs or values. A web service can't safely return arbitrary `Display` text. Add stable error code, field path and redacted public guidance, separately from debug detail.

`KeyObject::validate()` verifies selected presentation constraints, not mathematical public-key/certificate validity or all private parameter cases. Expose validation scope clearly so UI authors can't equate `Ok(())` with a usable and safely presented key.

Message shape doesn't check request/response cardinality, state, semantics of rights or elapsed time. A bounded, importable trace with explicit role, endpoint, exact bytes, observations and redaction would enable black-box scenario tests without rebuilding SDK state.

SDK shared checks can reproduce SDK bugs. Keep these diagnostics labelled; grow independently authored wire-level assertions, published vectors, and a second implementation before claiming interoperability or certification.

HTTP framework, async integration, body limits and privacy-safe logging are integrator responsibilities. A small official adapter recipe with the security boundaries spelled out would remove repeated implementation work.

The shared verifier in `gnap-crypto` can be used without constructing a full AS. The analyzer intentionally leaves proof checks `not_tested` until complete request context, trusted key, intended token and explicit clock/replay policies can be supplied safely.

The [authenticated workbench scenario](../../docs/authenticated-workbench.md) exercises consent, token binding, resource access, rotation and revocation against operator-approved AS/RS pairs with a separately configured client key. It doesn't turn an imported target into an authorized network destination. Third-party self-service probes would additionally need target ownership challenges, immutable operation plans, distributed quotas, audit records without secrets, a reviewed egress policy, and tightly scoped synthetic credentials. The scenario with approved pairs doesn't supply any of those controls.

## Lessons from the discovery diagnostics

The AS discovery profile consumes imported documents and one bounded OPTIONS response from an existing operator-approved AS target. It checks raw JSON/HTTP and endpoint relationships without using the SDK's discovery deserializer or validator. This avoids proving that a producer and the same validator agree. It is still not a second GNAP implementation or a certification suite.

The GNAP registry enums are useful independently as reference data; duplicating their known names would create a second maintenance problem. Subject Identifier formats are in another IANA registry absent from `gnap-registry`, so this app carries a small documented snapshot for those names only. Unknown names need an external registry review, and stay unresolved instead of failing automatically.

Three useful distinctions emerged: absent optional capabilities versus invalid types; a declared capability versus tested behavior; and a missing capture of HTTP context versus a bad response. The import envelope preserves those distinctions. URL parsers can silently repair malformed inputs, so independent assertions inspect raw URL characters first and compare the original endpoint without normalizing it. Local HTTP discovery remains a labelled development deviation, not a conformant result. After explicit raw URI syntax prechecks, IPvFuture, numeric ports outside u16 and reg-name forms rejected by WHATWG parsing remain visibly unresolved, not normative failures inferred from a library error. Passing those prechecks doesn't establish all host UTF-8/IDNA or URI production semantics. Exact identity can still be compared; malformed literals, percent triplets and nondigit ports fail independently of library acceptance. The safe import profile additionally rejects userinfo under the recipient SHOULD in RFC 9110 section 4.2.4, with a policy-specific finding rather than an invented GNAP MUST. Discovery context supplied with another message kind produces an explicit error, rather than being dropped.

Tests cover the actual diagnostic routes, fixed outbound OPTIONS request shape, bounded response adapter, redirects/authentication failures as response fixtures, malformed documents and redacted reports. These fixture tests don't themselves make a network round trip or exercise remote capability implementations.

## Lessons from the RFC 9767 imports

The workbench independently checks selected JSON rules for RS-facing AS discovery, introspection requests/responses, resource registration requests/responses, downstream derivation grant messages and RS-facing errors. It reuses the registry as reference data, not SDK validators as the oracle. Probes, consent and target allowlists are unchanged. The synthetic fixtures test the diagnostics only.

RS-facing errors need their own registry and §3.5 response convention, not accidental reuse of core AS errors.

The normative `iss` requirement outranks the example that omits it. No example may require HTTP 200 or a single header.

Request `proof` is recommended and `access` optional. A context-free validator mustn't invent mandatory fields for convenience.

Bound/bearer rules need conditional assertions. Caller-declared `RsContext` permits comparisons but isn't trusted state and can't override a bearer/key contradiction. Outer key shape can't prove a valid key or token binding.

Unknown extensions and resource-type semantics remain untested; membership in a registry can't establish the full processing of a parameter, or the effective rights it grants.

Lossy JSON maps and URL normalization can hide ambiguity. Duplicate members and parser limitations remain inconclusive, and identity compares the original strings.

Next evidence needs RS requests signed with the RS's own key, working tokens and negative tests for revocation, audience and rights. An application's `/resource-check` isn't RFC 9767 introspection. This increment adds no private-key upload or public credentialed probe.

### Resource registration

A `resource_reference` is an access-rights reference, not an access token. Reusing the validation of token values here would introduce restrictions that have nothing to do with it.

Registration delegates access syntax to RFC 9635 §8. Its REQUIRED object `type` takes precedence over the incomplete §3.4 example. An empty access array mustn't be rejected merely because a particular AS policy needs rights.

Token format registry membership and AS/RS compatibility are different questions. A current known format or an empty list can't attest an intersection; unknown names need registry review rather than permanent rejection. In particular, the SDK's opaque-token deployment policy doesn't make `opaque` an IANA format name: it is absent from this vendored registry. The synthetic positive registry fixture uses the registered name `biscuit`; it doesn't claim that any server supports Biscuit registration.

`token_introspection_required` needs per-RS authorization and actual AS capabilities to exercise the required error behavior. An imported boolean or endpoint string can't supply that evidence. No declared context replaces an authenticated exchange in these imports.

The response endpoint receives a string-type check only, not discovery's URI profile. The report explicitly leaves URI syntax, transport and actual service behavior untested. Additional members remain extensions to review, not errors introduced by a closed SDK shape.

The new synthetic fixtures exercise these distinctions, nested duplicate-name ambiguity, parser limits and redacted HTTP reports. They don't attest a running registration endpoint, RS key ownership or reference persistence. The network probes, and their consent and allowlist policies, stay exactly as they were.

### Downstream derivation

RFC 9767 §4 reuses GNAP's ordinary grant messages and client role. An RS-facing `resource_server` field can't replace `client`; identifying RS1 is distinct from proving its own key or the incoming token's suitability for it.

A diagnostic can select token requests without making `access_token` mandatory for every possible GNAP grant request. Multiple-token arrays, interaction, subject information and extensions mustn't be rejected because the application chose a simpler profile.

The grant response has no dedicated proof-of-derivation field. Its string token value and rights can't demonstrate parent-child lineage, downscope, downstream audience, consent or linked revocation. Those require an actual authenticated scenario, and local token attenuation is an entirely separate path.

Independent assertions need precise names and limits. The value assertion checks only string shape; its token68 encoding stays explicitly untested. Outer key, management, continuation, interaction and error types don't validate contents or protocol applicability either.

Request and response arrays have their own label rules. One imported response can't establish label correspondence or matching cardinality. Empty arrays mustn't produce fictitious per-token passes. A response without an access token observes no issuance.

The new fixtures and offline tests exercise these distinctions without querying an AS. They upload no private proof material, infer no network authority from declared context and leave the existing probe/consent/allowlist policy unchanged.

## Resolved during development

Combining the discovery and introspection imports exposed an existing UI race: an in-flight response could restore a report after Clear or a message-type change. The same problem affected probe results and late errors. Each new panel generation invalidates older results, including responses still being decoded. This doesn't cancel network requests or undo a probe already sent. A dependency-free JavaScript regression runs in CI with a strict DOM test double; it verifies this behavior, not browser rendering or GNAP conformance.

A separate [manual network smoke](LIVE_SMOKE.md) on 2026-09-05 did exercise the local workbench's real outbound HTTPS OPTIONS path to the deployed test AS: 8 checks passed, none failed, and 5 stayed explicitly untested. The shared cooldown also rejected a different operation eleven seconds later. Reading the actual report exposed a small usability issue: the key-rotation declaration finding states explicitly when the AS declares that feature unsupported. This was rechecked over the real network after rebuilding, without changing the assertions or claiming that any rotation was executed.
