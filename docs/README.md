# Documentation

Start with [Getting started](getting-started.md) to run a grant and integrate a
client, authorization server or resource server. The [architecture guide](architecture.md)
explains where protocol handling ends and application responsibilities begin.

## Applications

| Application | Guide | Hosted example |
| --- | --- | --- |
| Delegation lab | [Setup, consent and token management](../apps/delegation-demo/README.md) | [Open the lab](https://gnap-delegation.cleverapps.io) |
| Biscuit files | [Separate client, AS and RS](../apps/biscuit-files/README.md), [deployment and acceptance](biscuit-public-delivery.md) | [Open the client](https://gnap-biscuit.cleverapps.io) |
| Diagnostic workbench | [Import analysis and network probes](../apps/conformance-web/README.md) | [Open the workbench](https://gnap-conformance.cleverapps.io) |

These are synthetic, stateful teaching sandboxes, not production identity or
document services. Active probes require permission; use the application guides
to configure a local instance and understand its network and key boundaries.

## Build an authorization flow

- [Multiple access tokens](multiple-access-tokens.md): request labelled tokens,
  approve a subset and manage each independently.
- [Secondary-device interaction](secondary-device-interaction.md): code entry,
  owner consent and polling with separate client and owner sessions.
- [Push finish](push-finish.md): deliver the interaction result from the AS to
  the client and validate its binding to the grant.
- [Subject assertions](subject-assertions.md): request and verify identity
  information with pinned issuer, audience and session bindings.

## Protect a resource

- [Resource-server SDK](resource-server-sdk.md): combine trusted opaque-token
  introspection with local proof, replay, time and access checks.
- [Downstream delegation](downstream-delegation.md): use an existing opaque
  token to obtain a bounded, one-hop token for another resource server.
- [Biscuit file profile](../crates/gnap-biscuit/README.md): issue and attenuate
  structured tokens, verify requests and enforce live authority state.

## Test an integration

- [Authenticated workbench scenario](authenticated-workbench.md): configure an
  approved client key and exercise a signed lifecycle against an allowed AS/RS pair.
- [Verification tooling](verification.md): run documentation, registry, protocol
  and application checks, and interpret what their results establish.
- [Preparing the 0.1.0 crates](releasing.md): inspect package contents and plan
  dependency-ordered publication without uploading anything during preparation.
- [Application-driven development](ecosystem-development.md): report integration
  friction and turn it into reusable library improvements.
- [GNAP and modern OAuth](gnap-and-modern-oauth.md): understand the design choices
  without overlooking modern OAuth extensions.

## Support and evidence

The [support matrix](support-matrix.md) is the capability inventory and home for
remaining work. The [normative ledger](../conformance/README.md) preserves RFC
source context and maps reviewed observations; its [report](../conformance/REPORT.md)
is not an overall certification score.

Historical observations are kept separately from setup instructions:

- [5 September validation](validation-2026-09-05.md): initial application checks.
- [6 September validation](validation-2026-09-06.md): hosted delegation and diagnostics.
- [Discovery network smoke](../apps/conformance-web/LIVE_SMOKE.md): a local
  workbench calling the hosted AS.
- [Authenticated workbench delivery](https://github.com/davlgd/gnap/pull/31#issuecomment-5562455692):
  the reviewed revision and hosted approval/denial observations.
- [Biscuit public delivery](https://github.com/davlgd/gnap/pull/32#issuecomment-5562885907):
  the reviewed revision, HTTPS acceptance and operator-controlled maintenance.

Each record describes its own revision, date and scope. It is not a guarantee
that a hosted deployment remains unchanged or that another implementation will
interoperate with it.
