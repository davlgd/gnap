# Documentation

Start with [Getting started](getting-started.md) to run a grant, then integrate a client, an authorization server, or a resource server. The [architecture guide](architecture.md) explains where protocol handling ends and the responsibilities of your application begin.

## Applications

- [Delegation lab](../apps/delegation-demo/README.md): consent, token management, and identity in one application
- [Biscuit files](../apps/biscuit-files/README.md): a separate client, authorization server, and resource server
- [Biscuit delivery](biscuit-public-delivery.md): deploy the Biscuit example and run its acceptance checks
- [Diagnostic workbench](../apps/conformance-web/README.md): analyze GNAP messages and probe approved servers

The root [README](../README.md#try-the-applications) links to the hosted instances, which are synthetic sandboxes with volatile state, not production services.

## Build an authorization flow

- [Multiple access tokens](multiple-access-tokens.md): request labelled tokens and manage each one on its own
- [Secondary-device interaction](secondary-device-interaction.md): let the owner approve with a code on another device
- [Push finish](push-finish.md): deliver the interaction result from the server to the client
- [Subject assertions](subject-assertions.md): request and verify identity information about the owner

## Protect a resource

- [Resource-server SDK](resource-server-sdk.md): check opaque tokens with introspection and local proof checks
- [Downstream delegation](downstream-delegation.md): exchange a token for a bounded token for another server
- [Biscuit file profile](../crates/gnap-biscuit/README.md): issue, attenuate, and verify structured tokens

## Test an integration

- [Authenticated workbench](authenticated-workbench.md): drive a signed lifecycle against an approved server pair
- [Verification](verification.md): run every check and understand what its result establishes
- [Releasing](releasing.md): check the package contents and plan the publication order
- [Application-driven development](ecosystem-development.md): turn integration friction into library improvements
- [GNAP and modern OAuth](gnap-and-modern-oauth.md): compare the design of GNAP with modern OAuth extensions

## Support and evidence

The [support matrix](support-matrix.md) lists each capability with its state and limits. The [evidence ledger](../conformance/README.md) keeps the RFC source text and maps reviewed observations to it; its [report](../conformance/REPORT.md) is not a conformance score.

## Dated records

These records describe what was observed at one revision and date. They stay unchanged where they were published, and they don't guarantee that a hosted deployment still behaves the same way, or that another implementation interoperates with it.

- [5 September 2026 validation](validation-2026-09-05.md): first checks of the applications
- [6 September 2026 validation](validation-2026-09-06.md): hosted delegation and diagnostics
- [Discovery network smoke](../apps/conformance-web/LIVE_SMOKE.md): a local workbench calling the hosted server
- [Authenticated workbench delivery](https://github.com/davlgd/gnap/pull/31#issuecomment-5562455692): hosted approval and denial
- [Biscuit public delivery](https://github.com/davlgd/gnap/pull/32#issuecomment-5562885907): HTTPS acceptance and maintenance
