# Improve the libraries through applications

Applications reveal integration problems that isolated protocol tests miss: unclear setup, inconvenient APIs, missing transport assumptions, and behavior that changes when a service restarts. The example applications use the same public APIs as anyone else.

## Start with a user task

Choose a concrete operation, then implement it without reaching into another role's private state. Record the revision, configuration, attempted code, expected result and observed behavior. A minimal failing example is more useful than a general request for a nicer API.

The three consumers explore different boundaries:

| Consumer | Task | Integration questions |
| --- | --- | --- |
| [Delegation lab](../apps/delegation-demo/README.md) | Negotiate access, obtain tokens and use protected resources | Consent, continuation, token management and authenticated introspection |
| [Biscuit files](../apps/biscuit-files/README.md) | Restrict access locally and enforce it across three services | Rights mapping, request proof, authority revocation and restart behavior |
| [Diagnostic workbench](../apps/conformance-web/README.md) | Explain a message or exercise an approved endpoint | Useful diagnostics, malformed input, bounded network access and evidence quality |

These applications have separate Cargo workspaces and dependency locks. They consume library APIs through path dependencies instead of bypassing them for a demonstration.

## Turn friction into a reusable improvement

1. Reproduce the problem through the application's public integration path
2. Decide whether it's a protocol rule, an application policy, or a missing library primitive
3. Add a focused regression test, make the correction, and update the guide
4. Repeat the user task over the relevant transport, including a refused case
5. Review the change, and record what you actually exercised

The feedback reports of the applications record concrete API and documentation lessons: [delegation](../apps/delegation-demo/DEVELOPER_FEEDBACK.md), [Biscuit](../apps/biscuit-files/DEVELOPER_FEEDBACK.md) and [diagnostics](../apps/conformance-web/DEVELOPER_FEEDBACK.md). Keep reproducible findings public; personal task lists and draft reviews don't belong in those reports.

## Keep policy, proof and evidence separate

The specification defines the protocol requirements. An application's fixed rights, synthetic identity, lifetimes or shared files are selected policies, not additional GNAP mandates. Put capability decisions and their current implementation evidence in the [support matrix](support-matrix.md).

A successful self-interoperability test doesn't establish compatibility with an unrelated implementation. A diagnostic that uses the SDK's own parser isn't an independent parsing oracle. Describe local execution, hosted observations and genuinely independent evidence separately, following the [verification guide](verification.md).

Performance claims need a reproducible workload and measurements: revision, build mode, request count, concurrency and environment. A successful request alone isn't an efficiency benchmark.

## Exercise services safely

Use synthetic data and dedicated demonstration keys. Never publish credentials, log imported secrets or test arbitrary endpoints without permission. Bound request sizes, processing, state retention and concurrency. Browser actions need appropriate session isolation and cross-site request protection.

The application guides describe each network and deployment boundary. Durable storage, operational key management and real user authentication require their own integration work; an example's successful test doesn't supply them.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution and review conventions.
