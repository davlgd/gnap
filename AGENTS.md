# AGENTS.md

This file points coding agents to the rules of this repository, which all apply to agents. Before you change anything, read [CONTRIBUTING.md](CONTRIBUTING.md), the [support matrix](docs/support-matrix.md) for the profile you touch, and the code you change.

## Work rules

- Read the assertions of a test before you cite it as evidence
- Confirm that a check examined something before you trust its result
- Fix a generated file through its generator, never by hand
- Define each security bound as a constant of this project
- Depend on published crate releases only
- Attribute each measurement, and keep local, CI, and hosted results apart
- Record each change to a crate's public API in the [changelog](CHANGELOG.md)
- Compare what a check examined before and after you move code, not only its verdict
- Mutate each new security or correctness boundary, and see a test fail for the expected reason
- Make a refusal test fail for the reason it names, not at an earlier guard
- Drive the path a user takes, such as a page or an HTTP route, when you claim an end-to-end behavior
- Keep the sources unchanged while a check runs, and name a commit only for the sources it holds
- Let a test delete only a path it created, under a unique temporary name
- Keep the evidence you cite, failed runs included, each in its own file

A refusal test can contain the very value you think it accepts, and a linter that finds no file, or a tool that isn't installed, can still exit with 0. The generated files are `crates/gnap-registry/src/generated.rs`, `conformance/clauses.json`, and `conformance/REPORT.md`. A bound borrowed from a dependency, such as a key size, changes silently when the dependency does.

A mutation that stops the code from compiling proves nothing about a test: mutate an isolated copy, and check that the assertion which fails is the one about that boundary. A test that reaches a function directly can miss a defect of the route in front of it.

The evidence receipts in `conformance/` record the digests of the sources they ran and of `tools/conformance_ledger.py` itself. Changing either makes `python3 -B tools/conformance_ledger.py check` fail until you replay the receipts, as the [ledger guide](conformance/README.md#replay-provenance-and-publication) explains. Archive a replaced receipt byte for byte, and never rewrite an existing one to make the check pass.

## Before you report a change as done

- Run the [checks](CONTRIBUTING.md#check-your-change), and the full set in the [verification guide](docs/verification.md) when you touch an application, a generator, or the ledger
- Read each Markdown file you change as GitHub renders it, at its file view width of 1,012 pixels
- Verify that the remote branch holds your commit after you push it, before you report the change or reply to a review
- Write each commit subject with the [commit conventions](CONTRIBUTING.md#commit-messages), and check it with `mise run lint:commits`
- Keep documentation, structural, and behavioral changes in separate commits when you can

## Actions with external effects

Deploy, publish to a registry, change a repository setting, or delete a branch only when the maintainer has asked for it. Run a mutating hosted test on a temporary deployment unless the maintainer names a public instance, and once the test ends, record the revision each one ran, then delete only the resources you created for it. A branch can be deleted once its exact commits are reachable from `main` or archived, and nothing uses it: no open review, worktree, deployment, or documentation link. Never commit keys, credentials, account identifiers, or real user data.

Print the names of environment variables rather than a global dump, and show a value only when it isn't secret. Pass a secret through standard input or a private file, never as a command argument. A line filter doesn't hide a value that spans several lines, such as a PEM key.
