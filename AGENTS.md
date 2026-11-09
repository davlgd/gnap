# AGENTS.md

This file points coding agents to the rules of this repository, which all apply to agents. Before you change anything, read [CONTRIBUTING.md](CONTRIBUTING.md), the [support matrix](docs/support-matrix.md) for the profile you touch, and the code you change.

## Work rules

- Read the assertions of a test before you cite it as evidence
- Confirm that a check examined something before you trust its result
- Fix a generated file through its generator, never by hand
- Define each security bound as a constant of this project
- Depend on published crate releases only
- Attribute each measurement, and keep local, CI, and hosted results apart

A refusal test can contain the very value you think it accepts, and a linter that finds no file, or a tool that isn't installed, can still exit with 0. The generated files are `crates/gnap-registry/src/generated.rs`, `conformance/clauses.json`, and `conformance/REPORT.md`. A bound borrowed from a dependency, such as a key size, changes silently when the dependency does.

The evidence receipts in `conformance/` record the digests of the sources they ran and of `tools/conformance_ledger.py` itself. Changing either makes `python3 -B tools/conformance_ledger.py check` fail until you replay the receipts, as the [ledger guide](conformance/README.md#replay-provenance-and-publication) explains. Archive a replaced receipt byte for byte, and never rewrite an existing one to make the check pass.

## Before you report a change as done

- Run the [checks](CONTRIBUTING.md#check-your-change), and the full set in the [verification guide](docs/verification.md) when you touch an application, a generator, or the ledger
- Read each Markdown file you change as GitHub renders it, at its file view width of 1,012 pixels
- Verify that the remote branch holds your commit after you push it, before you report the change or reply to a review
- Write each commit subject with the [commit conventions](CONTRIBUTING.md#commit-messages), and check it with `mise run lint:commits`
- Keep documentation, structural, and behavioral changes in separate commits when you can

## Actions with external effects

Deploy, publish to a registry, change a repository setting, or delete a branch only when the maintainer has asked for it. A branch can be deleted once its exact commits are reachable from `main` or archived, and nothing uses it: no open review, worktree, deployment, or documentation link. Never commit keys, credentials, account identifiers, or real user data.
