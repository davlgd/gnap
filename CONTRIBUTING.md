# Contributing

This document explains how to propose, check, and submit a change to the GNAP libraries, applications, or documentation. Human contributors and coding agents follow it, with the guides it links to:

| To                                                      | Read                                          |
| ------------------------------------------------------- | --------------------------------------------- |
| Run a first grant and integrate a protocol role         | [Getting started](docs/getting-started.md)    |
| Know what the libraries support                         | [Support matrix](docs/support-matrix.md)      |
| Run every check and understand what it proves           | [Verification](docs/verification.md)          |
| Prepare a release                                       | [Releasing](docs/releasing.md)                |
| Work as a coding agent                                  | [AGENTS.md](AGENTS.md), then this document    |

## Propose a change

Describe the task you were trying to complete, what went wrong, and how to reproduce it. An integration report helps most with the revision you used, a minimal example, the expected and the observed behavior, and enough context to tell a protocol rule from an application policy. Use synthetic data, and remove credentials before you share anything.

Keep each pull request focused on one change: the quality of a review drops as its size grows. Explain why the change is useful, add a regression test for each failure you fix, and update the guides and support claims it affects.

## Check your change

Run these checks from the repository root before you push. The documentation and commit checks use the tools pinned in [`mise.toml`](mise.toml): install [mise](https://mise.jdx.dev/getting-started.html), review `mise.toml` and trust it with `mise trust`, then run `mise install`. The [verification guide](docs/verification.md) lists the complete set, including the standalone applications and the evidence ledger, and explains what each one establishes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
mise run lint:docs
```

A check that passes doesn't prove everything. A change that touches the network needs both a successful and a refused request, not only unit tests. Report local, CI, and hosted results separately, and don't present one as another.

## Code quality

The code aims for what an experienced Rust reviewer expects to find, so that a review has little to correct. The workspace turns on clippy's `pedantic` and `nursery` groups, and CI fails on any warning:

- Idiomatic, current Rust within the declared minimum version, with no warnings
- No dead code, commented-out code, or abstraction without a second use
- One responsibility per module, small traits, and transport, storage, time, and randomness injected rather than hardcoded
- Typed errors, and no panic on input that comes from outside the process
- The smallest public API that serves the use case, every public item documented
- A test for each behavior, with the refusal cases next to the successful ones

Comments explain why the code does something non-obvious, not what it does. References to the RFCs, such as `GNAP-9635-§7.3.1`, and the literal quotations next to them, are the project's normative traceability: keep them, and keep the quotations exact, because CI compares them with the vendored RFC text.

Own the security bounds you enforce, such as a key size or a decoded length, as named constants of this project. A limit borrowed from a dependency changes silently when the dependency does. Depend only on published crate releases, never on a Git revision, and explain in the pull request why each new dependency is needed.

## Write documentation

Write for readers who don't know the project yet. Address them directly in the second person, in the active voice, and in the present tense: describe how the code behaves, without promises such as *soon*, *for now*, or *not yet*. Prefer plain words and contractions, and remove phrases that delay the point, such as *note that*, *simply*, or *just*. Write *for example* and *that is* instead of *e.g.* and *i.e.*

Keep a sentence under 25 words when possible, and a paragraph to about 80 words. Prefer prose to lists, and keep each list item to one line. Write each paragraph on a single line of the source file, and let the editor wrap it.

Give each fact one home and link to it from elsewhere:

- The root README says what the project does and where to start
- The guides in `docs/` explain one task each
- The [support matrix](docs/support-matrix.md) is the inventory of capabilities and limits
- `docs/history/` keeps dated observations, which are never rewritten

Each crate README is the page readers see on crates.io, so it stays self-contained and can repeat the minimum Rust version.

State what the code does, not what it should do. A claim of support links to the test that shows it, and nothing is called conformant without that evidence. Run every command you document, show its real output, and give every code block a language. To check a page, push your branch and read the file on GitHub, whose file view is 1,012 pixels wide: a list item shouldn't wrap, and the last line of a paragraph shouldn't hold only a few words.

## Commit messages

Write each commit as a single [Conventional Commits](https://www.conventionalcommits.org/) header, `type(scope): subject`, without a body or a trailer. The scope names the crate or the area you change, such as `crypto`, `as`, or `workbench`:

```text
feat(crypto): add Ed25519 request signatures
fix(as): reject a reused interaction nonce
docs: rewrite the contributing guide
chore(deps): upgrade the RustCrypto stack
```

The type is one of `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`, or `revert`. Start the subject with a lowercase imperative verb, keep the header to 100 characters, and don't end it with a period. Run `mise run lint:commits` to check the commits of your branch; CI checks those of each pull request with the rules of [`commitlint.config.mjs`](commitlint.config.mjs).

Name the branch after the type of its main change, such as `feat/ed25519-signatures` or `docs/contributing-guide`.

## Open a pull request

Describe the pull request briefly: its main lines, its reason, how you verified it, and the limits a reviewer needs to know. Don't list every changed file. A Copilot review runs when you open the pull request and after each push.

Address each finding with a correction, or with reproducible evidence when you disagree. An approval doesn't cover what you push after it.

## Review and merge

Judge the work, not the author, with the same criteria for every contribution. When you ask for a change, show it and explain why.

Maintainers merge a pull request once CI passes on its latest commit, with a regular merge commit. The [evidence ledger](conformance/README.md) records commit identifiers, and a squash or a rebase that drops one of them makes its receipts unverifiable, so never rebase a branch that carries receipts.

## Safety

A contribution doesn't authorize a deployment or a change to an external service: a hosted test needs explicit permission for its target and its side effects. Never commit private keys, credentials, or real user data. Mark public test fixtures as such, and keep the third-party notices that come with them.

## License

The repository is licensed under [Apache-2.0](LICENSE), and the third-party notices of its test fixtures still apply.
