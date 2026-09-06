# Contributing

Contributions should make the libraries, examples or documentation easier to
use correctly. Start with [Getting started](docs/getting-started.md), then
consult the [support matrix](docs/support-matrix.md) for the profile you want to
change.

## Propose a focused change

Describe the user task, the problem and how to reproduce it. An integration
report should include the relevant revision, a minimal example, expected and
observed behavior, and enough context to distinguish protocol rules from
application policy. Use synthetic data and remove credentials.

Keep each pull request focused. Explain why the change is useful, add regression
tests for corrected failures, and update the affected guides and support claims.
Do not add unused abstractions or report unsupported behavior as successful.
The [application-driven method](docs/ecosystem-development.md) explains how
consumer feedback informs SDK changes.

Write public documentation, commit subjects and pull requests in clear English.
Use short, descriptive commit subjects and plain-language PR descriptions;
explain the decision and useful evidence rather than listing every changed file.
Keep commit messages to the subject line. Contributors use their own Git identity.

## Verify your change

The [CI workflow](.github/workflows/ci.yml) is the canonical command list.
Common checks from the repository root are:

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
python3 -B -m unittest discover -s tools/tests -v
python3 -B tools/check_readme.py
python3 -B tools/check_quotes.py
python3 -B tools/conformance_ledger.py check
```

The standalone applications need their own test commands and Rust toolchain;
see their READMEs. Network-bound changes need successful and refused requests,
not only unit tests. Report local, CI and hosted results separately.
[Verification tooling](docs/verification.md) explains what each check covers.
The [release guide](docs/releasing.md) covers package preparation; publication
requires a separate maintainer decision.

For generated data, change the generator or reviewed source input and reproduce
the artifact before checking for upstream drift. Do not edit generated output
to hide a mismatch. Protocol tests should cite the RFC requirement they exercise.

## Document for the reader

Keep the root README focused on what a user can do and where to begin.
Put integration instructions in task-oriented guides, capability inventory in
the support matrix, and dated observations in evidence records. Link to the
authoritative description instead of maintaining competing status summaries.

Keep useful integration feedback and reproducible evidence public. Personal
plans, draft reviews, account identifiers and temporary operational notes belong
in ignored local files, not the public documentation. Never commit private keys,
deployment credentials or real user data. Clearly identify public test fixtures
and preserve their third-party notices.

## Review and publication

Open a pull request with the relevant checks and meaningful limitations.
Address review findings with a correction or reproducible evidence for a
disagreement. Maintainers merge reviewed changes after the current revision's
CI checks pass; an older review or a resolved thread does not verify new code.
Maintainer-led work includes adversarial and automated code review before a
regular merge commit. Personal review coordination stays in local maintainer notes.

A contribution does not authorize deployments or changes to external services.
Hosted tests require explicit permission for the target and their side effects.
The [application guides](docs/README.md#applications) document the public
sandboxes and their safety boundaries.

The repository is licensed under [Apache-2.0](LICENSE); third-party fixture
notices remain applicable.
