# Verification tooling

Run commands from the repository root. The [CI workflow](../.github/workflows/ci.yml)
is the authoritative list for pull requests; application READMEs document their
separate toolchains and acceptance scenarios.

## Documentation and source checks

```sh
python3 -B -m unittest discover -s tools/tests -v
python3 -B tools/check_readme.py
python3 -B tools/check_quotes.py
python3 -B tools/check_package_assets.py
```

`check_readme.py` retains its command name but checks the narrated grant
transcript in [Getting started](getting-started.md). It runs the real `flow`
example and compares its output with the published block. It does not infer
implementation support from section numbers or depend on a private requirements
directory. Support claims are reviewed in the [matrix](support-matrix.md).

`check_quotes.py` checks double-quoted passages of at least five words in Rust
comments near RFC citations, excluding documentation code blocks. It selects
`.rs` files recursively under `crates/*/{src,tests,examples}` and
`apps/*/{src,tests,examples}` without following symlinks. Usual Cargo `target`
directories are outside those roots; a custom build directory inside a source
root is not automatically excluded. Names such as `fixtures`, `vendor` or
`external` do not exclude Rust modules within a selected source root.

The checker downloads missing RFC texts and compares selected passages after
normalizing whitespace, quotation marks, backticks, emphasis and line-break
hyphenation. It accepts an explicit `[...]` elision. Non-Rust inputs and Rust
files outside the selected roots are not covered. This verifies selected
quotations, not paraphrases, all section references or protocol conformance.

## Protocol tests and registries

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
```

Tests consume [protocol vectors](../vectors) and the
[state-machine model](../vectors/state-machine.json). Finite sequence exploration
checks the chosen model and inputs, not every possible history. Exchanges between
this project's own SDK roles do not establish independent interoperability.

To refresh IANA input data and reproduce the registry artifact:

```sh
python3 tools/fetch_registries.py
python3 tools/generate_registry.py
```

The fetch uses the network; generation uses the vendored CSV files and installed
`rustfmt`. Review source and generated changes together. CI checks reproduction
from the vendored input separately from upstream drift.

## Normative evidence ledger

```sh
python3 -B tools/conformance_ledger.py check
python3 -B tools/conformance_ledger.py run-tests
python3 -B tools/conformance_ledger.py discovery-tests
```

The [ledger guide](../conformance/README.md) explains the pinned source inventory,
applicability decisions and execution receipts. `check` is offline and read-only.
The regression commands test the accounting and discovery-test tooling; their
success is not proof that GNAP is implemented. Machine-generated receipts remain
local unless deliberately reviewed and published as evidence.

## HTTP acceptance

The [delegation application](../apps/delegation-demo/README.md),
[authenticated workbench](authenticated-workbench.md) and
[Biscuit delivery guide](biscuit-public-delivery.md) describe opt-in scenarios.
Use them only against authorized targets, with disposable state and synthetic
data. Biscuit's maintenance mode additionally requires explicit operator actions
that interrupt the shared service.

Record the revision, execution environment and observed outcome. A transport
failure is not an authorization refusal; a client-reported result is not an
independent wire capture; local HTTP is not hosted TLS validation. The
[evidence index](README.md#support-and-evidence) links dated public observations.
