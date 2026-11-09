# Verification

This guide lists every check of the repository, the command that runs it, and what its result establishes. Run the commands from the repository root. The [CI workflow](../.github/workflows/ci.yml) is the authoritative list: each section below matches one of its jobs, and a repository ruleset lets a pull request merge only once they all pass.

A passing check proves less than it seems. A test between this project's own roles shows that they agree with each other, not that an independent implementation would. A transport failure isn't an authorization refusal, and local HTTP isn't hosted TLS.

## Formatting, documentation, and commits

CI runs these first, and starts the costly jobs only once they pass. They use the tools pinned in [`mise.toml`](../mise.toml): review the file, trust it with `mise trust`, then run `mise install`.

```bash
cargo fmt --all --check
for app in delegation-demo conformance-web biscuit-files; do
  cargo fmt --manifest-path "apps/$app/Cargo.toml" --check
done
mise run lint:docs
mise run lint:commits
```

The three applications are separate Cargo workspaces, which `cargo fmt --all` doesn't reach. `lint:docs` runs markdownlint on the tracked Markdown files, then lychee, offline, on their internal links and anchors: links to this repository on github.com resolve against your working tree. It doesn't check external URLs or the quality of the prose. `lint:commits` checks the commits of your branch against [`commitlint.config.mjs`](../commitlint.config.mjs).

## Rust lint, tests, and documentation

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
```

The workspace turns on clippy's `pedantic` and `nursery` groups, and CI fails on any warning. The tests read the [protocol vectors](../vectors) and the [state-machine model](../vectors/state-machine.json): exploring a finite set of sequences checks the chosen model and inputs, not every possible history. CI also runs every example, because they document the libraries as much as they test them.

## Minimum supported Rust version

```bash
cargo +1.95.0 build --workspace --locked
```

This builds the committed dependency graph with the declared minimum version. The packaging checks of the [releasing guide](releasing.md) also run with this version, and are tested with Cargo 1.98.

## Claims about the RFCs

```bash
python3 -B -m unittest discover -s tools/tests -v
python3 -B tools/check_quotes.py
python3 -B tools/check_getting_started.py
python3 -B tools/check_package_assets.py
python3 -B tools/conformance_ledger.py check
python3 -B tools/conformance_ledger.py run-tests
python3 -B tools/conformance_ledger.py discovery-tests
```

These tools need Python 3.11 or newer, and no third-party package.

`check_quotes.py` checks the double-quoted passages of five words or more that sit near an RFC citation in a Rust comment, against the RFC text. It reads the `.rs` files under `crates/*/` and `apps/*/`, in their `src`, `tests`, and `examples` directories, and downloads the RFC texts it misses. It normalizes whitespace, quotation marks, emphasis, and line-break hyphenation, and accepts an explicit `[...]` elision. It verifies these quotations, not paraphrases, section references, or protocol conformance.

`check_getting_started.py` runs the `flow` example and compares its output with the transcript in [Getting started](getting-started.md). `check_package_assets.py` checks that each crate carries its license and README, that every file it includes with `include_str!` or `include_bytes!` sits inside the crate, and that its test fixtures match their canonical copies.

`conformance_ledger.py check` is offline and read-only: it verifies the vendored RFC sources, the evidence receipts, and the generated inventory. Its `run-tests` command tests the ledger tooling itself, not GNAP. Its `discovery-tests` command runs six independent assertions on a discovery response: against the bundled synthetic fixture by default, or against a reviewed capture, which gives a dated observation of one server, not a proof of conformance. The [ledger guide](../conformance/README.md) explains the inventory, the applicability decisions, and the receipts.

## Applications

Each application is a separate workspace with its own lockfile and tested toolchain, documented in its guide. Biscuit files needs Rust 1.98 and Unix, because its key files rely on Unix permission modes.

```bash
node --test apps/conformance-web/tests/ui/*.test.mjs apps/delegation-demo/tests/ui/*.test.mjs
for app in delegation-demo conformance-web biscuit-files; do
  cargo clippy --manifest-path "apps/$app/Cargo.toml" --all-targets --locked -- -D warnings
  cargo test --manifest-path "apps/$app/Cargo.toml" --locked
done
```

CI then starts the applications on the loopback interface and drives them with [`smoke_ecosystem.py`](../tools/smoke_ecosystem.py), [`smoke_lifecycle.py`](../tools/smoke_lifecycle.py), and [`smoke_biscuit.py`](../tools/smoke_biscuit.py). These scenarios use plain HTTP, so they don't exercise certificate validation.

The applications make HTTPS requests through rustls, which loads the certificate authorities of the system on Linux and fails if it finds none. Install the system CA bundle in a deployment image, and a C compiler, which the AWS-LC cryptographic backend needs to build. Check an outbound HTTPS request from the target image before you deploy. The SDK crates don't depend on this stack.

## IANA registries

```bash
python3 tools/generate_registry.py
python3 tools/fetch_registries.py
python3 tools/generate_registry.py
```

The first command regenerates `crates/gnap-registry/src/generated.rs` from the vendored copies in `registries/`, offline: CI fails if the result differs from the committed file. The other two download the current registries and regenerate from them, to show whether IANA has changed something. CI reports such a change as a warning, and doesn't fail when IANA is unreachable. Review a regenerated file together with the source data it comes from, in the same pull request.

## Dependencies

CI doesn't run these checks, because their result depends on an external advisory database that changes without any change to this repository. Install [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) with `cargo install --locked cargo-deny`, then run it on the four workspaces with the policy of [`deny.toml`](../deny.toml):

```bash
cargo deny check
for app in delegation-demo conformance-web biscuit-files; do
  (cd "apps/$app" && cargo deny check)
done
```

The licenses, sources, and bans pass on all four workspaces. The advisories of the SDK and of Biscuit files report one vulnerability, [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) on `crypto-bigint` 0.5.5, which `biscuit-auth` 6.0.0 pulls in: `crypto-bigint` 0.7.6 fixes it, but on 2026-11-09 no published Biscuit release drops 0.5.5, and one warning that `proc-macro-error2` is unmaintained, [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html). The other two applications report no advisory.

## Hosted acceptance

The [delegation lab](../apps/delegation-demo/README.md), the [authenticated workbench](authenticated-workbench.md), and the [Biscuit delivery guide](biscuit-public-delivery.md) describe opt-in scenarios against deployed applications. Run them only against a target you're authorized to test, with disposable state and synthetic data. The maintenance mode of Biscuit interrupts the shared service, and needs explicit operator actions.

Record the revision, the environment, and the observed outcome. A result the client reports isn't an independent capture of what crossed the wire. The [documentation index](README.md#dated-records) lists the dated observations already published.
