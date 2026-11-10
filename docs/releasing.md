# Releasing the crates

This guide releases a new version of the twelve SDK crates on crates.io, where version 0.1.0 is published. Users add them as registry dependencies, as [Getting started](getting-started.md#add-the-libraries-to-your-application) shows. The HTTP applications are examples, not packages of the release.

Publishing is a separate decision of the maintainer. Don't upload a package, create a release tag, or change registry ownership while you check the packages. A published version is effectively permanent, as Cargo's [publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html) explains.

## Choose the toolchain

Workspace publishing needs Cargo 1.90 or newer, so the declared minimum, Rust 1.95, can run every command of this guide. The packaging workflow is tested with Cargo 1.98, which remains the recommended version. The [mise tasks](../mise.toml) below use the Cargo on your `PATH`, without installing a toolchain. The asset check needs Python 3.11 or newer.

## Check the package contents

Start from a clean, reviewed revision whose CI passes:

```bash
python3 -B tools/check_package_assets.py
cargo package --workspace --list --locked
cargo package --workspace --locked
```

The asset check verifies each crate's README, documentation URL, inherited SPDX license, embedded-file paths, and its exact copies of the canonical licenses and test fixtures. It doesn't inspect every build input, nor scan for secrets. The copies are listed in [`package-assets.json`](../tools/package-assets.json): update a canonical file and its copies together.

Review the actual file list, tests and examples included, rather than assuming that the ignore rules of Git make a complete publication policy. The RFC-derived test keys are public fixtures that keep their provenance notices, and must never become deployment credentials.

Cargo writes the archives under `target/package`. In a workspace, it verifies the new versions together through a temporary local registry, without uploading anything; see [`cargo package`](https://doc.rust-lang.org/cargo/commands/cargo-package.html). This verification compiles the libraries, but doesn't run their tests and examples: run those from the unpacked archives, without the sibling source directories, so that a stray reference to another crate's files can't succeed.

### Rerun after a change of code

The temporary registry keeps its extracted sources in your Cargo home. Since the crates keep the same name and version from one run to the next, a later run can reuse those extractions, and verify a crate against an outdated sibling. When you rerun after changing the code without changing the version, give Cargo a fresh home rather than deleting cache directories:

```bash
CARGO_HOME="$(mktemp -d)" cargo package --workspace --locked
```

Cargo downloads the dependencies again, leaving your cache alone. The prefix also works for `mise run publish:dry-run`.

## Review before an upload

- Check the crate names and the registry owner just before the release
- Check the package versions and the internal dependency requirements together
- Review the versions, licenses, advisories, and yanked releases of the dependencies
- Test a fresh consumer on the supported Rust version, and read the generated API documentation
- Keep the links of each crate README absolute, so they work from a registry page
- Check that the public description matches the [support matrix](support-matrix.md)

Account details stay out of public files. A path dependency also carries the version of the crate it names, such as `version = "0.1.0"`, which Cargo uses on the registry, as its [dependency rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations) explain.

The [verification guide](verification.md#dependencies) runs the dependency checks, and states the advisory that remains in the graph of `gnap-biscuit`. The pinned lockfile doesn't validate the dependency resolution of a new consumer, so test a fresh one. Review warnings rather than suppressing them to get a clean release. Version 0.1.0 doesn't mean complete GNAP conformance, nor production-ready identity and storage services. Public release evidence names the reviewed revision and the checks you ran.

## Rehearse the release

Rehearse the whole workspace without uploading:

```bash
mise run publish:dry-run
```

This runs `cargo publish --workspace --registry crates-io --locked --dry-run`, which orders the crates by dependency and verifies the new versions together. It builds the archives and can contact the registry, but uploads nothing: it isn't an offline check, nor a guarantee that the registry will accept them. It keeps Cargo's clean-tree and lockfile checks, and reports yanked dependencies and future compiler incompatibilities, which a successful run doesn't resolve. See [`cargo publish`](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).

To print the commands without running even the Cargo dry run, use `mise run --dry-run publish:dry-run`.

## Publish

The maintainer publishes, not the coding agents or CI. Once the checks above pass, the maintainer runs:

```bash
mise run publish
```

The task asks for confirmation, with *no* as the default, then runs `cargo publish --workspace --registry crates-io --locked`. It publishes the SDK members at the versions of their manifests, without the applications or a tag, and no other task triggers it.

Workspace publication isn't atomic. If an upload or an index wait fails, check which versions reached crates.io before you retry, rather than rerunning the whole workspace. Publish the remaining crates one at a time with `cargo publish -p <crate> --registry crates-io --locked`, once their dependencies are on the registry. Never use `--no-verify` to get past a failing check.

To publish by hand or to recover, use an order in which each crate's dependencies, development ones included, come first:

1. `gnap-registry` and `gnap-net`
2. `gnap-types`
3. `gnap-core` and `gnap-crypto`
4. `gnap-subject`
5. `gnap-client`
6. `gnap-as`, `gnap-rs`, and `gnap-biscuit`
7. `gnap-conformance`, whose tests run against `gnap-as`
8. `gnap`, which re-exports all the others

Recompute this order when the dependencies change, and check that each dependency is visible on the registry before you publish a crate that needs it. After the release, verify the versions, the package contents, and the docs.rs builds, then update the installation instructions and the [changelog](../CHANGELOG.md), and publish the release notes and the tag.
