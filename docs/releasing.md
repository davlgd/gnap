# Preparing the 0.1.0 crates

This guide prepares the ten SDK crates for their first registry release. It does
not announce that they are published. Until publication, use the
[source-dependency setup](getting-started.md#integrate-a-protocol-role).
The HTTP applications are examples, not packages in this release.

Publication requires a separate maintainer decision. Do not upload a package,
create a release tag or change registry ownership as part of documentation or
packaging checks. Cargo describes why a published version is effectively
permanent in its [publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html).

## Check the source and package contents

Use a clean, reviewed revision with passing CI. The packaging workflow below
has been exercised with Cargo 1.98; this release-tooling version is separate from
the SDK's declared Rust 1.85 minimum. The asset check requires Python 3.11 or newer.

```sh
python3 -B tools/check_package_assets.py
cargo package --workspace --list --locked
cargo package --workspace --locked
```

The asset check verifies local crate READMEs, documentation URLs, the inherited
SPDX license, literal embedded-file paths and exact copies of canonical licenses
and test fixtures. It does not inspect every possible build input or scan for secrets.
The asset mapping is [package-assets.json](../tools/package-assets.json);
update canonical sources and their package-local copies together.

Each package has its own README and the Apache-2.0 license text. RFC-derived
test keys remain deliberately public fixtures with their provenance notices;
they must never become deployment credentials. Review the actual file list,
including tests and examples, rather than assuming Git ignore rules are a
complete publication policy.

Cargo creates archives under `target/package`. In a multi-package workspace,
the tested Cargo version can verify unpublished local dependencies together
using a temporary registry. This is local preparation, not a registry upload.
An individual package's registry dependencies must otherwise be available.
See [cargo package](https://doc.rust-lang.org/cargo/commands/cargo-package.html)
for the command's verification boundary.

Default package verification compiles libraries; it is not a substitute for
running tests and examples from unpacked archives. Check those without sibling
source checkouts so an accidental cross-crate file reference cannot succeed.
The fixture copies exist to make that verification possible, not to exclude
tests from the published source.

## Review before the first upload

- Verify the intended crate names and registry owner immediately before release.
  A missing registry entry is not a reservation or proof that publication will
  be accepted. Keep credentials and account coordination out of public files.
- Check all package versions and internal dependency requirements together.
  Path dependencies carry `version = "0.1.0"` for registry resolution; see
  [Cargo's dependency rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations).
- Review third-party dependency versions, licenses, advisories and yanked
  releases. The pinned workspace lock alone does not validate a new consumer's
  dependency resolution or minimum Rust version.
- Test a fresh consumer at the supported Rust version and inspect the generated
  API documentation. Review warnings rather than suppressing them to get a
  nominally clean release.
- Keep README links usable from a registry page. Crate READMEs link to public
  guides using absolute URLs rather than workspace-relative `../../docs` paths.
- Confirm that the public description matches the
  [supported profiles](support-matrix.md). Version 0.1.0 does not mean complete
  GNAP conformance or production-ready identity and storage services.

Machine-specific observations, unresolved dependency decisions and draft release
coordination belong in ignored local notes. Public release evidence should name
the reviewed revision and the checks actually performed.

## Publish only after approval

One valid order, including the current development dependencies, is:

1. `gnap-registry`, `gnap-net` (independent roots).
2. `gnap-types`.
3. `gnap-core`, `gnap-crypto`.
4. `gnap-subject`.
5. `gnap-client`.
6. `gnap-as`, `gnap-rs`, `gnap-biscuit`.

Recompute the order when dependencies change. After the maintainer's explicit
release approval, verify each prerequisite is visible in the registry before
publishing a dependent crate. Use `cargo publish -p <crate> --dry-run --locked`
as a final rehearsal, then the corresponding publish command only for the
approved package and revision. Never use `--no-verify` to conceal a failing check.

After publication, verify registry versions, package contents and docs.rs builds,
then update installation instructions and publish the approved release notes
and tag. A local archive check alone does not establish those outcomes.
