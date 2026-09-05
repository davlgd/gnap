# Application validation — 5 September 2026

This records the first application-driven development cycle. It is a dated
observation, not a certification or a promise about subsequent revisions.

## Revisions and scope

The identifiers below refer to pre-publication revisions retained locally.
The public repository starts from a reviewed snapshot without that history;
these identifiers cannot be resolved in a public clone.

- `0c07084`: shared GNAP signature verifier, preserving the 61 existing AS
  interaction tests unchanged.
- `63f0889`: shared and borrowed stores. An application consumer's `Arc` orphan-rule
  workaround became reusable SDK forwarding implementations and a regression test.
- `cf567ba`: HTTP applications, acceptance script, CI configuration and documentation.
  This revision was deployed for the delegation demo.
- `fe4f9a2`: diagnostic checks distinguish GNAP error responses from an HTTP-status
  deployment policy. This revision was deployed and exercised for the workbench.

## Checks actually run

| Check | Observation |
| --- | --- |
| SDK workspace | 174 tests and 16 documentation tests passed |
| SDK quality | Formatting, clippy with warnings denied, rustdoc with warnings denied, locked offline build on Rust 1.85.0 passed |
| Documentation claims | 215 RFC quotations checked; README transcript and local scope checks passed |
| Delegation application | Six tests, formatting and clippy with warnings denied passed |
| Diagnostic workbench | Sixteen tests, formatting and clippy with warnings denied passed |
| Application JavaScript | Both scripts passed `node --check` |
| HTTP acceptance | The same 17 observations passed on localhost and on the deployed HTTPS applications |
| Browser | Chromium exercised approval, callback wait, protected read, rotation and revocation; local browser checks also exercised denial |
| Cloud browser | TLS and Secure/HttpOnly/SameSite cookies checked for the demo; workbench import, download, revision provenance and configured AS/RS targets checked |
| Live AS probe | Five checks passed; authenticated flow explicitly remained untested |
| Live RS probe | The protected resource rejected a credential-free request; valid-token proof, rights and introspection remained untested by this probe |

The 17 acceptance observations include repeated reads and retired-token checks:
they are not 17 independent normative requirements. The script is
[`tools/smoke_ecosystem.py`](../tools/smoke_ecosystem.py). It creates disposable
synthetic sessions, preserves browser isolation, follows only the expected
callback origin, and does not print credentials.

## Deployment observations

Both applications were deployed with Clever Tools to the requested test account,
using Rust 1.98.0, a dedicated M build instance and one XS runtime instance.
Their actual provider settings and deployed commits were checked through the API.
HTTPS redirection was enabled for both. Provider identifiers and account linkage
remain in ignored local deployment configuration.

The CLI's embedded Git transport timed out. For the demo, the provider had
nevertheless accepted the deployment; its API and logs established success.
For the workbench, no deployment had been created. A retry using system Git
succeeded, and the experimental CLI setting was restored to its initial value.
An unsuccessful CLI exit was not interpreted as either deployment success or
failure without checking provider state.

The deployed workbench exposed a mobile layout defect that the local `unknown`
revision did not: a full 40-character commit identifier overflowed the report
summary. At a 390-pixel viewport the document measured 406 pixels wide. Allowing
the summary to wrap long words restored a 390-pixel document width, including
when a long RS target URL was selected. This was checked in Chromium, not
inferred from the CSS alone.

## Limits

The demo's three roles run under one operator, with one application signing key
and volatile shared storage. Resource-owner identity is simulated by a visitor's
explicit decision. The RS is co-located: no RFC 9767 introspection API is claimed.

The workbench shares SDK parsers. Its active probes exercise rejection only and
allow only operator-approved targets; they do not provide arbitrary-target,
self-service certification. Successful application scenarios do not establish
independent implementation interoperability or production readiness.

Before publication, the CI commands had only been exercised locally. Peer review
and browser checks are not an independent security audit or a performance
comparison with OAuth.

## Public snapshot verification

On the same day, the first public snapshot, `13d511f`, passed all five jobs in
[GitHub Actions run 33971954769](https://github.com/davlgd/gnap/actions/runs/33971954769),
including the application HTTP acceptance checks on a fresh GitHub runner.

The run also exposed two warnings: an obsolete checkout action and apparent
IANA registry drift. Refreshing the CSV files produced no changes. The generator
instead removed Rust attributes and formatting from the committed artifact.
Its template and formatting step were corrected, and two consecutive generations
then reproduced the artifact exactly. CI now checks that reproducibility before
fetching upstream data, so a generator regression cannot be mislabeled as an
IANA update. The checkout action was updated to the inspected v7.0.1 commit.
