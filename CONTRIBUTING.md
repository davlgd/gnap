# Contributing

Start with the [support matrix](docs/support-matrix.md). It separates the
protocol's requirements from this project's choices and from what the code
actually does. Examples should make a real application task possible and record
the SDK or documentation friction they encounter.

## Keep changes reviewable

Use a branch for one coherent change. Explain why the change is useful, keep the
implementation focused, and add regression tests for the failures it addresses.
Update examples and support claims together. Do not add unused abstractions or
hide incomplete behavior behind a successful check.

Use plain language in commit messages and pull requests. A short account of the
problem, the decision and the evidence is more useful than a catalogue of files
or a copied test log. State meaningful limitations. Maintainer-authored commits
use the maintainer's configured personal identity; contributors use their own.

The repository's Apache-2.0 license does not replace notices attached to
third-party fixtures. Never commit deployment credentials, real user data or
private development material. Public example keys must be identified as such.

## Maintainer-led review and merge

The following workflow applies to autonomous maintainer work:

1. Implement and test a bounded change, then request an adversarial review from
   Claude. Supply the actual diff, source references, failing cases and known
   limits. Reconcile findings explicitly; a timeout is not agreement.
2. After consensus, open a pull request assigned to **davlgd** and request
   **Copilot code review**. Request a reviewer, not the Copilot coding agent.
3. Read every finding. Fix valid issues and reply with the correction and its
   evidence. Explain any disagreement with a reproducible example or source;
   do not change correct behavior just to silence a reviewer. Resolving a thread
   alone is not evidence that the finding has been addressed.
4. Re-run relevant checks, obtain renewed Claude review for material changes,
   push the corrections and explicitly re-request Copilot review. Repeat until
   an actual completed review of the latest head has no outstanding findings.
   Silence, a failed review job, an empty reviewer list or a review of an older
   commit does not satisfy this gate. If review is unavailable or a disagreement
   remains unresolved, leave the PR open and notify the maintainer.
5. Merge only after CI passes on the current PR head, the latest applicable
   Claude consensus still holds, and Copilot has completed a clean review of
   that head. Respect any additional repository protections and do not bypass
   them. Recheck the head SHA immediately before merging. A material change
   after review starts the review cycle again.

GitHub may represent a completed Copilot review as `COMMENTED` rather than
`APPROVED`, depending on settings. Inspect its actual findings and completion;
do not fabricate an approval. Replies document the resolution for people, but
are not a substitute for requesting a new review: Copilot does not converse in
those threads. See [GitHub's code review documentation](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/request-a-code-review/use-code-review).

With a recent GitHub CLI, the explicit request is:

```console
gh pr edit <number> --repo davlgd/gnap --add-reviewer '@copilot'
```

## Verification

Run the checks relevant to the change. The [CI workflow](.github/workflows/ci.yml)
is the canonical command list: workspace tests, formatting, strict clippy,
documentation, the minimum supported Rust build, registry reproduction and
standalone application acceptance. Report local, GitHub-runner and deployed
checks separately. Do not present self-interop or shared-parser diagnostics as
an independent conformance audit.

When changing generated data, fix the generator and reproduce the artifact from
the vendored input before checking for upstream changes. When changing a network
boundary, exercise rejection paths as well as the successful application flow.

## Hosted test applications

Use Clever Tools and only the maintainer-designated test account for this
project. Every application needs a dedicated **M build instance**; runtime size
is a separate choice. Use synthetic data and bounded, disposable state.

Choose meaningful, available `cleverapps.io` subdomains and retain existing
working links during migrations. A domain change must account for canonical
origins, callback URIs, cookies, request signatures and test target allowlists;
an added DNS name alone does not establish a working application. Never claim
an existing domain or change an unrelated application.

Verify the account, actual deployed revision, build flavor, HTTPS behavior and
application scenario after a deployment. Keep provider identifiers and account
linkage in ignored local configuration. Deploy reviewed code, not an unrelated
working branch, and keep a known-good revision available for recovery.
