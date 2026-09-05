# Public GNAP normative evidence ledger

This is a reproducible **source inventory and evidence accounting tool**, not an
assertion that the workspace completes GNAP. Start with [REPORT.md](REPORT.md).
The ledger covers the official source material of RFC 9635 and RFC 9767, including
recommendations, optional mechanisms and the complete capability lists of C1/C2.
It does not shrink the inventory to the features already implemented.

## Reproduce and verify

Python 3.11 or newer; standard library only. Run from the repository root:

```sh
python3 -B tools/conformance_ledger.py check
python3 -B tools/conformance_ledger.py run-tests
```

`check` is offline and read-only. It verifies vendored XML hashes, regenerates
the inventory in memory, checks decisions/evidence, and compares both generated
artifacts byte-for-byte. It returns nonzero for a mismatch or invalid input.
`run-tests` actually executes the ledger's named regression tests and writes an
ignored local receipt to `conformance/runs/self-tests.json`. These tests verify
**the accounting tool**, not GNAP implementations; their results cannot be mapped
to GNAP clauses. For conventional test output without a receipt:

```sh
python3 -B -m unittest discover -s conformance/tests -v
```

To reproduce generated files, or retrieve the same pinned public sources:

```sh
python3 -B tools/conformance_ledger.py generate
python3 -B tools/conformance_ledger.py fetch
python3 -B tools/conformance_ledger.py check
```

`fetch` only retrieves the two exact RFC Editor URLs in
[sources.lock.json](sources.lock.json), with TLS, no redirects and a 4 MB/source
limit. Both downloads must match the pinned SHA-256 values before either source
is replaced. It does not update the lock, apply errata, or make a changed upstream
document silently become the new standard. Review a source-lock update as a
separate change. `report` prints the current generated report to stdout.

## Data and counting model

- `sources/`: complete, unmodified official XML documents; see [NOTICE.md](NOTICE.md).
- `clauses.json`: generated anchored **source blocks**, the original BCP14
  occurrences, source links, section/field context and immediately following
  capability lists. Terminology boilerplate remains present with its explicit
  exclusion reason. Marker ownership is checked one-to-one.
- `decisions.json`: reviewed applicability decisions, separate from observations.
- `evidence.json`: mappings to named assertions in actual execution receipts.
- `runs/`: local machine-generated test receipts, ignored by Git by default.

The first inventory contains 339 normative source blocks, not 339 reviewed
atomic obligations. RFC 9635 supplies 553 marked keywords (542 normative plus 11
terminology occurrences); RFC 9767 supplies 80 (69 plus 11). These numbers count
the pinned sources, not a percentage of implemented behavior. All 339 blocks
initially have `unresolved` applicability and `not_run` evidence. No private
historical coverage decisions or documents were imported.

Each occurrence retains its original keyword. BCP14 synonyms are normalized only
for the separate `strength`/`polarity` fields: `REQUIRED` and `SHALL` are mandatory,
`RECOMMENDED` is a recommendation. A MUST and SHOULD in the same paragraph do not
collapse into one rank. Their full paragraph and source anchor remain available
for future atomic decomposition. The eight list items of each Appendix C profile
are retained even though they contain no BCP14 markup themselves. C2's first item
contains two required start modes. Source wording, including `jwks`, is retained
literally; interpretation and errata must not be hidden inside extraction.

IDs use the RFC number and the official XML `pn` anchor, not a counter derived
from how sentences happened to be split. Updating extraction logic does not
renumber later paragraphs. A change to the pinned source still requires review;
anchors are not a promise that arbitrary future source versions are equivalent.

This does **not** prove that markup alone captures every normative implication.
Cross-references, conditional behavior, negative cases, security recommendations,
inherited list requirements and deployment duties need human review. Keeping
source blocks intact avoids pretending this first lot has completed that review.

## Applicability is not evidence

Initial decisions are empty. A future reviewed decision has this shape (the
example is explanatory and is not installed as a real decision):

```json
{
  "clause_id": "rfc9635:section-appendix.c.1-1",
  "applicability": "applicable",
  "review": "reviewed",
  "rationale": "The selected AS deployment targets C1; every listed capability remains to be evaluated.",
  "condition": "AS claims the C1 profile",
  "role": "as",
  "profile": "C1-AS"
}
```

Applicability is `unresolved`, `applicable` or `condition_false`. The latter two
require `reviewed`, a nonempty rationale and condition, and an explicit role and
profile. One contextual decision per source block is supported in this first
lot; duplicate/conflicting decisions fail. There is no multi-deployment/profile
completion engine yet. All source blocks remain visible regardless of decisions.
`condition_false` must reflect an actual RFC condition that does not hold in the
declared context, not the fact that implementation is missing. Reviewer judgment
is essential: a schema validator cannot establish that a rationale is true.

Appendix C permits a functioning client subset in its stated circumstances; it
does not give an AS the same exception. An optional protocol mechanism can have
mandatory rules when selected. Biscuit being a project target is separate from
whether GNAP mandates a token format. The public [support matrix](../docs/support-matrix.md)
remains the product/capability inventory; this ledger does not replace it.

## Real execution receipts, not comments as evidence

`run-tests` uses Python unittest discovery and records every named result:
`pass`, `fail`, `error`, `skipped`, `expected_failure`, `unexpected_success`.
An empty suite, missing outcome, source outside the repository or duplicate case
ID fails closed. A class/module setup failure that prevents complete accounting
does not produce a valid receipt. The receipt records source-module/tool hashes,
Git revision and dirty-worktree flag, plus UTC Unix start/end times. It contains
no raw failure output; console test output should still use synthetic data only.

Future independently authored Python wire scenarios can live under
`conformance/scenarios/` and use the same real runner:

```sh
python3 -B tools/conformance_ledger.py run-tests \
  --directory conformance/scenarios \
  --scope gnap-scenarios \
  --output conformance/runs/wire-scenarios.json
```

That directory does not exist in this first lot: the command is a documented
extension point, not a claimed GNAP suite. The runner refuses to relabel tests
outside this scenario directory as GNAP evidence. It executes trusted repository
Python code; **never expose it as an arbitrary public command or upload runner**.

Each future `evidence.json` claim has `clause_id`, `run` (a JSON receipt under
`conformance/runs/`), `case_id` and a description of the `assertion`. The validator
requires a reviewed applicable decision, the actual named case result, and
unchanged recorded source hashes. It also checks that the named class/method is
still declared in the recorded Python module using AST parsing, without importing
or executing tests during `check`. This first adapter supports directly declared
unittest methods; inherited/dynamically generated case declarations need a future
adapter rather than being counted blindly. Reading a GNAP receipt also verifies
that every case module resolves under `conformance/scenarios/`; changing a tooling
receipt's `scope` field cannot relabel its tests as GNAP evidence. The recorded
hash of `tools/conformance_ledger.py` is mandatory and must match the current tool;
after changing the runner, rerun the suite instead of trusting its old receipt.
It refuses unknown IDs, missing receipts,
tooling receipts and source-only `by: test/vector/analysis` claims. Skips and
expected failures are inconclusive, never passes; a failure is never hidden by
another passing observation. Even successful execution is reported only as
`passing_observation_not_completion`: this source-block inventory has not yet
reviewed every atomic obligation or whether an assertion is sufficient.

Receipts are **trusted local execution records, not cryptographic attestations**.
An operator can edit a JSON file or write a meaningless test. Review remains
necessary. This first runner hashes test modules and itself, not every dependency
or deployed server; target revision, toolchains, configuration, redacted wire
artifacts and dependency provenance must be added before live results support a
release claim. Stale, unrelated, source-only and skipped evidence must not become
conformance claims. Rust/nextest/JUnit and live workbench receipt adapters are not
implemented in this lot.

## Next bounded increments

Review source blocks into atomic obligations with conditions and preserved links;
add named independent positive/negative wire scenarios and their executed receipts;
then connect workbench reports. Complete C1/C2, RFC9767 behavior, security reviews
and deployment evidence remain substantive work, not accounting checkboxes.
There is intentionally no overall percentage or certificate badge.
