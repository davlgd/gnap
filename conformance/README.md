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
the pinned sources, not a percentage of implemented behavior. The original
inventory had all 339 blocks with `unresolved` applicability and `not_run`
evidence. Two section 9 blocks now have reviewed AS applicability; all other
blocks remain unresolved. The first historical discovery observation below now
maps six executed assertions to those two blocks, without completing them. No private
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

Two decisions now contextualize the AS discovery response. A reviewed decision has this shape (the
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

The discovery suite now uses the dedicated `discovery-tests` command below to
bind mandatory capture provenance as well as actual execution. The generic
runner remains an extension point for other scenarios and refuses to relabel tests
outside this scenario directory as GNAP evidence. It executes trusted repository
Python code; **never expose it as an arbitrary public command or upload runner**.

Each future `evidence.json` claim has `clause_id`, `run` (a JSON receipt under
`conformance/runs/`, or a reviewed public receipt under `conformance/receipts/`),
`case_id` and a description of the `assertion`. The validator
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
release claim. The discovery adapter below now binds capture/configuration and
helper hashes, but does not attest remote code. Stale, unrelated, source-only and skipped evidence must not become
conformance claims. Rust/nextest/JUnit and live workbench receipt adapters are not
implemented in this lot.

## First executable group: discovery response, RFC 9635 section 9

The default command is entirely offline and uses a **synthetic** document:

```sh
python3 -B tools/conformance_ledger.py discovery-tests
```

It executes six directly declared tests in
`conformance/scenarios/test_as_discovery.py`, using independent Python JSON/URI
assertions, not SDK validators or the web workbench's verdict:

| Source block | Named assertions (class `DiscoveryResponse`) |
| --- | --- |
| `rfc9635:section-9-2` | `test_options_response_media_type`, `test_response_is_json_object` |
| `rfc9635:section-9-3.2.1` | `test_endpoint_required_string`, `test_endpoint_absolute_host_without_fragment`, `test_endpoint_https`, `test_endpoint_matches_exact_request` |

The endpoint block contains four BCP14 occurrences and its string type comes
from field context. They are not collapsed into a completed atomic obligation.
The first block retains the client's MAY separately from the AS response MUST.
Both decisions contextualize AS applicability only; the extraction's block
review state and all other section 9 blocks remain unresolved. Required field
checks do not assert that every optional discovery capability works.

HTTP 200 is **not** one of these six normative assertions. Duplicate JSON names
make dependent interpretation inconclusive (`skipped`), not an invented GNAP
MUST failure. The JSON object and `Content-Type: application/json` requirements
are explicit in [RFC 9635 section 9, paragraph 2](https://www.rfc-editor.org/rfc/rfc9635.html#section-9-2)
(vendored XML lines 7216–7220), not inferred from a diagnostic profile. Missing
Content-Type fails; repeated Content-Type metadata is ambiguous and therefore
skipped, without asserting a separate GNAP header-cardinality MUST.
URI grammar does not impose the web diagnostic's separate userinfo
safety policy. Registry/capability lists, optional rotation metadata, capability
execution, sections 9.1/9.2, transport conformance and C1/C2 completion are outside
this slice; none is silently excluded from the full source inventory.

### Operator-only capture, explicitly opt-in

Only use a public discovery endpoint you operate or are authorized to test:

```sh
GNAP_DISCOVERY_LIVE=1 \
GNAP_DISCOVERY_ENDPOINT=https://your-owned-as.example/gnap \
python3 -B tools/conformance_ledger.py capture-discovery

python3 -B tools/conformance_ledger.py discovery-tests \
  --capture conformance/runs/discovery-capture.json
```

The collector rejects CI environments. The CI job never invokes it. It sends
one credential-free OPTIONS, with no proxy or redirect following, validates TLS
for the configured DNS name and connects to a pinned public IPv4 address. One
subprocess owns the entire DNS/TLS/HTTP exchange and is killed and reaped at the
five-second wall-clock deadline, including slow headers and chunk metadata.
Socket timeouts are additional safeguards, not the total deadline. The body
limit is 32 KiB. A mixed private/public DNS answer is refused. The first collector
does not support IPv6-only targets, explicit ports, query components or IP
literals: these are conservative collector limits, not GNAP exclusions. Capture
data can never cause a request: only the operator's explicit environment value
is eligible for network collection. No received code or command is executed.

The capture preserves the response body as exact base64-encoded bytes and its
SHA-256, exact queried endpoint, effective UTC Unix capture time, status, and
only Content-Type headers. Cookies, authentication headers and other headers
are discarded. The **body is not redacted**, since altered bytes would no longer
be the response tested. Discovery is public metadata; the operator must review
the body before publishing and must not publish a response containing secrets.
Errors do not reflect captured values. `remote_revision` is always `unknown`:
TLS and a deployment URL are not an attestation of remote source code.

### Replay provenance and publication

Two independent fields prevent conflating evidence types:

- `capture_origin=synthetic`: oracle fixture only, refused as AS evidence.
- `capture_origin=live`: a response acquired from a server at the recorded time.
- `execution_mode=capture_replay`: the six assertions ran offline against those
  bound bytes. A replay of a live capture is **historical**, not a current live
  network test. This is the only publishable execution mode in this adapter.
- `execution_mode=live` is reserved by the receipt validator for acquisition
  during the execution interval; the two-command workflow above does not emit
  it and cannot acquire network data during CI replay.

Receipts bind the capture file hash, original body hash, exact endpoint, capture
time, collector configuration/hash, scenario/helper sources and ledger runner.
Source or capture changes invalidate the receipt. The JSON is untrusted data.
`check` imports the versioned, trusted repository capture helper to validate it;
it never imports or executes code supplied by a capture or receipt. Receipts remain trusted
local records, not forgery-proof cryptographic attestations. Editing every
hash/provenance field dishonestly is not something this format can prevent.

Publication deliberately takes two commits, coordinated by the maintainer:

1. Review the capture, place it under `conformance/captures/`, and commit it with
   the finalized scenario/helper/runner sources. No AS evidence claim yet.
2. From that clean commit, replay and emit the public receipt:

   ```sh
   python3 -B tools/conformance_ledger.py discovery-tests \
     --capture conformance/captures/as-discovery.json \
     --publish --output conformance/receipts/as-discovery.json
   ```

3. Map only actually executed case IDs to the two reviewed blocks in
   `evidence.json`, regenerate the report, check it, then commit these artifacts.

Public receipts require a known clean source revision and matching source and
capture blobs (the capture path/hash is also mandatory in `source_files`)
from that actual Git commit, not merely a supplied `dirty: false`. The subsequent
artifact commit can differ. The claims CI checkout fetches history so offline
`git show` can verify the earlier commit. `runs/` stays ignored; `receipts/` and
reviewed `captures/` are publishable and checked on a fresh clone. Do not map an
ignored local run in the public evidence file. Existing receipts are historical:
CI checks them offline and generates its own separate synthetic oracle receipt,
without converting either into a new current network observation.

The first published [receipt](receipts/gnap-delegation-discovery-2026-09-05.json)
replays the [reviewed capture](captures/gnap-delegation-discovery-2026-09-05.json)
from `https://gnap-delegation.cleverapps.io/gnap`, captured at UTC Unix
`1788645193` on 5 September 2026. Its six assertions ran at UTC Unix `1788645383`
from clean source commit `28275dca68cb5933f27a34af0af3c0076cf470f4`.
The body contains only the public grant endpoint, announced `httpsig` proof and
`key_rotation_supported: false`. Only the six listed response assertions are
mapped: capability execution and remote source revision remain unknown.
This real capture replay remains
`passing_observation_not_completion`, contextualized by its capture time and
endpoint; the ledger still has no global percentage or certification.

## Next bounded increments

Review source blocks into atomic obligations with conditions and preserved links;
add named independent positive/negative wire scenarios and their executed receipts;
then connect workbench reports. Complete C1/C2, RFC9767 behavior, security reviews
and deployment evidence remain substantive work, not accounting checkboxes.
There is intentionally no overall percentage or certificate badge.
