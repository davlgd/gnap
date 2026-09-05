#!/usr/bin/env python3
"""Public, source-pinned GNAP inventory and execution-backed evidence ledger.

This tool intentionally does not turn extracted paragraphs into a claim of
atomic requirement coverage. Run `--help`; Python 3.11+, standard library only.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import time
import unicodedata
import unittest
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SCHEMA = 1
KEYWORDS = {
    "MUST": ("obligation", "positive"),
    "REQUIRED": ("obligation", "positive"),
    "SHALL": ("obligation", "positive"),
    "MUST NOT": ("obligation", "negative"),
    "SHALL NOT": ("obligation", "negative"),
    "SHOULD": ("recommendation", "positive"),
    "RECOMMENDED": ("recommendation", "positive"),
    "SHOULD NOT": ("recommendation", "negative"),
    "NOT RECOMMENDED": ("recommendation", "negative"),
    "MAY": ("option", "positive"),
    "OPTIONAL": ("option", "positive"),
}
BLOCKS = {"t", "li", "dd", "dt", "td", "th"}
MAX_SOURCE_BYTES = 4_000_000
RUNNER_PATH = "tools/conformance_ledger.py"


class LedgerError(ValueError):
    """An input cannot support a trustworthy ledger calculation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    # Duplicate keys must not silently replace applicability or result fields.
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LedgerError(f"Cannot read JSON: {path.name}: {error}") from error
    require(isinstance(result, dict), f"Expected object in {path.name}")
    return result


def fields(value: dict, expected: set[str], context: str) -> None:
    require(isinstance(value, dict) and set(value) == expected,
            f"Unexpected or missing fields in {context}")


def local_path(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
            "Paths must be nonempty repository-relative paths")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), "Path escapes repository")
    return path


def text(element: ET.Element) -> str:
    """Preserve displayed xref labels without source whitespace noise."""
    def pieces(node):
        if node.tag == "xref" and not (node.text or "").strip():
            yield node.get("derivedContent", "")
        else:
            yield node.text or ""
        for child in node:
            yield from pieces(child)
            yield child.tail or ""
    return " ".join(unicodedata.normalize("NFC", "".join(pieces(element))).split())


def section_label(section: ET.Element) -> str:
    pn = section.get("pn", "")
    if pn.startswith("section-appendix."):
        return pn.removeprefix("section-appendix.").upper()
    return pn.removeprefix("section-")


def extract_document(rfc: str, data: bytes) -> dict:
    """Own every BCP14 occurrence exactly once, retaining its source context.

    Units are anchored source blocks, NOT atomic obligations. Lists following a
    block are context, not duplicate marker ownership. In particular Appendix C
    requirements keep their unmarked capability lists.
    """
    require(len(data) <= MAX_SOURCE_BYTES, "Source XML too large")
    try:
        document = ET.fromstring(data)
    except ET.ParseError as error:
        raise LedgerError(f"Invalid source XML: {error}") from error
    require(document.tag == "rfc" and document.get("number") == rfc,
            "Source RFC identity mismatch")
    parents = {child: parent for parent in document.iter() for child in parent}
    owners: dict[ET.Element, list[ET.Element]] = {}
    for marker in document.iter("bcp14"):
        owner = parents.get(marker)
        while owner is not None and (owner.tag not in BLOCKS or not owner.get("pn")):
            owner = parents.get(owner)
        require(owner is not None, "BCP14 marker has no anchored source block")
        owners.setdefault(owner, []).append(marker)

    clauses, excluded = [], []
    seen_ids: set[str] = set()
    all_occurrences: list[str] = []
    for block, markers in owners.items():
        anchor = block.get("pn")
        block_id = f"rfc{rfc}:{anchor}"
        require(block_id not in seen_ids, "Duplicate source block anchor")
        seen_ids.add(block_id)
        section = parents.get(block)
        while section is not None and section.tag != "section":
            section = parents.get(section)
        require(section is not None, "Normative source block lacks section context")
        title = section.find("name")
        occurrences = []
        for index, marker in enumerate(markers, 1):
            keyword = text(marker)
            require(keyword in KEYWORDS, f"Unknown BCP14 keyword: {keyword}")
            strength, polarity = KEYWORDS[keyword]
            occurrence_id = f"{block_id}:bcp14-{index}"
            occurrences.append({"id": occurrence_id, "keyword": keyword,
                                "strength": strength, "polarity": polarity})
            all_occurrences.append(occurrence_id)
        block_text = text(block)
        item = {
            "id": block_id,
            "rfc": rfc,
            "anchor": anchor,
            "section": section_label(section),
            "section_title": text(title) if title is not None else "",
            "source_url": f"https://www.rfc-editor.org/rfc/rfc{rfc}.html#{anchor}",
            "text": block_text,
            "occurrences": occurrences,
            "field_context": None,
            "list_context": [],
            "preceding_context": None,
            "review_state": "unresolved",
        }
        # Capture a definition-list field even when the marker is inside a t
        # within dd. Capturing context does not change marker ownership.
        container = block
        while container is not None and container is not section:
            parent = parents.get(container)
            if parent is not None:
                siblings = list(parent)
                position = siblings.index(container)
                if container.tag == "dd" and position and siblings[position - 1].tag == "dt":
                    item["field_context"] = text(siblings[position - 1])
                if container.tag in {"ul", "ol", "dl"} and position:
                    previous = siblings[position - 1]
                    if previous.tag == "t":
                        item["preceding_context"] = text(previous)
            container = parent
        parent = parents[block]
        siblings = list(parent)
        for following in siblings[siblings.index(block) + 1:]:
            if following.tag not in {"ul", "ol", "dl"}:
                break
            item["list_context"].append({
                "anchor": following.get("pn"),
                "kind": following.tag,
                "items": [{"anchor": child.get("pn"), "text": text(child)}
                          for child in following if child.tag in {"li", "dt", "dd"}],
            })
        if "are to be interpreted as described in BCP" in block_text:
            # Still retain every marker and source paragraph in the inventory.
            item["exclusion_reason"] = "BCP14 terminology definition, not a GNAP behavior requirement"
            excluded.append(item)
        else:
            clauses.append(item)
    source_count = sum(1 for _ in document.iter("bcp14"))
    require(len(all_occurrences) == len(set(all_occurrences)) == source_count,
            "Marker ownership is not a bijection with source occurrences")
    keywords = Counter(o["keyword"] for c in clauses for o in c["occurrences"])
    return {
        "rfc": rfc,
        "source_sha256": digest(data),
        "reconciliation": {
            "source_markers": source_count,
            "normative_markers": sum(keywords.values()),
            "excluded_markers": sum(len(c["occurrences"]) for c in excluded),
            "source_blocks": len(clauses),
            "keywords": dict(sorted(keywords.items())),
        },
        "clauses": clauses,
        "excluded_context": excluded,
    }


def sources(root: Path) -> list[dict]:
    lock = read_json(root / "conformance/sources.lock.json")
    fields(lock, {"schema_version", "documents"}, "source lock")
    require(lock["schema_version"] == SCHEMA and isinstance(lock["documents"], list), "Unsupported source lock schema")
    require(all(isinstance(d, dict) for d in lock["documents"]), "Source documents must be objects")
    require([d.get("rfc") for d in lock["documents"]] == ["9635", "9767"],
            "Source inventory must include RFC9635 and RFC9767 in order")
    for item in lock["documents"]:
        fields(item, {"rfc", "url", "sha256", "path"}, "source document")
        number = item["rfc"]
        require(item["url"] == f"https://www.rfc-editor.org/rfc/rfc{number}.xml", "Noncanonical source URL")
        require(item["path"] == f"conformance/sources/rfc{number}.xml", "Unexpected source path")
        require(isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "Invalid source hash")
    return lock["documents"]


def generate_inventory(root: Path) -> dict:
    documents = []
    for item in sources(root):
        path = local_path(root, item["path"])
        try:
            data = path.read_bytes()
        except OSError as error:
            raise LedgerError(f"Missing source {item['path']}; run fetch") from error
        require(digest(data) == item["sha256"], f"Source hash mismatch: {item['path']}")
        documents.append(extract_document(item["rfc"], data))
    return {"schema_version": SCHEMA, "unit": "anchored source block, not an atomic requirement", "documents": documents}


def decision_states(root: Path, inventory: dict) -> dict[str, dict]:
    clauses = {c["id"]: c for d in inventory["documents"] for c in d["clauses"]}
    data = read_json(root / "conformance/decisions.json")
    fields(data, {"schema_version", "decisions"}, "decisions")
    require(data["schema_version"] == SCHEMA and isinstance(data["decisions"], list), "Unsupported decisions schema")
    states = {identifier: {"applicability": "unresolved", "review": "unresolved", "evidence": "not_run"} for identifier in clauses}
    seen = set()
    for item in data["decisions"]:
        fields(item, {"clause_id", "applicability", "review", "rationale", "condition", "role", "profile"}, "decision")
        identifier = item["clause_id"]
        require(isinstance(identifier, str) and identifier in clauses, f"Unknown clause ID: {identifier}")
        require(identifier not in seen, f"Duplicate or contradictory decision: {identifier}")
        seen.add(identifier)
        require(isinstance(item["applicability"], str) and item["applicability"] in {"applicable", "condition_false", "unresolved"}, "Invalid applicability")
        require(isinstance(item["review"], str) and item["review"] in {"unresolved", "reviewed"}, "Invalid review state")
        for key in ("rationale", "condition", "role", "profile"):
            require(isinstance(item[key], str) and item[key].strip(), f"Decision requires {key}")
        require(item["role"] in {"as", "client", "rs", "deployment", "multiple"}, "Unknown decision role")
        require(item["profile"] in {"core", "C1-AS", "C1-client", "C2-AS", "C2-client", "RS", "project"}, "Unknown decision profile")
        require(item["applicability"] == "unresolved" or item["review"] == "reviewed", "An applicability decision requires review")
        # This initial inventory has no reviewed decomposition of block contents.
        # Recording applicability is useful; a block cannot become a proven
        # atomic requirement merely because one referenced test passed.
        states[identifier] = {"applicability": item["applicability"], "review": item["review"], "evidence": "not_run"}
    return states


def validate_run(root: Path, run: dict, *, published: bool = False) -> dict[str, str]:
    expected = {"schema_version", "runner", "scope", "started_at_unix_utc", "finished_at_unix_utc", "source_revision", "working_tree_dirty", "source_files", "discovered_cases", "results"}
    if isinstance(run, dict) and "observation" in run:
        expected.add("observation")
    fields(run, expected, "execution receipt")
    require(run["schema_version"] == SCHEMA and run["runner"] == "python-unittest-v1", "Unsupported execution receipt")
    require(isinstance(run["scope"], str) and run["scope"] in {"tooling", "gnap-scenarios"}, "Unknown execution scope")
    require(isinstance(run["source_revision"], str) and (run["source_revision"] == "unknown" or re.fullmatch(r"[0-9a-f]{40,64}", run["source_revision"])), "Invalid source revision")
    require(isinstance(run["working_tree_dirty"], bool), "Execution must record dirty state")
    start, finish = run["started_at_unix_utc"], run["finished_at_unix_utc"]
    require(type(start) is int and type(finish) is int and 0 < start <= finish, "Invalid execution times")
    require(isinstance(run["source_files"], dict) and run["source_files"], "Execution has no source hashes")
    require(RUNNER_PATH in run["source_files"], "Execution receipt lacks the required runner hash")
    require(run["source_files"][RUNNER_PATH] == digest(Path(__file__).read_bytes()),
            "Execution runner does not match the current ledger tool")
    for relative, expected in run["source_files"].items():
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
                "Invalid execution source hash")
        path = local_path(root, relative)
        require(path.is_file() and digest(path.read_bytes()) == expected, f"Execution source changed or disappeared: {relative}")
    discovered = run["discovered_cases"]
    require(isinstance(discovered, list) and discovered and all(isinstance(c, str) and c for c in discovered), "Execution has no discovered named cases")
    require(len(discovered) == len(set(discovered)), "Duplicate discovered cases")
    # Check declarations without importing/executing arbitrary modules during
    # `check`. This first runner supports directly declared unittest methods;
    # dynamic/inherited/parameterized cases need a dedicated future adapter.
    for case in discovered:
        parts = case.rsplit(".", 2)
        require(len(parts) == 3, "Case ID must name module, class and method")
        module, class_name, method = parts
        suffix = module.replace(".", "/") + ".py"
        candidates = [relative for relative in run["source_files"]
                      if relative == suffix or relative.endswith("/" + suffix)]
        require(len(candidates) == 1, "Named case has no unique recorded module")
        module_path = local_path(root, candidates[0])
        require(run["scope"] != "gnap-scenarios" or module_path.is_relative_to((root / "conformance/scenarios").resolve()),
                "GNAP evidence module must be under conformance/scenarios; tooling cannot be relabelled")
        try:
            tree = ast.parse(module_path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeError) as error:
            raise LedgerError("Cannot inspect named test declaration") from error
        declared = any(isinstance(node, ast.ClassDef) and node.name == class_name
                       and any(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                               and child.name == method for child in node.body)
                       for node in tree.body)
        require(declared, f"Named case declaration is absent: {case}")
    require(isinstance(run["results"], list), "Execution results must be a list")
    results = {}
    for item in run["results"]:
        fields(item, {"case_id", "status"}, "case result")
        identifier = item["case_id"]
        require(isinstance(identifier, str) and identifier in discovered and identifier not in results, "Unknown or duplicate executed case")
        require(isinstance(item["status"], str) and item["status"] in {"pass", "fail", "error", "skipped", "expected_failure", "unexpected_success"}, "Invalid case outcome")
        results[identifier] = item["status"]
    require(set(results) == set(discovered), "Discovered tests were not all accounted for")
    if "observation" in run:
        validate_discovery_observation(root, run)
    elif ("conformance/scenarios/test_as_discovery.py" in run["source_files"]
          or any(module == "test_as_discovery" or module.endswith(".test_as_discovery")
                 for module in (case.rsplit(".", 2)[0] for case in discovered))):
        raise LedgerError("Discovery scenarios require capture provenance")
    if published:
        require("observation" in run and run["observation"]["execution_mode"] == "capture_replay",
                "Published discovery receipts must be offline capture replays")
        require(run["source_revision"] != "unknown" and run["working_tree_dirty"] is False,
                "Published receipt requires a known clean source commit")
        committed_inputs = dict(run["source_files"])
        capture_path = run["observation"]["capture_path"]
        require(not local_path(root, capture_path).is_relative_to((root / "conformance/runs").resolve()),
                "Published receipt cannot depend on an ignored local capture")
        committed_inputs[capture_path] = run["observation"]["capture_sha256"]
        for relative, expected_hash in committed_inputs.items():
            try:
                committed = subprocess.check_output(["git", "show", f"{run['source_revision']}:{relative}"], cwd=root, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as error:
                raise LedgerError("Published receipt source commit cannot be verified") from error
            require(digest(committed) == expected_hash, "Published source/capture hash differs from declared commit")
    return results


def validate_discovery_observation(root: Path, run: dict) -> None:
    from conformance.discovery import read_capture, CaptureError
    observation = run["observation"]
    fields(observation, {"kind", "execution_mode", "capture_origin", "capture_path", "capture_sha256",
                         "endpoint", "captured_at_unix_utc", "remote_revision", "collector_config_sha256"}, "discovery observation")
    require(observation["kind"] == "as-discovery-v1" and isinstance(observation["execution_mode"], str) and observation["execution_mode"] in {"capture_replay", "live"}, "Unknown discovery observation mode")
    require(run["scope"] == "gnap-scenarios", "Discovery observations are GNAP scenarios")
    require("conformance/discovery.py" in run["source_files"] and "conformance/scenarios/test_as_discovery.py" in run["source_files"], "Discovery helper and scenario hashes are required")
    path = local_path(root, observation["capture_path"])
    require(run["source_files"].get(observation["capture_path"]) == observation["capture_sha256"],
            "Capture hash must also be bound in source_files")
    require(any(path.is_relative_to((root / folder).resolve()) for folder in ("conformance/fixtures", "conformance/captures", "conformance/runs")), "Capture must be under an approved data directory")
    require(path.is_file() and path.stat().st_size <= 100_000 and digest(path.read_bytes()) == observation["capture_sha256"], "Capture changed or disappeared")
    try:
        capture = read_capture(path)
    except (CaptureError, OSError) as error:
        raise LedgerError("Invalid discovery capture") from error
    for field in ("capture_origin", "endpoint", "captured_at_unix_utc", "remote_revision", "collector_config_sha256"):
        require(observation[field] == capture[field], "Observation contradicts bound capture")
    require(observation["execution_mode"] != "live" or capture["capture_origin"] == "live", "Synthetic fixture cannot become live execution")
    if observation["execution_mode"] == "live":
        require(run["started_at_unix_utc"] <= capture["captured_at_unix_utc"] <= run["finished_at_unix_utc"], "Live capture was not acquired during this execution")
    if path.is_relative_to((root / "conformance/fixtures").resolve()):
        require(capture["capture_origin"] == "synthetic", "Synthetic fixture directory cannot hold live provenance")
    if capture["capture_origin"] == "live":
        require(capture["captured_at_unix_utc"] <= run["finished_at_unix_utc"], "Capture is later than its replay")


def apply_evidence(root: Path, states: dict[str, dict]) -> None:
    data = read_json(root / "conformance/evidence.json")
    fields(data, {"schema_version", "claims"}, "evidence mapping")
    require(data["schema_version"] == SCHEMA and isinstance(data["claims"], list), "Unsupported evidence mapping")
    seen = set()
    by_clause: dict[str, list[str]] = {}
    # Reuse one validated snapshot per receipt for this report only. A later
    # invocation must recheck the receipt and its source hashes from disk.
    validated: dict[Path, dict[str, str]] = {}
    for claim in data["claims"]:
        fields(claim, {"clause_id", "run", "case_id", "assertion"}, "evidence claim")
        identifier = claim["clause_id"]
        require(isinstance(identifier, str) and identifier in states, f"Evidence refers to unknown clause: {identifier}")
        state = states[identifier]
        require(state["applicability"] == "applicable" and state["review"] == "reviewed", "Evidence cannot contradict unresolved or condition-false applicability")
        require(isinstance(claim["assertion"], str) and claim["assertion"].strip(), "Evidence needs a described assertion")
        require(isinstance(claim["run"], str) and isinstance(claim["case_id"], str), "Evidence run and case ID must be strings")
        key = (identifier, claim["run"], claim["case_id"])
        require(key not in seen, "Duplicate evidence claim")
        seen.add(key)
        path = local_path(root, claim["run"])
        published = path.is_relative_to((root / "conformance/receipts").resolve())
        require(published or path.is_relative_to((root / "conformance/runs").resolve()), "Evidence receipt must live under conformance/runs or conformance/receipts")
        if path not in validated:
            run = read_json(path)
            outcomes = validate_run(root, run, published=published)
            require(run["scope"] == "gnap-scenarios", "Tooling self-tests cannot attest GNAP behavior")
            if "observation" in run:
                require(run["observation"]["capture_origin"] == "live", "Synthetic oracle fixtures cannot attest an AS")
            validated[path] = outcomes
        outcomes = validated[path]
        require(claim["case_id"] in outcomes, "Evidence refers to an absent test")
        by_clause.setdefault(identifier, []).append(outcomes[claim["case_id"]])
    for identifier, outcomes in by_clause.items():
        # Preserve negative observations; never select the 'strongest' past pass.
        # A successful test is evidence of its named assertion, not of every
        # obligation in a still-undecomposed normative block.
        states[identifier]["evidence"] = (
            "failing_observation" if any(s in {"fail", "error", "unexpected_success"} for s in outcomes)
            else "inconclusive" if any(s != "pass" for s in outcomes)
            else "passing_observation_not_completion"
        )


def render_report(root: Path, inventory: dict) -> str:
    for path in sorted((root / "conformance/receipts").glob("*.json")):
        validate_run(root, read_json(path), published=True)
    states = decision_states(root, inventory)
    apply_evidence(root, states)
    lines = [
        "# GNAP normative evidence ledger", "",
        "Generated by `python3 tools/conformance_ledger.py generate`.", "",
        "**Incomplete source inventory, not a conformance certificate.** Units below",
        "are anchored source blocks, not reviewed atomic requirements. No global",
        "completion percentage is calculated. Every source block remains visible,",
        "including unimplemented features, deployment duties, recommendations and options.", "",
        "## Source reconciliation", "",
        "| RFC | Source BCP14 markers | Normative markers | Terminology markers | Source blocks |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for doc in inventory["documents"]:
        r = doc["reconciliation"]
        lines.append(f"| {doc['rfc']} | {r['source_markers']} | {r['normative_markers']} | {r['excluded_markers']} | {r['source_blocks']} |")
    lines.extend(["", "All original keywords are retained. REQUIRED/SHALL have MUST strength;",
                  "RECOMMENDED has SHOULD strength. A block containing MUST and SHOULD keeps",
                  "both occurrences, and a passing observation cannot erase a recommendation.", "",
                  "## Applicability and observed evidence", "",
                  "| State | Source blocks |", "| --- | ---: |"])
    for key in ("applicability", "evidence"):
        for state, count in sorted(Counter(s[key] for s in states.values()).items()):
            lines.append(f"| {key}: `{state}` | {count} |")
    observations = {}
    for claim in read_json(root / "conformance/evidence.json")["claims"]:
        run = read_json(local_path(root, claim["run"]))
        if "observation" in run:
            observations.setdefault(claim["run"], {"observation": run["observation"], "assertions": []})["assertions"].append({
                "clause_id": claim["clause_id"], "case_id": claim["case_id"], "assertion": claim["assertion"]})
    if observations:
        lines.extend(["", "## Bound discovery observations", "",
                      "Capture replay describes the historical response at the recorded endpoint/time,",
                      "not current server behavior, remote source attestation or block completion.", ""])
        # JSON escaping plus escaped backticks prevents untrusted metadata from
        # breaking out of the fenced data block in the generated Markdown.
        lines.extend(["```json", json.dumps(observations, indent=2, sort_keys=True, ensure_ascii=True).replace("`", "\\u0060"), "```", ""])
    lines.extend(["", "`condition_false` requires a reviewed condition, role, profile and rationale;",
                  "it does not remove a source block or mean a missing project target is completed.",
                  "`passing_observation_not_completion` means the named test ran successfully;",
                  "atomic decomposition and assertion sufficiency still need review. A source",
                  "comment, an unexecuted vector, a missing test or a skipped test is never a pass.", "",
                  "## Appendix C capability context", ""])
    for doc in inventory["documents"]:
        for clause in doc["clauses"]:
            if doc["rfc"] == "9635" and clause["section"] in {"C.1", "C.2"}:
                lines.append(f"### {clause['section']}: {clause['section_title']}")
                lines.append("")
                for listing in clause["list_context"]:
                    for item in listing["items"]:
                        lines.append(f"- {item['text']}")
                lines.append("")
    lines.extend([
        "These are literal source capability names, including the RFC's `jwks` spelling;",
        "interpretation belongs to reviewed decisions, not silent source rewriting.",
        "Appendix C permits a functioning client subset in its stated circumstances;",
        "it does not grant an AS that exception. Neither C1 nor C2 completion is claimed.", "",
        "## Evidence limits", "",
        "Historical private coverage assertions were not imported. XML extraction and",
        "ledger regression tests exercise this tool, not GNAP implementations. Execution",
        "receipts are trusted local test-run records, not cryptographic attestations or",
        "proof that a test assertion fully expresses an RFC requirement. Uploaded receipts",
        "from untrusted parties must not be accepted by a public service.", "",
        "See [README.md](README.md) for reproduction, data contracts and next steps.",
    ])
    return "\n".join(lines) + "\n"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(root: Path) -> None:
    opener = urllib.request.build_opener(NoRedirects())
    downloaded = []
    for item in sources(root):
        request = urllib.request.Request(item["url"], headers={"User-Agent": "gnap-public-ledger/1"})
        with opener.open(request, timeout=30) as response:
            data = response.read(MAX_SOURCE_BYTES + 1)
        require(len(data) <= MAX_SOURCE_BYTES and digest(data) == item["sha256"],
                f"Downloaded source differs from pinned bytes: RFC{item['rfc']}")
        downloaded.append((local_path(root, item["path"]), data))
    # Do not replace either source unless both passed their pinned checks.
    for path, data in downloaded:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def flatten_tests(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten_tests(test)
        else:
            yield test


class RecordingResult(unittest.TextTestResult):
    # A case can report several outcomes: one per failing subtest, then its own
    # body, which may still fail, raise or skip. The most severe one is kept and
    # nothing is ever downgraded, whatever order unittest reports them in.
    # "error" outranks "fail": a case that raised something other than an
    # assertion failure did not run as designed, so its result is not a verdict
    # on the behaviour under test. An unexpected success is a failure for
    # unittest too. A skip or an expected failure is inconclusive, so it
    # outranks "pass": a partly skipped case is not a passing observation.
    SEVERITY = {"error": 3, "fail": 2, "unexpected_success": 2, "skipped": 1, "expected_failure": 1, "pass": 0}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def record(self, test, outcome):
        # A skipped subtest arrives under a derived ID and leaves its parent
        # case without a success callback. It counts against the parent.
        if isinstance(test, unittest.case._SubTest):
            test = test.test_case
        previous = self.outcomes.get(test.id())
        if previous is None or self.SEVERITY[previous] <= self.SEVERITY[outcome]:
            self.outcomes[test.id()] = outcome

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "fail")

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, "skipped")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, "expected_failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, "unexpected_success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            # The same split unittest applies: an assertion failure is a
            # failure, any other exception is an error.
            self.record(test, "fail" if issubclass(err[0], test.failureException) else "error")


def run_tests(root: Path, directory: str, scope: str, output: str, *, observation=None, capture=None, published=False) -> bool:
    start_dir = local_path(root, directory)
    require(start_dir.is_dir(), "Test directory does not exist")
    require(scope == "tooling" or start_dir.is_relative_to((root / "conformance/scenarios").resolve()),
            "GNAP scenario receipts require tests under conformance/scenarios; tooling tests cannot be relabelled")
    output_path = local_path(root, output)
    folder = "conformance/receipts" if published else "conformance/runs"
    require(output_path.is_relative_to((root / folder).resolve()) and output_path.suffix == ".json", f"Receipt path must be {folder}/*.json")
    suite = unittest.defaultTestLoader.discover(str(start_dir))
    cases = list(flatten_tests(suite))
    identifiers = [case.id() for case in cases]
    require(identifiers and len(identifiers) == len(set(identifiers)), "No tests or duplicate test IDs discovered")
    # Source hashes bind the test modules and the tool that produced the receipt.
    # Other dependency/configuration provenance must be added by future runners.
    files = {Path(__file__).resolve()}
    if observation is not None:
        require(directory == "conformance/scenarios", "Discovery runner uses only the fixed scenario directory")
        files.add(root / "conformance/discovery.py")
        files.add(local_path(root, observation["capture_path"]))
        require("test_as_discovery" in sys.modules, "Discovery scenario module was not discovered")
        sys.modules["test_as_discovery"].CAPTURE = capture
    for case in cases:
        module = sys.modules.get(type(case).__module__)
        path = getattr(module, "__file__", None)
        require(path is not None, "Cannot locate discovered test source")
        files.add(Path(path).resolve())
    hashes = {}
    for path in sorted(files):
        require(path.is_relative_to(root.resolve()), "Discovered test source is outside repository")
        hashes[str(path.relative_to(root.resolve()))] = digest(path.read_bytes())
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True))
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = "unknown", True
    require(not published or (revision != "unknown" and not dirty), "Publish only from a clean committed source tree")
    started = int(time.time())
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    # setUpClass/Module failures can yield synthetic IDs and leave discovered
    # cases unrun. Refuse to emit a falsely complete receipt in that case.
    require(set(result.outcomes) == set(identifiers), "Execution did not report every discovered case; no receipt written")
    require(all(path.is_file() and digest(path.read_bytes()) == hashes[str(path.relative_to(root.resolve()))] for path in files), "Sources changed during execution")
    receipt = {"schema_version": SCHEMA, "runner": "python-unittest-v1", "scope": scope,
               "started_at_unix_utc": started, "finished_at_unix_utc": int(time.time()),
               "source_revision": revision, "working_tree_dirty": dirty,
               "source_files": hashes, "discovered_cases": identifiers,
               "results": [{"case_id": case, "status": result.outcomes[case]} for case in identifiers]}
    if observation is not None:
        receipt["observation"] = observation
    validate_run(root, receipt, published=published)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(canonical(receipt), encoding="utf-8")
    return result.wasSuccessful()


def discovery_tests(root: Path, capture_path: str, output: str, published: bool) -> bool:
    from conformance.discovery import read_capture, CaptureError
    path = local_path(root, capture_path)
    try:
        capture = read_capture(path)
    except CaptureError as error:
        raise LedgerError(str(error)) from error
    require(not published or not path.is_relative_to((root / "conformance/runs").resolve()),
            "Publish the reviewed capture in conformance/captures before recording a clean-source receipt")
    observation = {"kind": "as-discovery-v1", "execution_mode": "capture_replay",
                   "capture_path": capture_path, "capture_sha256": digest(path.read_bytes())}
    for field in ("capture_origin", "endpoint", "captured_at_unix_utc", "remote_revision", "collector_config_sha256"):
        observation[field] = capture[field]
    return run_tests(root, "conformance/scenarios", "gnap-scenarios", output,
                     observation=observation, capture=capture, published=published)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("fetch", "generate", "check", "report"):
        sub.add_parser(name)
    runner = sub.add_parser("run-tests", help="Execute trusted local Python unittest tests and record every named outcome")
    runner.add_argument("--directory", default="conformance/tests")
    runner.add_argument("--scope", choices=("tooling", "gnap-scenarios"), default="tooling")
    runner.add_argument("--output", default="conformance/runs/self-tests.json")
    discovery = sub.add_parser("discovery-tests", help="Replay one bound capture through six independent section 9 assertions; offline by default")
    discovery.add_argument("--capture", default="conformance/fixtures/discovery.json")
    discovery.add_argument("--output", default="conformance/runs/discovery.json")
    discovery.add_argument("--publish", action="store_true")
    collector = sub.add_parser("capture-discovery", help="Operator-only live collection; requires environment opt-in and forbids CI")
    collector.add_argument("--output", default="conformance/runs/discovery-capture.json")
    args = parser.parse_args()
    try:
        if args.command == "fetch":
            fetch(ROOT)
        elif args.command == "run-tests":
            return 0 if run_tests(ROOT, args.directory, args.scope, args.output) else 1
        elif args.command == "discovery-tests":
            return 0 if discovery_tests(ROOT, args.capture, args.output, args.publish) else 1
        elif args.command == "capture-discovery":
            import os
            from conformance.discovery import acquire, encoded, CaptureError
            output = local_path(ROOT, args.output)
            require(output.is_relative_to((ROOT / "conformance/runs").resolve()) and output.suffix == ".json", "Live capture output must be conformance/runs/*.json")
            try:
                capture = acquire(os.environ.get("GNAP_DISCOVERY_ENDPOINT"))
            except CaptureError as error:
                raise LedgerError(str(error)) from error
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(encoded(capture))
        else:
            inventory = generate_inventory(ROOT)
            report = render_report(ROOT, inventory)
            artifacts = {ROOT / "conformance/clauses.json": canonical(inventory), ROOT / "conformance/REPORT.md": report}
            if args.command == "generate":
                for path, contents in artifacts.items():
                    path.write_text(contents, encoding="utf-8")
            elif args.command == "check":
                for path, expected in artifacts.items():
                    require(path.is_file() and path.read_text(encoding="utf-8") == expected,
                            f"Generated artifact differs: {path.relative_to(ROOT)}")
                print("Source hashes, marker ownership, decisions, evidence and generated artifacts verified. No conformance completion claim.")
            else:
                print(report, end="")
    except (LedgerError, OSError) as error:
        print(f"ledger error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
