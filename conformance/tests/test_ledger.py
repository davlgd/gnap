"""Regression tests for the ledger itself, not evidence of GNAP conformance."""

import copy
import importlib.util
import io
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("conformance_ledger", ROOT / "tools/conformance_ledger.py")
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


def xml(number="9635", content=None):
    if content is None:
        content = '<t pn="section-2-1">The AS <bcp14>MUST</bcp14> reject it and <bcp14>SHOULD</bcp14> explain why.</t>'
    return (f'<rfc number="{number}"><middle><section pn="section-2"><name>Request</name>'
            f'{content}</section></middle></rfc>').encode()


class ExtractionTests(unittest.TestCase):
    def test_required_is_mandatory_without_erasing_other_strengths(self):
        result = ledger.extract_document("9635", xml(content=(
            '<dl pn="section-2-1"><dt pn="section-2-1.1">client (object)</dt>'
            '<dd pn="section-2-1.2"><bcp14>REQUIRED</bcp14>. '
            'A name is <bcp14>RECOMMENDED</bcp14>, extras are <bcp14>OPTIONAL</bcp14>.</dd></dl>')))
        clause = result["clauses"][0]
        self.assertEqual([o["strength"] for o in clause["occurrences"]], ["obligation", "recommendation", "option"])
        self.assertEqual([o["keyword"] for o in clause["occurrences"]], ["REQUIRED", "RECOMMENDED", "OPTIONAL"])
        self.assertEqual(clause["field_context"], "client (object)")

    def test_compound_blocks_keep_each_marker(self):
        result = ledger.extract_document("9635", xml())
        self.assertEqual(len(result["clauses"]), 1)
        self.assertEqual(result["reconciliation"]["source_markers"], 2)
        self.assertEqual(result["reconciliation"]["normative_markers"], 2)
        self.assertEqual([o["keyword"] for o in result["clauses"][0]["occurrences"]], ["MUST", "SHOULD"])

    def test_anchor_id_does_not_change_when_an_earlier_block_is_added(self):
        first = ledger.extract_document("9635", xml())["clauses"][0]["id"]
        modified = ledger.extract_document("9635", xml(content=(
            '<t pn="section-2-other">A client <bcp14>MAY</bcp14> act.</t>'
            '<t pn="section-2-1">The AS <bcp14>SHALL</bcp14> reject it.</t>')))
        self.assertEqual(modified["clauses"][1]["id"], first)

    def test_unmarked_following_list_is_retained(self):
        result = ledger.extract_document("9635", xml(content=(
            '<t pn="section-2-1">Implementations <bcp14>MUST</bcp14> implement:</t>'
            '<ul pn="section-2-2"><li pn="section-2-2.1">redirect</li>'
            '<li pn="section-2-2.2">PS256</li></ul>')))
        items = result["clauses"][0]["list_context"][0]["items"]
        self.assertEqual([i["text"] for i in items], ["redirect", "PS256"])
        self.assertEqual(result["reconciliation"]["source_markers"], 1)

    def test_normative_list_item_is_not_double_counted_as_context(self):
        result = ledger.extract_document("9635", xml(content=(
            '<t pn="section-2-1">Implementations <bcp14>MUST</bcp14> implement:</t>'
            '<ul pn="section-2-2"><li pn="section-2-2.1">The client <bcp14>MUST NOT</bcp14> retry.</li></ul>')))
        self.assertEqual(result["reconciliation"]["source_markers"], 2)
        self.assertEqual(sum(len(c["occurrences"]) for c in result["clauses"]), 2)
        self.assertEqual(result["clauses"][1]["preceding_context"], "Implementations MUST implement:")

    def test_xref_and_nested_field_context_survive(self):
        result = ledger.extract_document("9635", xml(content=(
            '<dl pn="section-2-1"><dt pn="section-2-1.1">label</dt><dd pn="section-2-1.2">'
            '<t pn="section-2-1.2.1"><bcp14>REQUIRED</bcp14> as in <xref derivedContent="Section 3.2"/>.</t>'
            '</dd></dl>')))
        clause = result["clauses"][0]
        self.assertEqual(clause["field_context"], "label")
        self.assertEqual(clause["text"], "REQUIRED as in Section 3.2.")

    def test_unknown_marker_and_anchor_collision_are_errors(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.extract_document("9635", xml(content='<t pn="section-2-1"><bcp14>WHATEVER</bcp14></t>'))
        with self.assertRaises(ledger.LedgerError):
            ledger.extract_document("9635", xml(content='<t pn="same"><bcp14>MUST</bcp14></t><t pn="same"><bcp14>MAY</bcp14></t>'))
        with self.assertRaises(ledger.LedgerError):
            ledger.extract_document("9635", xml(content='<t><bcp14>MUST</bcp14></t>'))

    def test_official_source_counts_and_both_eight_item_profiles(self):
        inventory = ledger.generate_inventory(ROOT)
        self.assertEqual([d["reconciliation"]["source_markers"] for d in inventory["documents"]], [553, 80])
        self.assertEqual([d["reconciliation"]["normative_markers"] for d in inventory["documents"]], [542, 69])
        self.assertEqual([d["reconciliation"]["excluded_markers"] for d in inventory["documents"]], [11, 11])
        core = inventory["documents"][0]
        for section in ("C.1", "C.2"):
            clause = next(c for c in core["clauses"] if c["section"] == section)
            self.assertEqual(len(clause["list_context"][0]["items"]), 8)
        secondary = next(c for c in core["clauses"] if c["section"] == "C.2")
        self.assertIn("user_code and user_code_uri", secondary["list_context"][0]["items"][0]["text"])

    def test_generated_artifacts_reproduce_without_network(self):
        inventory = ledger.generate_inventory(ROOT)
        self.assertEqual((ROOT / "conformance/clauses.json").read_text(), ledger.canonical(inventory))
        self.assertEqual((ROOT / "conformance/REPORT.md").read_text(), ledger.render_report(ROOT, inventory))
        self.assertNotIn("%", ledger.render_report(ROOT, inventory))


class LedgerInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gnap-ledger-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        documents = []
        for number in ("9635", "9767"):
            data = xml(number)
            relative = f"conformance/sources/rfc{number}.xml"
            self.write(relative, data)
            documents.append({"rfc": number, "url": f"https://www.rfc-editor.org/rfc/rfc{number}.xml", "path": relative, "sha256": ledger.digest(data)})
        self.write_json("conformance/sources.lock.json", {"schema_version": 1, "documents": documents})
        self.write_json("conformance/decisions.json", {"schema_version": 1, "decisions": []})
        self.write_json("conformance/evidence.json", {"schema_version": 1, "claims": []})
        self.inventory = ledger.generate_inventory(self.root)
        self.identifier = self.inventory["documents"][0]["clauses"][0]["id"]

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def write_json(self, relative, value):
        self.write(relative, ledger.canonical(value).encode())

    def decision(self, **kwargs):
        decision = {"clause_id": self.identifier, "applicability": "applicable", "review": "reviewed", "rationale": "Synthetic ledger unit-test fixture, not a protocol assertion", "condition": "Fixture condition", "role": "as", "profile": "core"}
        return decision | kwargs

    def receipt(self, status="pass", scope="gnap-scenarios"):
        relative = "conformance/scenarios/fixture_test.py" if scope == "gnap-scenarios" else "conformance/tests/fixture_test.py"
        self.write(relative, b"# synthetic receipt fixture, not protocol evidence\nimport unittest\nclass Case(unittest.TestCase):\n    def test_synthetic(self):\n        self.assertTrue(True)\n")
        self.write(ledger.RUNNER_PATH, (ROOT / ledger.RUNNER_PATH).read_bytes())
        return {"schema_version": 1, "runner": "python-unittest-v1", "scope": scope,
                "started_at_unix_utc": 10, "finished_at_unix_utc": 11,
                "source_revision": "unknown", "working_tree_dirty": True,
                "source_files": {relative: ledger.digest((self.root / relative).read_bytes()), ledger.RUNNER_PATH: ledger.digest((self.root / ledger.RUNNER_PATH).read_bytes())},
                "discovered_cases": ["fixture_test.Case.test_synthetic"],
                "results": [{"case_id": "fixture_test.Case.test_synthetic", "status": status}]}

    def prepare_claim(self, outcome="pass", scope="gnap-scenarios"):
        self.write_json("conformance/decisions.json", {"schema_version": 1, "decisions": [self.decision()]})
        receipt = self.receipt(outcome, scope)
        self.write_json("conformance/runs/synthetic.json", receipt)
        claim = {"clause_id": self.identifier, "run": "conformance/runs/synthetic.json", "case_id": receipt["discovered_cases"][0], "assertion": "Synthetic fixture; this is not GNAP evidence"}
        self.write_json("conformance/evidence.json", {"schema_version": 1, "claims": [claim]})
        return claim

    def test_source_hash_mismatch_and_missing_source_fail_closed(self):
        self.write("conformance/sources/rfc9635.xml", b"changed")
        with self.assertRaisesRegex(ledger.LedgerError, "hash mismatch"):
            ledger.generate_inventory(self.root)
        (self.root / "conformance/sources/rfc9635.xml").unlink()
        with self.assertRaisesRegex(ledger.LedgerError, "Missing source"):
            ledger.generate_inventory(self.root)

    def test_wrong_rfc_identity_and_source_url_are_rejected(self):
        with self.assertRaisesRegex(ledger.LedgerError, "identity"):
            ledger.extract_document("9635", xml("9767"))
        lock = ledger.read_json(self.root / "conformance/sources.lock.json")
        lock["documents"][0]["url"] = "https://attacker.example/rfc9635.xml"
        self.write_json("conformance/sources.lock.json", lock)
        with self.assertRaisesRegex(ledger.LedgerError, "source URL"):
            ledger.sources(self.root)

    def test_unknown_id_and_duplicate_decision_are_errors(self):
        for decisions in ([self.decision(clause_id="does-not-exist")], [self.decision(), self.decision(applicability="condition_false")]):
            self.write_json("conformance/decisions.json", {"schema_version": 1, "decisions": decisions})
            with self.assertRaises(ledger.LedgerError):
                ledger.decision_states(self.root, self.inventory)

    def test_condition_false_requires_review_and_explicit_context(self):
        for decision in (self.decision(applicability="condition_false", review="unresolved"), self.decision(applicability="condition_false", condition=""), self.decision(role="unknown")):
            self.write_json("conformance/decisions.json", {"schema_version": 1, "decisions": [decision]})
            with self.assertRaises(ledger.LedgerError):
                ledger.decision_states(self.root, self.inventory)

    def test_unreviewed_and_condition_false_cannot_claim_passing_evidence(self):
        self.prepare_claim()
        for decisions in ([], [self.decision(applicability="condition_false")]):
            self.write_json("conformance/decisions.json", {"schema_version": 1, "decisions": decisions})
            states = ledger.decision_states(self.root, self.inventory)
            with self.assertRaisesRegex(ledger.LedgerError, "contradict"):
                ledger.apply_evidence(self.root, states)

    def test_test_absent_from_receipt_cannot_pass(self):
        claim = self.prepare_claim()
        claim["case_id"] = "not_executed"
        self.write_json("conformance/evidence.json", {"schema_version": 1, "claims": [claim]})
        with self.assertRaisesRegex(ledger.LedgerError, "absent test"):
            ledger.apply_evidence(self.root, ledger.decision_states(self.root, self.inventory))

    def test_comment_vector_and_no_execution_receipt_cannot_pass(self):
        claim = self.prepare_claim()
        for receipt in ({"by": "test", "ref": "comment-only"}, {"by": "vector", "ref": "vectors/example.json"}):
            self.write_json(claim["run"], receipt)
            with self.assertRaisesRegex(ledger.LedgerError, "fields"):
                ledger.apply_evidence(self.root, ledger.decision_states(self.root, self.inventory))

    def test_skipped_expected_failure_and_failed_cases_do_not_pass(self):
        for outcome, expected in (("skipped", "inconclusive"), ("expected_failure", "inconclusive"), ("fail", "failing_observation"), ("unexpected_success", "failing_observation")):
            self.prepare_claim(outcome)
            states = ledger.decision_states(self.root, self.inventory)
            ledger.apply_evidence(self.root, states)
            self.assertEqual(states[self.identifier]["evidence"], expected)

    def test_even_passing_execution_is_not_normative_completion(self):
        self.prepare_claim()
        states = ledger.decision_states(self.root, self.inventory)
        ledger.apply_evidence(self.root, states)
        self.assertEqual(states[self.identifier]["evidence"], "passing_observation_not_completion")

    def test_tooling_scope_cannot_attest_gnap(self):
        self.prepare_claim(scope="tooling")
        with self.assertRaisesRegex(ledger.LedgerError, "self-tests"):
            ledger.apply_evidence(self.root, ledger.decision_states(self.root, self.inventory))

    def test_real_tooling_execution_cannot_be_relabelled_as_gnap(self):
        # Actually execute one synthetic tooling test in an isolated temporary
        # tree. Its receipt is real; only the subsequent mutation is fabricated.
        self.write(ledger.RUNNER_PATH, (ROOT / ledger.RUNNER_PATH).read_bytes())
        self.write("conformance/tests/test_scope_boundary.py", b"import unittest\nclass Boundary(unittest.TestCase):\n    def test_fixture(self):\n        self.assertEqual(2 + 2, 4)\n")
        completed = subprocess.run([sys.executable, "-B", str(self.root / ledger.RUNNER_PATH), "run-tests"],
                                   cwd=self.root, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = ledger.read_json(self.root / "conformance/runs/self-tests.json")
        self.assertEqual(receipt["scope"], "tooling")
        self.assertEqual(list(ledger.validate_run(self.root, receipt).values()), ["pass"])
        receipt["scope"] = "gnap-scenarios"
        with self.assertRaisesRegex(ledger.LedgerError, "tooling cannot be relabelled"):
            ledger.validate_run(self.root, receipt)
        self.write_json("conformance/runs/self-tests.json", receipt)
        self.write_json("conformance/decisions.json", {"schema_version": 1, "decisions": [self.decision()]})
        self.write_json("conformance/evidence.json", {"schema_version": 1, "claims": [{"clause_id": self.identifier, "run": "conformance/runs/self-tests.json", "case_id": receipt["discovered_cases"][0], "assertion": "Synthetic mutation, never actual GNAP evidence"}]})
        with self.assertRaisesRegex(ledger.LedgerError, "tooling cannot be relabelled"):
            ledger.apply_evidence(self.root, ledger.decision_states(self.root, self.inventory))

    def test_missing_or_replaced_runner_hash_is_rejected(self):
        receipt = self.receipt()
        del receipt["source_files"][ledger.RUNNER_PATH]
        with self.assertRaisesRegex(ledger.LedgerError, "required runner hash"):
            ledger.validate_run(self.root, receipt)
        receipt = self.receipt()
        receipt["source_files"][ledger.RUNNER_PATH] = "0" * 64
        with self.assertRaisesRegex(ledger.LedgerError, "current ledger tool"):
            ledger.validate_run(self.root, receipt)

    def test_malformed_json_field_types_are_ledger_errors(self):
        receipt = self.receipt()
        for field, invalid in (("scope", []), ("results", {}), ("started_at_unix_utc", True)):
            with self.subTest(field=field):
                mutated = copy.deepcopy(receipt)
                mutated[field] = invalid
                with self.assertRaises(ledger.LedgerError):
                    ledger.validate_run(self.root, mutated)
        for field in ("case_id", "status"):
            mutated = copy.deepcopy(receipt)
            mutated["results"][0][field] = []
            with self.assertRaises(ledger.LedgerError):
                ledger.validate_run(self.root, mutated)

    def test_changed_test_source_or_unaccounted_case_invalidates_receipt(self):
        receipt = self.receipt()
        receipt["results"] = []
        with self.assertRaisesRegex(ledger.LedgerError, "not all accounted"):
            ledger.validate_run(self.root, receipt)

    def test_a_receipt_cannot_invent_a_nonexistent_test_declaration(self):
        receipt = self.receipt()
        receipt["discovered_cases"] = ["fixture_test.Case.test_invented"]
        receipt["results"][0]["case_id"] = receipt["discovered_cases"][0]
        with self.assertRaisesRegex(ledger.LedgerError, "declaration is absent"):
            ledger.validate_run(self.root, receipt)
        receipt = self.receipt()
        self.write("conformance/scenarios/fixture_test.py", b"renamed or changed test")
        with self.assertRaisesRegex(ledger.LedgerError, "changed or disappeared"):
            ledger.validate_run(self.root, receipt)

    def test_unknown_evidence_id_or_duplicate_result_is_rejected(self):
        claim = self.prepare_claim()
        claim["clause_id"] = "unknown-clause"
        self.write_json("conformance/evidence.json", {"schema_version": 1, "claims": [claim]})
        with self.assertRaisesRegex(ledger.LedgerError, "unknown clause"):
            ledger.apply_evidence(self.root, ledger.decision_states(self.root, self.inventory))
        receipt = self.receipt()
        receipt["results"].append(copy.deepcopy(receipt["results"][0]))
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate executed"):
            ledger.validate_run(self.root, receipt)

    def test_duplicate_json_keys_are_not_silently_overwritten(self):
        self.write("duplicate.json", b'{"status":"fail","status":"pass"}')
        with self.assertRaisesRegex(ledger.LedgerError, "Duplicate JSON"):
            ledger.read_json(self.root / "duplicate.json")

    def test_path_traversal_is_rejected(self):
        for relative in ("../../outside.json", "/etc/passwd"):
            with self.assertRaises(ledger.LedgerError):
                ledger.local_path(self.root, relative)


class RunnerTests(unittest.TestCase):
    def test_recorder_records_actual_named_outcomes_including_subtest_failure(self):
        class Fixture(unittest.TestCase):
            def test_good(self):
                self.assertEqual(1 + 1, 2)

            @unittest.skip("intentional fixture")
            def test_skipped(self):
                self.fail("must never run")

            def test_failed_subtest(self):
                with self.subTest("fixture"):
                    self.assertEqual(1, 2)

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Fixture)
        result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=ledger.RecordingResult).run(suite)
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(Counter(result.outcomes.values()), {"pass": 1, "fail": 1, "skipped": 1})


if __name__ == "__main__":
    unittest.main()
