"""Synthetic oracle/provenance regressions, never observations of a real AS."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from conformance import discovery as wire
from conformance.scenarios import test_as_discovery as scenario

SPEC = importlib.util.spec_from_file_location("discovery_ledger_tests", ROOT / "tools/conformance_ledger.py")
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)


class CommandErrorTests(unittest.TestCase):
    def test_unexpected_command_errors_keep_the_process_traceback(self):
        for command, operation in (("capture-discovery", "acquire"), ("discovery-tests", "read_capture")):
            with self.subTest(command=command):
                script = f"""
import sys
from unittest import mock
sys.path.insert(0, {str(ROOT / 'tools')!r})
import conformance_ledger as ledger
from conformance import discovery
sys.argv = ['ledger', {command!r}]
with mock.patch.object(discovery, {operation!r}, side_effect=ValueError('unexpected bug')):
    raise SystemExit(ledger.main())
"""
                result = subprocess.run([sys.executable, "-B", "-c", script], cwd=ROOT,
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Traceback (most recent call last)", result.stderr)
                self.assertIn("ValueError: unexpected bug", result.stderr)
                self.assertNotIn("ledger error:", result.stderr)

    def test_expected_capture_errors_are_reported_by_both_commands(self):
        for command, operation in (("capture-discovery", "acquire"), ("discovery-tests", "read_capture")):
            with self.subTest(command=command):
                stream = io.StringIO()
                with mock.patch.object(sys, "argv", ["ledger", command]), \
                     mock.patch.object(sys, "stderr", stream), \
                     mock.patch.object(wire, operation, side_effect=wire.CaptureError("invalid capture")):
                    self.assertEqual(ledger.main(), 1)
                self.assertEqual(stream.getvalue(), "ledger error: invalid capture\n")

    def test_unexpected_value_errors_remain_visible_from_both_commands(self):
        for command, operation in (("capture-discovery", "acquire"), ("discovery-tests", "read_capture")):
            with self.subTest(command=command):
                stream = io.StringIO()
                with mock.patch.object(sys, "argv", ["ledger", command]), \
                     mock.patch.object(sys, "stderr", stream), \
                     mock.patch.object(wire, operation, side_effect=ValueError("unexpected bug")):
                    with self.assertRaisesRegex(ValueError, "unexpected bug"):
                        ledger.main()
                self.assertEqual(stream.getvalue(), "")


class OracleTests(unittest.TestCase):
    def test_endpoint_reads_and_parses_its_capture_once(self):
        capture = wire.make_capture("https://as.example/gnap", 200,
                                    [["content-type", "application/json"]],
                                    b'{"grant_request_endpoint":"https://as.example/gnap"}',
                                    origin="synthetic", timestamp=None)
        case = scenario.DiscoveryResponse("test_endpoint_required_string")
        with mock.patch.object(case, "capture", return_value=capture) as read, \
                mock.patch.object(wire, "document", wraps=wire.document) as parse:
            self.assertEqual(case.endpoint(), "https://as.example/gnap")
        read.assert_called_once_with()
        parse.assert_called_once_with(capture)

    def outcomes(self, body, *, status=200, headers=None, target="https://as.example/gnap"):
        capture = wire.make_capture(target, status, headers if headers is not None else [["content-type", "application/json"]],
                                    body, origin="synthetic", timestamp=None)
        with mock.patch.object(scenario, "CAPTURE", capture):
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(scenario.DiscoveryResponse)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, resultclass=ledger.RecordingResult).run(suite)
        self.assertNotIn("TOP-SECRET", stream.getvalue())
        return {key.rsplit(".", 1)[1]: value for key, value in result.outcomes.items()}

    def test_six_assertions_run_and_http_200_is_not_a_normative_assertion(self):
        outcomes = self.outcomes(b'{"grant_request_endpoint":"https://as.example/gnap"}', status=201)
        self.assertEqual(len(outcomes), 6)
        self.assertEqual(set(outcomes.values()), {"pass"})

    def test_media_object_type_scheme_components_and_identity_have_negative_cases(self):
        cases = [
            (b'{}', "test_endpoint_required_string"),
            (b'[]', "test_response_is_json_object"),
            (b'{', "test_response_is_json_object"),
            (b'{"grant_request_endpoint":42}', "test_endpoint_required_string"),
            (b'{"grant_request_endpoint":"http://as.example/gnap"}', "test_endpoint_https"),
            (b'{"grant_request_endpoint":"https:///gnap"}', "test_endpoint_absolute_host_without_fragment"),
            (b'{"grant_request_endpoint":"https://as.example/gnap#fragment"}', "test_endpoint_absolute_host_without_fragment"),
            (b'{"grant_request_endpoint":"https://as.example/other"}', "test_endpoint_matches_exact_request"),
        ]
        for body, name in cases:
            with self.subTest(name=name):
                self.assertEqual(self.outcomes(body)[name], "fail")
        self.assertEqual(self.outcomes(b'{}', headers=[["content-type", "TOP-SECRET"]])["test_options_response_media_type"], "fail")

    def test_duplicate_members_are_inconclusive_not_invented_gnap_must(self):
        outcomes = self.outcomes(b'{"grant_request_endpoint":"https://as.example/gnap","grant_request_endpoint":"TOP-SECRET"}')
        self.assertEqual(outcomes["test_response_is_json_object"], "skipped")
        self.assertEqual(outcomes["test_endpoint_required_string"], "skipped")

    def test_absent_content_type_fails_but_repetition_is_inconclusive(self):
        body = b'{"grant_request_endpoint":"https://as.example/gnap"}'
        self.assertEqual(self.outcomes(body, headers=[])["test_options_response_media_type"], "fail")
        self.assertEqual(self.outcomes(body, headers=[["content-type", "application/json"], ["content-type", "text/html"]])["test_options_response_media_type"], "skipped")

    def test_uri_grammar_does_not_invent_userinfo_or_whatwg_constraints(self):
        for value in ("https://user:pw@host/gnap", "https://@host/gnap", "https://[v1.future]/gnap", "https://host:999999999999/gnap", "https://%FF.example/gnap", "https://999.999/gnap"):
            self.assertTrue(wire.absolute_host_without_fragment(value), value)
        for value in ("https://", "https://host:words/gnap", "https://[vG.future]/gnap", "https://host/space here", "https://host/%ZZ", "https://höst/", "https://[::1]evil/", "https://host/\\"):
            self.assertFalse(wire.absolute_host_without_fragment(value), value)

    def test_capture_hash_bounds_and_secret_headers_are_enforced(self):
        original = wire.read_capture(ROOT / "conformance/fixtures/discovery.json")
        for field, value in (("body_sha256", "0" * 64), ("body_base64", "!"), ("headers", [["authorization", "TOP-SECRET"]]),
                             ("remote_revision", "fabricated-commit"), ("collector_config_sha256", "0" * 64)):
            altered = original | {field: value}
            with self.assertRaises(wire.CaptureError):
                wire.validate_capture(altered)
        with self.assertRaises(wire.CaptureError):
            wire.make_capture("https://as.example/gnap", 200, [], b"x" * (wire.LIMIT + 1), origin="synthetic", timestamp=None)

    def test_live_is_opt_in_and_never_runs_in_ci(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(wire.subprocess, "run") as launch:
            with self.assertRaises(wire.CaptureError):
                wire.acquire("https://as.example/gnap")
            launch.assert_not_called()
        with mock.patch.dict(os.environ, {"GNAP_DISCOVERY_LIVE": "1", "CI": "true"}, clear=True), mock.patch.object(wire.subprocess, "run") as launch:
            with self.assertRaises(wire.CaptureError):
                wire.acquire("https://as.example/gnap")
            launch.assert_not_called()

    def test_collector_endpoint_and_dns_address_policy_are_conservative(self):
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "192.0.0.9", "192.88.99.1", "198.18.0.1", "224.0.0.1", "::1", "::ffff:8.8.8.8"):
            self.assertFalse(wire.public_ipv4(address), address)
        self.assertTrue(wire.public_ipv4("8.8.8.8"))
        for url in ("http://as.example/gnap", "https://127.0.0.1/gnap", "https://user@as.example/gnap", "https://as.example:443/gnap", "https://as.example/gnap#x", "https://as.example/gnap?x=1"):
            with self.assertRaises((wire.CaptureError, ValueError)):
                wire.configured_endpoint(url)
        wire.configured_endpoint("https://as.example/gnap")

    def test_collector_pins_dns_strips_headers_and_never_follows_redirects(self):
        for status in (200, 302):
            with self.subTest(status=status), mock.patch.dict(os.environ, {"GNAP_DISCOVERY_LIVE": "1", "HTTPS_PROXY": "http://forbidden"}, clear=True), \
                    mock.patch.object(wire.socket, "getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]), \
                    mock.patch.object(wire.socket, "create_connection") as connect, \
                    mock.patch.object(wire.ssl, "create_default_context") as context, \
                    mock.patch.object(wire.http.client, "HTTPSConnection") as http:
                response = http.return_value.getresponse.return_value
                response.status = status
                response.read1.side_effect = [b'{"grant_request_endpoint":"https://as.example/gnap"}', b'']
                response.getheaders.return_value = [("Content-Type", "application/json"), ("Set-Cookie", "TOP-SECRET"), ("Location", "http://169.254.169.254/")]
                if status == 302:
                    with self.assertRaises(wire.CaptureError):
                        wire._acquire("https://as.example/gnap")
                    response.read1.assert_not_called()
                else:
                    capture = wire._acquire("https://as.example/gnap")
                    self.assertEqual(capture["capture_origin"], "live")
                    self.assertEqual(capture["remote_revision"], "unknown")
                    self.assertNotIn("TOP-SECRET", json.dumps(capture))
                    self.assertEqual(capture["headers"], [["content-type", "application/json"]])
                self.assertEqual(connect.call_args.args[0], ("8.8.8.8", 443))
                context.return_value.wrap_socket.assert_called_once_with(connect.return_value, server_hostname="as.example")
                http.return_value.request.assert_called_once_with("OPTIONS", "/gnap", headers={"Accept": "application/json"})
                http.return_value.close.assert_called_once()

    def test_collector_does_not_connect_to_any_mixed_private_dns_answer(self):
        with mock.patch.dict(os.environ, {"GNAP_DISCOVERY_LIVE": "1"}, clear=True), \
                mock.patch.object(wire.socket, "getaddrinfo", return_value=[(None, None, None, None, (address, 443)) for address in ("8.8.8.8", "127.0.0.1")]), \
                mock.patch.object(wire.socket, "create_connection") as connect:
            with self.assertRaises(wire.CaptureError):
                wire._acquire("https://as.example/gnap")
            connect.assert_not_called()

    def test_wall_clock_kills_slow_connect_and_real_http_parser_drip_headers_or_chunks(self):
        # Real child processes and HTTPResponse parsing over socketpair; no DNS,
        # external network, TLS certificate claim or live-AS evidence.
        program = r'''
import os, socket, sys, threading, time
from unittest import mock
sys.path.insert(0, sys.argv[1])
from conformance import discovery as wire
mode = sys.argv[2]
with open(sys.argv[3], "w") as output:
    output.write(str(os.getpid()))
client, server = socket.socketpair()
def drip():
    server.recv(4096)
    initial = b"HTTP/1.1 200 OK\r\nX-Slow: " if mode == "headers" else b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;extension="
    server.sendall(initial)
    while True:
        server.sendall(b"x")
        time.sleep(0.01)
threading.Thread(target=drip, daemon=True).start()
def connect(*args, **kwargs):
    if mode == "connect":
        time.sleep(10)
    return client
with mock.patch.object(wire.socket, "getaddrinfo", return_value=[(0, 0, 0, 0, ("8.8.8.8", 443))]), mock.patch.object(wire.socket, "create_connection", side_effect=connect), mock.patch.object(wire.ssl, "create_default_context") as context:
    context.return_value.wrap_socket.side_effect = lambda raw, **kwargs: raw
    wire._acquire("https://as.example/gnap")
'''
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("connect", "headers", "chunks"):
                marker = Path(directory) / mode
                started = time.monotonic()
                with self.assertRaises(wire.CaptureError):
                    wire._run_worker([sys.executable, "-I", "-c", program, str(ROOT), mode, str(marker)], timeout=0.5)
                self.assertLess(time.monotonic() - started, 2, mode)
                self.assertTrue(marker.exists(), "child actually started")
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(marker.read_text()), 0)

    def test_public_collector_always_uses_the_whole_process_deadline(self):
        capture = wire.read_capture(ROOT / "conformance/fixtures/discovery.json")
        with mock.patch.dict(os.environ, {"GNAP_DISCOVERY_LIVE": "1"}, clear=True), mock.patch.object(wire, "_run_worker", return_value=capture) as worker:
            wire.acquire("https://as.example/gnap")
            self.assertEqual(worker.call_args.args[1], 5)
            self.assertEqual(worker.call_args.args[0], [sys.executable, "-I", str(Path(wire.__file__).resolve()), "--worker", "https://as.example/gnap"])


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in ("tools/conformance_ledger.py", "conformance/discovery.py", "conformance/scenarios/test_as_discovery.py", "conformance/fixtures/discovery.json"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        completed = subprocess.run([sys.executable, "-B", "tools/conformance_ledger.py", "discovery-tests"], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.receipt = json.loads((self.root / "conformance/runs/discovery.json").read_bytes())

    def test_real_fixture_receipt_binds_every_source_capture_configuration_and_mode(self):
        self.assertEqual(set(ledger.validate_run(self.root, self.receipt).values()), {"pass"})
        self.assertEqual(self.receipt["observation"]["capture_origin"], "synthetic")
        self.assertEqual(self.receipt["observation"]["execution_mode"], "capture_replay")
        for field, value in (("execution_mode", "live"), ("capture_origin", "live"), ("endpoint", "https://other.example/gnap"),
                             ("captured_at_unix_utc", 1), ("collector_config_sha256", "0" * 64)):
            mutated = copy.deepcopy(self.receipt)
            mutated["observation"][field] = value
            with self.assertRaises(ledger.LedgerError):
                ledger.validate_run(self.root, mutated)

    def test_missing_provenance_or_helper_hash_is_refused(self):
        mutated = copy.deepcopy(self.receipt)
        del mutated["observation"]
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_run(self.root, mutated)
        mutated = copy.deepcopy(self.receipt)
        del mutated["source_files"]["conformance/discovery.py"]
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_run(self.root, mutated)

    def test_missing_scenario_module_is_a_clear_ledger_error(self):
        path = self.root / "conformance/scenarios/test_as_discovery.py"
        path.rename(path.with_name("hidden_scenario.py"))
        (path.parent / "test_other.py").write_text("import unittest\nclass Other(unittest.TestCase):\n    def test_other(self): pass\n")
        result = subprocess.run([sys.executable, "-B", "tools/conformance_ledger.py", "discovery-tests"], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Discovery scenario module was not discovered", result.stderr)
        self.assertNotIn("KeyError", result.stderr)

    def test_qualified_discovery_cases_cannot_omit_capture_provenance(self):
        for prefix in ("", "scenarios.", "conformance.scenarios."):
            with self.subTest(prefix=prefix):
                mutated = copy.deepcopy(self.receipt)
                del mutated["observation"]
                mutated["discovered_cases"] = [prefix + case for case in mutated["discovered_cases"]]
                for result in mutated["results"]:
                    result["case_id"] = prefix + result["case_id"]
                with self.assertRaisesRegex(ledger.LedgerError, "Discovery scenarios require capture provenance"):
                    ledger.validate_run(self.root, mutated)

    def test_recorded_discovery_source_requires_provenance_even_with_aliased_cases(self):
        # Synthetic mutation of an actual fixture run, never published as evidence.
        alias = "conformance/scenarios/test_aliased.py"
        path = self.root / alias
        shutil.copyfile(self.root / "conformance/scenarios/test_as_discovery.py", path)
        mutated = copy.deepcopy(self.receipt)
        mutated["source_files"][alias] = ledger.digest(path.read_bytes())
        del mutated["observation"]
        mutated["discovered_cases"] = [case.replace("test_as_discovery.", "test_aliased.", 1)
                                     for case in mutated["discovered_cases"]]
        for result in mutated["results"]:
            result["case_id"] = result["case_id"].replace("test_as_discovery.", "test_aliased.", 1)
        with self.assertRaisesRegex(ledger.LedgerError, "Discovery scenarios require capture provenance"):
            ledger.validate_run(self.root, mutated)

    def test_nested_discovery_module_requires_provenance_without_canonical_source_path(self):
        nested = "conformance/scenarios/nested/test_as_discovery.py"
        path = self.root / nested
        path.parent.mkdir()
        shutil.copyfile(self.root / "conformance/scenarios/test_as_discovery.py", path)
        mutated = copy.deepcopy(self.receipt)
        mutated["source_files"][nested] = mutated["source_files"].pop("conformance/scenarios/test_as_discovery.py")
        del mutated["observation"]
        mutated["discovered_cases"] = ["nested." + case for case in mutated["discovered_cases"]]
        for result in mutated["results"]:
            result["case_id"] = "nested." + result["case_id"]
        with self.assertRaisesRegex(ledger.LedgerError, "Discovery scenarios require capture provenance"):
            ledger.validate_run(self.root, mutated)

    def test_changed_source_and_changed_capture_invalidate_receipt(self):
        for relative in ("conformance/discovery.py", "conformance/fixtures/discovery.json"):
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(ledger.LedgerError):
                ledger.validate_run(self.root, self.receipt)
            path.write_bytes(original)

    def test_synthetic_fixture_is_refused_as_as_evidence(self):
        identifier = "rfc9635:section-9-2"
        states = {identifier: {"applicability": "applicable", "review": "reviewed", "evidence": "not_run"}}
        mapping = {"schema_version": 1, "claims": [{"clause_id": identifier, "run": "conformance/runs/discovery.json",
                   "case_id": self.receipt["discovered_cases"][0], "assertion": "Synthetic test, not an actual AS claim"}]}
        (self.root / "conformance/evidence.json").write_text(json.dumps(mapping))
        with self.assertRaisesRegex(ledger.LedgerError, "Synthetic oracle"):
            ledger.apply_evidence(self.root, states)

    def test_published_receipt_requires_known_clean_commit(self):
        with self.assertRaisesRegex(ledger.LedgerError, "clean source commit"):
            ledger.validate_run(self.root, self.receipt, published=True)

    def test_published_source_commit_is_checked_not_just_dirty_boolean(self):
        receipt = copy.deepcopy(self.receipt)
        receipt.update(source_revision="a" * 40, working_tree_dirty=False)
        # Simulated Git objects in an isolated regression; not a real published receipt.
        def committed(args, **_):
            relative = args[-1].split(":", 1)[1]
            return (self.root / relative).read_bytes()
        with mock.patch.object(ledger.subprocess, "check_output", side_effect=committed):
            ledger.validate_run(self.root, receipt, published=True)
        with mock.patch.object(ledger.subprocess, "check_output", return_value=b"different source"):
            with self.assertRaisesRegex(ledger.LedgerError, "declared commit"):
                ledger.validate_run(self.root, receipt, published=True)
        def changed_capture(args, **kwargs):
            return b"different capture" if args[-1].endswith(":conformance/fixtures/discovery.json") else committed(args, **kwargs)
        with mock.patch.object(ledger.subprocess, "check_output", side_effect=changed_capture):
            with self.assertRaisesRegex(ledger.LedgerError, "declared commit"):
                ledger.validate_run(self.root, receipt, published=True)

    def test_historical_capture_replay_remains_dated_not_live_execution(self):
        # A synthetic test of the provenance schema, never published as live evidence.
        capture = wire.read_capture(self.root / "conformance/fixtures/discovery.json")
        capture.update(capture_origin="live", captured_at_unix_utc=1)
        path = self.root / "conformance/captures/schema-test.json"
        path.parent.mkdir()
        path.write_bytes(wire.encoded(capture))
        receipt = copy.deepcopy(self.receipt)
        receipt["observation"].update(capture_path="conformance/captures/schema-test.json", capture_sha256=wire.sha(path.read_bytes()), capture_origin="live", captured_at_unix_utc=1)
        receipt["source_files"]["conformance/captures/schema-test.json"] = wire.sha(path.read_bytes())
        ledger.validate_run(self.root, receipt)
        receipt["observation"]["execution_mode"] = "live"
        with self.assertRaisesRegex(ledger.LedgerError, "not acquired during"):
            ledger.validate_run(self.root, receipt)

    def test_fixture_moved_and_relabelled_origin_alone_still_fails_hash_binding(self):
        path = self.root / "conformance/captures/mutated.json"
        path.parent.mkdir()
        altered = wire.read_capture(self.root / "conformance/fixtures/discovery.json")
        altered["capture_origin"] = "live"
        altered["captured_at_unix_utc"] = 1
        path.write_bytes(wire.encoded(altered))
        receipt = copy.deepcopy(self.receipt)
        receipt["observation"].update(capture_path="conformance/captures/mutated.json", capture_origin="live", captured_at_unix_utc=1)
        with self.assertRaises(ledger.LedgerError):
            ledger.validate_run(self.root, receipt)

    def test_untrusted_capture_does_not_execute_fields(self):
        marker = self.root / "executed"
        capture = wire.read_capture(self.root / "conformance/fixtures/discovery.json")
        capture["python"] = f"open({str(marker)!r}, 'w').close()"
        path = self.root / "conformance/fixtures/untrusted.json"
        path.write_text(json.dumps(capture))
        with self.assertRaises(wire.CaptureError):
            wire.read_capture(path)
        self.assertFalse(marker.exists())
