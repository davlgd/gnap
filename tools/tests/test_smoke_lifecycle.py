"""Offline acceptance-driver safety tests, not protocol observations."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", [str(TOOLS), *sys.path]):
    SPEC = importlib.util.spec_from_file_location("smoke_lifecycle", TOOLS / "smoke_lifecycle.py")
    smoke = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(smoke)


class LifecycleSmokeTests(unittest.TestCase):
    def test_registration_returns_only_public_configuration(self):
        public = {"kty": "RSA", "alg": "PS256", "kid": "test", "n": "public", "e": "AQAB"}
        body = {"jwk": public, "callback": "https://workbench.example/lifecycle/callback"}
        with patch.object(smoke, "request", return_value=(200, None, body, 0)):
            self.assertEqual(smoke.registration("https://workbench.example"), [body])

    def test_private_members_are_refused_even_when_null(self):
        for member in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
            body = {"jwk": {"kty": "RSA", "alg": "PS256", member: None},
                    "callback": "https://workbench.example/lifecycle/callback"}
            with self.subTest(member=member), \
                    patch.object(smoke, "request", return_value=(200, None, body, 0)):
                with self.assertRaisesRegex(AssertionError, "^Public key contains private material$"):
                    smoke.registration("https://workbench.example")

    def test_callback_destination_and_path_must_match_exactly(self):
        base = "https://workbench.example"
        path = "/lifecycle/callback"
        self.assertEqual(smoke.local_path(base + path + "?hash=synthetic", base, path, exact=True),
                         path + "?hash=synthetic")
        for url in (None, base + path + "/extra", base + path + "#fragment",
                    "https://elsewhere.example" + path, "http://workbench.example" + path,
                    "https://user@workbench.example" + path):
            with self.subTest(url=url), self.assertRaises(AssertionError):
                smoke.local_path(url, base, path, exact=True)

    def test_incomplete_diagnostics_only_expose_fixed_identifiers_and_statuses(self):
        checks = [
            {"id": "lifecycle-completion", "status": "not_tested", "detail": "private-value"},
            {"id": "private-value", "status": "fail"},
            {"id": "lifecycle-completion", "status": "private-value"},
            {"id": [], "status": "fail"}, {"id": "lifecycle-completion", "status": []},
            "private-value", None,
        ]
        self.assertEqual(smoke.observed_checks({"report": {"checks": checks}}),
                         ["lifecycle-completion:not_tested"])

    def test_malformed_incomplete_reports_remain_redacted(self):
        for report in (None, "private-value", [], {"checks": None}, {"checks": "private-value"}):
            with self.subTest(report=report):
                self.assertEqual(smoke.observed_checks({"report": report}), [])

    def test_transport_exception_does_not_leak_through_cli(self):
        output = io.StringIO()
        args = ["smoke_lifecycle.py", "--workbench", "https://workbench.example",
                "--demo", "https://as.example"]
        with patch.object(sys, "argv", args), \
                patch.object(smoke, "scenario", side_effect=OSError("private-callback-value")), \
                contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            smoke.main()
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "fail")
        self.assertNotIn("private-callback-value", output.getvalue())

    def test_form_parser_preserves_duplicate_tickets_for_rejection(self):
        parser = smoke.ConsentForm()
        parser.feed('<input name="ticket" value="one"><input name="ticket" value="two">')
        self.assertEqual(parser.tickets, ["one", "two"])


if __name__ == "__main__":
    unittest.main()
