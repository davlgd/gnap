"""Offline safety and control-flow tests for the Biscuit acceptance driver."""

import argparse
import contextlib
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", [str(TOOLS), *sys.path]):
    SPEC = importlib.util.spec_from_file_location("smoke_biscuit", TOOLS / "smoke_biscuit.py")
    smoke = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(smoke)

AS, RS, CLIENT = "https://as.example", "https://rs.example", "https://client.example"


def headers(cookie=False):
    result = Message()
    result["Content-Type"] = "application/json"
    result["Cache-Control"] = "no-store"
    if cookie:
        result["Set-Cookie"] = "biscuit_session=abcdefghijklmnopqrstuv; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1200"
    return result


class ApplicationDouble:
    def __init__(self):
        self.sessions = {}
        self.calls = []
        self.online = True

    def exchange(self, browser, base, path, method="GET", data=None, browser_origin=None):
        self.calls.append((base, path, method))
        if path == "/health":
            return 200, headers(), None
        if base != CLIENT:
            return 401, headers(), {"error": "request refused"}
        if browser_origin != CLIENT:
            return 403, headers(), None
        action = path.rsplit("/", 1)[-1]
        body = {"event": "PRIVATE-EVENT-NOT-FOR-REPORT"}
        if action == "start":
            self.sessions[browser] = {"attenuated": False, "key_rotations": 0, "revoked": False, "old": False}
            return 200, headers(True), body
        if browser not in self.sessions:
            return 401, headers(), None
        state = self.sessions[browser]
        if action == "status":
            body.update(attenuated=state["attenuated"], retired_available=False, key_rotations=state["key_rotations"])
        elif action == "attenuate":
            state["attenuated"] = True
            body.update(data)
        elif action in ("rotate", "rotate-key"):
            state["attenuated"] = False
            state["key_rotations"] += action == "rotate-key"
            body["key_rotations"] = state["key_rotations"]
        elif action == "revoke":
            state["revoked"] = True
        else:
            refused = (action in ("read-draft", "write-notes", "check-retired", "check-old-key")
                       or state["old"] or state["revoked"] or (action == "write" and state["attenuated"]))
            status = 503 if not self.online else 403 if refused else 200
            result = {"error": "request refused"} if status != 200 else (
                {"written_bytes": 42} if action == "write" else
                {"content": "Synthetic notes: local attenuation preserves the client's key.\n"})
            body.update(status=status, result=result)
        return 200, headers(), body


class BiscuitSmokeTests(unittest.TestCase):
    def scenario(self):
        return smoke.Scenario(AS, RS, CLIENT)

    def test_default_scenario_has_positive_controls_unique_checks_and_no_live_sessions(self):
        app, scenario = ApplicationDouble(), self.scenario()
        with patch.object(smoke, "exchange", side_effect=app.exchange):
            scenario.run()
        self.assertTrue(all(check["status"] == "pass" for check in scenario.checks))
        names = [check["check"] for check in scenario.checks]
        self.assertEqual(len(names), len(set(names)))
        for name in ("attenuated-write-refused", "key-rotation-2-check-old-key",
                     "revocation-retires-descendant", "independent-session-remains-available"):
            self.assertIn(name, names)
        self.assertFalse(scenario.sessions)
        self.assertTrue(all(state["revoked"] for state in app.sessions.values()))
        self.assertNotIn("PRIVATE", json.dumps(scenario.checks))

    def test_a_deny_all_service_fails_the_first_positive_control(self):
        app, scenario = ApplicationDouble(), self.scenario()

        def deny(*args):
            status, metadata, body = app.exchange(*args)
            if args[2] == "/action/read" and status == 200:
                body.update(status=403, result={"error": "request refused"})
            return status, metadata, body

        with patch.object(smoke, "exchange", side_effect=deny):
            with self.assertRaisesRegex(smoke.Failure, "^initial-read-notes$"):
                scenario.run()
            self.assertEqual(scenario.cleanup(), ["revocation-acknowledged"])

    def test_malformed_action_response_is_not_echoed(self):
        for body in (None, [], {"event": "private", "access_token": "private"}):
            with self.subTest(body=body), patch.object(smoke, "exchange", return_value=(200, headers(), body)):
                with self.assertRaises(smoke.Failure) as error:
                    self.scenario().start()
                self.assertNotIn("private", str(error.exception))

    def test_maintenance_preserves_sessions_across_operator_actions(self):
        app, scenario = ApplicationDouble(), self.scenario()
        steps = []

        def maintenance(instruction):
            steps.append(instruction)
            if instruction.startswith("Stop"):
                app.online = False
            elif instruction.startswith("Restart the AS"):
                app.online = True
                for state in app.sessions.values():
                    state["old"] = True

        with patch.object(smoke, "exchange", side_effect=app.exchange), patch.object(smoke, "pause", side_effect=maintenance):
            scenario.run(maintenance=True)
        self.assertEqual(len(steps), 3)
        names = [check["check"] for check in scenario.checks]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("as-outage-refuses-resource", names)
        self.assertIn("as-restart-retires-old-authority", names)
        self.assertIn("new-grant-after-as-restart", names)
        self.assertFalse(scenario.sessions)

    def test_expired_observation_windows_are_inconclusive(self):
        # Fix the origin as well as observations: (started + 900) - started
        # can round below 900 when started comes from the runner's real clock.
        with patch.object(smoke.time, "monotonic", return_value=100.0):
            scenario = self.scenario()
        for extra in (0.0, 0.25):
            with self.subTest(extra=extra):
                with patch.object(smoke.time, "monotonic", return_value=200.0 + extra):
                    with self.assertRaises(smoke.Inconclusive):
                        smoke.Scenario.unexpired_descendant(100.0)
                with patch.object(smoke.time, "monotonic", side_effect=[100.0, 1000.0 + extra]), \
                        patch.object(smoke, "exchange", return_value=(200, {}, {})) as delayed:
                    with self.assertRaises(smoke.Inconclusive):
                        scenario.call(object(), AS, "/health")
                    delayed.assert_called_once()
                with patch.object(smoke.time, "monotonic", return_value=1000.0 + extra), \
                        patch.object(smoke, "exchange") as network:
                    with self.assertRaises(smoke.Inconclusive):
                        scenario.call(object(), AS, "/health")
                    network.assert_not_called()

    def test_observations_just_before_expiry_are_allowed(self):
        with patch.object(smoke.time, "monotonic", return_value=100.0):
            scenario = self.scenario()
        with patch.object(smoke.time, "monotonic", return_value=199.75):
            smoke.Scenario.unexpired_descendant(100.0)
        response = (200, {}, {})
        with patch.object(smoke.time, "monotonic", return_value=999.75), \
                patch.object(smoke, "exchange", return_value=response) as network:
            self.assertEqual(scenario.call(object(), AS, "/health"), response)
            network.assert_called_once()

    def test_missing_or_ambiguous_cookie_is_refused(self):
        self.assertTrue(smoke.session_cookie(headers(True), True))
        self.assertFalse(smoke.session_cookie(headers(), True))
        repeated = headers(True)
        repeated["Set-Cookie"] = repeated["Set-Cookie"]
        self.assertFalse(smoke.session_cookie(repeated, True))
        insecure = Message()
        insecure["Set-Cookie"] = headers(True)["Set-Cookie"].replace("; Secure", "")
        self.assertFalse(smoke.session_cookie(insecure, True))
        self.assertTrue(smoke.session_cookie(insecure, False))

    def test_json_ambiguity_is_rejected_recursively(self):
        for raw in ('{"event":"a","event":"b"}', '{"result":{"status":200,"status":403}}'):
            with self.assertRaises(ValueError):
                json.loads(raw, object_pairs_hook=smoke.unique_object)

    def test_origins_are_explicit_canonical_and_loopback_only_for_http(self):
        for value in (AS, "http://[::1]:18085", "http://127.0.0.1:18085"):
            self.assertEqual(smoke.canonical_origin(value), value)
        for value in ("http://remote.example", "https://user@as.example", "https://as.example:443",
                      "https://AS.example", "https://as.example/path", "https://as.example:bad"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                smoke.canonical_origin(value)

    def test_cli_requires_consent_before_network(self):
        args = ["smoke_biscuit.py", "--as", AS, "--rs", RS, "--client", CLIENT]
        with patch.object(sys, "argv", args), patch.object(smoke, "exchange") as network, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            smoke.main()
        network.assert_not_called()

    def test_network_exception_is_redacted_and_inconclusive(self):
        args = ["smoke_biscuit.py", "--as", AS, "--rs", RS, "--client", CLIENT, "--consent"]
        output = io.StringIO()
        with patch.object(sys, "argv", args), patch.object(smoke, "exchange", side_effect=OSError("SECRET")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(smoke.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(report["failed_check"], "bounded-http-exchange")
        self.assertNotIn("SECRET", output.getvalue())


if __name__ == "__main__":
    unittest.main()
