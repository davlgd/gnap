"""Offline HTTP-helper regressions, not GNAP conformance observations."""

from email.message import Message
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "smoke_ecosystem", Path(__file__).resolve().parents[1] / "smoke_ecosystem.py"
)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class Response(io.BytesIO):
    status = 200

    def __init__(self, body):
        super().__init__(body)
        self.headers = Message()


class PushSmokeTests(unittest.TestCase):
    def run_scenario(self, *, receipt=True, exposed=False):
        choice = None

        def response(_browser, _base, path, *_args):
            nonlocal choice
            action = path.rsplit("/", 1)[-1]
            if action == "start-push":
                body = {"state": "pending"}
            elif action in ("approve", "deny"):
                choice = action
                body = {"state": "awaiting_push"}
                if exposed:
                    body["redirect"] = "private-callback"
            elif action == "status":
                body = {"state": "ready", "push_finish": {
                    "received": receipt, "expired": False, "delivery": "delivered"}}
            elif action == "continue":
                body = {"state": "approved" if choice == "approve" else "denied",
                        "token_present": choice == "approve", "continuation_open": False}
            elif action in ("read", "check-retired"):
                body = {"last_resource_status": 200 if action == "read" else 401}
            elif action == "revoke":
                body = {"token_present": False}
            else:
                self.fail("Unexpected smoke action")
            return 200, Message(), body, 0

        outcomes = []
        with patch.object(smoke, "request", side_effect=response), \
                patch.object(smoke, "wait_for_continuation"), \
                patch.object(smoke.time, "monotonic", side_effect=range(0, 1000, 20)):
            smoke.push_demo("https://demo.example", outcomes)
        return outcomes

    def test_both_decisions_and_token_lifecycle_are_checked(self):
        self.assertEqual(self.run_scenario(), [
            {"check": "push-approve", "status": "pass"},
            {"check": "push-deny", "status": "pass"},
        ])

    def test_sender_acknowledgement_does_not_substitute_for_client_receipt(self):
        with self.assertRaisesRegex(AssertionError, "not received and acknowledged"):
            self.run_scenario(receipt=False)

    def test_callback_leaks_fail_with_a_fixed_redacted_error(self):
        with self.assertRaisesRegex(AssertionError, "^Push action exposed a callback destination$"):
            self.run_scenario(exposed=True)


class SmokeHttpTests(unittest.TestCase):
    def test_html_request_negotiates_html_and_decodes_text(self):
        opener = Mock()
        opener.open.return_value = Response(b"<body>synthetic</body>")
        status, _, body, _ = smoke.request(opener, "https://example.test", "/code", html=True)
        self.assertEqual(opener.open.call_args.args[0].get_header("Accept"), "text/html")
        self.assertEqual((status, body), (200, "<body>synthetic</body>"))

    def test_default_request_still_negotiates_and_decodes_json(self):
        opener = Mock()
        opener.open.return_value = Response(b'{"status":"ok"}')
        status, _, body, _ = smoke.request(opener, "https://example.test", "/health")
        self.assertEqual(opener.open.call_args.args[0].get_header("Accept"), "application/json")
        self.assertEqual((status, body), (200, {"status": "ok"}))

    def test_owner_cookie_is_found_in_either_header_without_splitting_expires(self):
        owner = "gnap_owner=synthetic; Path=/code; HttpOnly; Secure; SameSite=Strict"
        other = "other=synthetic; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Path=/"
        for values in ((owner, other), (other, owner)):
            with self.subTest(owner_first=values[0] == owner):
                headers = Message()
                for value in values:
                    headers.add_header("Set-Cookie", value)
                cookie = smoke.owner_cookie(headers)
                self.assertIsNotNone(cookie)
                self.assertEqual(cookie.value, "synthetic")
                self.assertEqual(cookie["path"], "/code")
                self.assertEqual(cookie["samesite"], "Strict")
                self.assertTrue(cookie["httponly"] and cookie["secure"])

    def test_missing_owner_cookie_is_refused(self):
        with self.assertRaisesRegex(AssertionError, "exactly one owner cookie"):
            smoke.owner_cookie(Message())

    def test_two_owner_set_cookie_headers_are_ambiguous(self):
        headers = Message()
        headers.add_header("Set-Cookie", "gnap_owner=first; Path=/code; Secure")
        headers.add_header("Set-Cookie", "gnap_owner=second; Path=/code")
        with self.assertRaisesRegex(AssertionError, "exactly one owner cookie"):
            smoke.owner_cookie(headers)


if __name__ == "__main__":
    unittest.main()
