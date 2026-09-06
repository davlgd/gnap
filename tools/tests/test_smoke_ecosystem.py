"""Offline HTTP-helper regressions, not GNAP conformance observations."""

from email.message import Message
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock

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
