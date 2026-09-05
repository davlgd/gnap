"""Six wire assertions; no SDK parser, workbench verdict or fixture-as-AS claim."""
from pathlib import Path
import unittest

from conformance.discovery import CaptureError, absolute_host_without_fragment, document, endpoint, read_capture

CAPTURE = None  # Set only by the trusted local runner, never by uploaded code.


class DiscoveryResponse(unittest.TestCase):
    def capture(self):
        if CAPTURE is None:
            return read_capture(Path(__file__).resolve().parents[1] / "fixtures/discovery.json")
        return CAPTURE

    def doc(self):
        try:
            return document(self.capture())
        except CaptureError:
            self.skipTest("Ambiguous JSON members: no normative last-wins assertion")

    def endpoint(self):
        self.doc()
        return endpoint(self.capture())

    def test_options_response_media_type(self):
        headers = self.capture()["headers"]
        self.assertTrue(headers, "Required JSON Content-Type metadata is absent")
        if len(headers) > 1:
            self.skipTest("Repeated Content-Type metadata is ambiguous; no GNAP cardinality MUST asserted")
        self.assertTrue(headers[0][1].split(";", 1)[0].strip().lower() == "application/json", "Expected JSON media type")

    def test_response_is_json_object(self):
        self.doc()

    def test_endpoint_required_string(self):
        self.endpoint()

    def test_endpoint_absolute_host_without_fragment(self):
        self.assertTrue(absolute_host_without_fragment(self.endpoint()), "Endpoint URI grammar/components invalid")

    def test_endpoint_https(self):
        self.assertTrue(self.endpoint().split(":", 1)[0].lower() == "https", "Expected HTTPS scheme")

    def test_endpoint_matches_exact_request(self):
        self.assertTrue(self.endpoint() == self.capture()["endpoint"], "Endpoint differs from exact queried URL")
