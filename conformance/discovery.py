"""Independent, bounded RFC 9635 section 9 capture and assertion helpers.

Capture documents are data, never modules, expressions, or commands to execute.
The collector is operator-only; it is not a public URL testing service.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

LIMIT = 32768
CONFIG = {"method": "OPTIONS", "credentials": False, "proxy": False,
          "redirects": False, "max_body_bytes": LIMIT, "timeout_seconds": 5,
          "address_policy": "public-ipv4-pinned-v1"}


class CaptureError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise CaptureError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Ambiguous JSON members; interpretation not tested")
        result[key] = value
    return result


def no_constant(_):
    raise ValueError("Non-JSON numeric constant")


def validate_capture(value):
    need(isinstance(value, dict) and set(value) == {
        "schema_version", "capture_origin", "endpoint", "captured_at_unix_utc",
        "remote_revision", "http_status", "headers", "body_base64", "body_sha256",
        "collector_config", "collector_config_sha256"}, "Invalid capture envelope")
    need(type(value["schema_version"]) is int and value["schema_version"] == 1, "Unknown capture schema")
    need(value["capture_origin"] in ("live", "synthetic"), "Unknown capture origin")
    need(value["remote_revision"] == "unknown", "Remote code is not attested")
    stamp = value["captured_at_unix_utc"]
    need((value["capture_origin"] == "synthetic" and stamp is None)
         or (value["capture_origin"] == "live" and type(stamp) is int and stamp > 0),
         "Capture date contradicts origin")
    need(isinstance(value["endpoint"], str) and 0 < len(value["endpoint"]) <= 2048,
         "Invalid captured request endpoint")
    need(type(value["http_status"]) is int and 100 <= value["http_status"] <= 599,
         "Invalid captured HTTP status")
    headers = value["headers"]
    need(isinstance(headers, list) and len(headers) <= 8, "Invalid captured headers")
    for header in headers:
        need(isinstance(header, list) and len(header) == 2
             and header[0] == "content-type" and isinstance(header[1], str)
             and len(header[1]) <= 256 and not any(c in header[1] for c in "\r\n"),
             "Only bounded Content-Type headers may be retained")
    need(isinstance(value["body_base64"], str) and len(value["body_base64"]) <= 4 * ((LIMIT + 2) // 3),
         "Captured body exceeds bound")
    try:
        body = base64.b64decode(value["body_base64"], validate=True)
    except ValueError as error:
        raise CaptureError("Invalid body encoding") from error
    need(len(body) <= LIMIT and sha(body) == value["body_sha256"], "Captured body hash mismatch")
    need(value["collector_config"] == CONFIG
         and value["collector_config_sha256"] == sha(encoded(CONFIG)), "Capture configuration mismatch")
    return body


def read_capture(path: Path):
    with path.open("rb") as stream:
        raw = stream.read(100_001)
    need(len(raw) <= 100_000, "Capture envelope too large")
    try:
        value = json.loads(raw, object_pairs_hook=pairs_unique, parse_constant=no_constant)
        validate_capture(value)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise CaptureError("Invalid capture data; values are not reflected") from error
    return value


def make_capture(endpoint, status, headers, body, *, origin, timestamp):
    result = {"schema_version": 1, "capture_origin": origin, "endpoint": endpoint,
              "captured_at_unix_utc": timestamp, "remote_revision": "unknown",
              "http_status": status, "headers": headers,
              "body_base64": base64.b64encode(body).decode("ascii"), "body_sha256": sha(body),
              "collector_config": CONFIG.copy(), "collector_config_sha256": sha(encoded(CONFIG))}
    validate_capture(result)
    return result


def public_ipv4(address):
    value = ipaddress.ip_address(address)
    return value.version == 4 and value.is_global and not any(value in ipaddress.ip_network(net)
        for net in ("192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15", "224.0.0.0/4"))


def configured_endpoint(endpoint):
    need(isinstance(endpoint, str) and len(endpoint) <= 2048 and endpoint.isascii(), "Invalid operator endpoint")
    parts = urlsplit(endpoint)
    need(parts.scheme == "https" and parts.netloc == parts.hostname
         and parts.hostname is not None and re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", parts.hostname)
         and "." in parts.hostname and not parts.fragment and not parts.query
         and parts.path.startswith("/") and not re.search(r"[\x00-\x20\x7f]", endpoint),
         "Collector requires canonical HTTPS DNS host, default port, path, no credentials/query/fragment")
    try:
        ipaddress.ip_address(parts.hostname)
    except ValueError:
        return parts
    raise CaptureError("IP literal targets are not allowed")


def live_enabled():
    need(os.environ.get("GNAP_DISCOVERY_LIVE") == "1", "Live collection requires GNAP_DISCOVERY_LIVE=1")
    need(not any(os.environ.get(key) for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD")),
         "Live collection is forbidden in CI")


def _run_worker(command, timeout):
    # One process owns DNS, TLS and the complete HTTP parser. A slow stream of
    # header bytes or chunk metadata cannot renew this wall-clock deadline.
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=True)
        need(len(result.stdout) <= 100_000, "Collector output exceeds bound")
        capture = json.loads(result.stdout, object_pairs_hook=pairs_unique, parse_constant=no_constant)
        validate_capture(capture)
        return capture
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # subprocess.run kills and reaps the child before raising on timeout.
        raise CaptureError("Capture inconclusive: collector failed or exceeded wall-clock deadline; no response reflected") from error


def acquire(endpoint):
    live_enabled()
    configured_endpoint(endpoint)
    return _run_worker([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", endpoint], CONFIG["timeout_seconds"])


def _acquire(endpoint):
    """Worker implementation; production always calls it in the bounded child."""
    parts = configured_endpoint(endpoint)
    deadline = time.monotonic() + CONFIG["timeout_seconds"]
    try:
        addresses = sorted({answer[4][0] for answer in socket.getaddrinfo(parts.hostname, 443, socket.AF_INET, socket.SOCK_STREAM)})
        need(isinstance(addresses, list) and 0 < len(addresses) <= 16
             and all(public_ipv4(address) for address in addresses), "Address policy refused target")
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(parts.hostname, timeout=2, context=context)
        raw = socket.create_connection((addresses[0], 443), timeout=min(2, deadline - time.monotonic()))
        try:
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            tls = context.wrap_socket(raw, server_hostname=parts.hostname)
            connection.sock = tls
            connection.request("OPTIONS", parts.path, headers={"Accept": "application/json"})
            response = connection.getresponse()
            need(not 300 <= response.status <= 399, "Redirect not followed; no capture emitted")
            chunks = []
            length = 0
            while True:
                remaining = deadline - time.monotonic()
                need(remaining > 0, "Capture deadline exceeded")
                tls.settimeout(remaining)
                chunk = response.read1(min(4096, LIMIT + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
                need(length <= LIMIT, "Capture body exceeds bound")
            # No cookies, authentication values, Location or server banners retained.
            headers = [["content-type", v] for n, v in response.getheaders() if n.lower() == "content-type"]
            return make_capture(endpoint, response.status, headers, b"".join(chunks),
                                origin="live", timestamp=int(time.time()))
        finally:
            connection.close()
            raw.close()
    except (OSError, ValueError, subprocess.SubprocessError, http.client.HTTPException) as error:
        raise CaptureError("Capture inconclusive: DNS/address policy/TLS/HTTP/deadline/size failure; no response reflected") from error


def document(capture):
    body = validate_capture(capture)
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs_unique, parse_constant=no_constant)
    except CaptureError:
        raise  # Duplicate member ambiguity is not turned into a GNAP MUST.
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AssertionError("Response is not JSON") from error
    if not isinstance(value, dict):
        raise AssertionError("Response is not a single JSON object")
    return value


def endpoint(capture):
    value = document(capture).get("grant_request_endpoint")
    if not isinstance(value, str):
        raise AssertionError("Required endpoint must be a JSON string")
    return value


def absolute_host_without_fragment(value):
    # Independent RFC3986 grammar prechecks, not urllib's permissive repair.
    if not value.isascii() or re.search(r"[\x00-\x20\x7f]", value) or "#" in value:
        return False
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        return False
    match = re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#]+)([^#]*)", value)
    if not match:
        return False
    authority, tail = match.groups()
    if not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@/?%\-]*", tail):
        return False
    hostport = authority.rsplit("@", 1)[-1]
    if "@" in authority:
        userinfo = authority.rsplit("@", 1)[0]
        if not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:%\-]*", userinfo):
            return False
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0 or not re.fullmatch(r"(?::[0-9]*)?", hostport[end + 1:]):
            return False
        literal = hostport[1:end]
        if re.fullmatch(r"v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:\-]+", literal, re.IGNORECASE):
            return True
        try:
            return "%" not in literal and ipaddress.ip_address(literal).version == 6
        except ValueError:
            return False
    if ":" in hostport:
        hostport, port = hostport.rsplit(":", 1)
        if not re.fullmatch(r"[0-9]*", port):
            return False
    return bool(hostport and re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=%\-]+", hostport))


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 3 and sys.argv[1] == "--worker", "Internal collector invocation required")
        live_enabled()
        result = encoded(_acquire(sys.argv[2]))
        need(len(result) <= 100_000, "Collector output exceeds bound")
        sys.stdout.buffer.write(result)
    except (ValueError, OSError):
        print("Collector failed; no response content is returned", file=sys.stderr)
        raise SystemExit(1)
