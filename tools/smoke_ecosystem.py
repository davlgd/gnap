#!/usr/bin/env python3
"""Exercise only explicitly supplied GNAP demo/workbench deployments.

Creates disposable synthetic grants in the demo. Never prints cookies, tokens,
callback secrets, message bodies or imported values. This is an application
acceptance smoke test, not a general GNAP conformance checker.
"""

import argparse
import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise argparse.ArgumentTypeError("Supply an HTTP(S) origin, without path or credentials")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise argparse.ArgumentTypeError("Non-loopback targets require HTTPS")
    return value.rstrip("/")


def client():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        NoRedirect(),
    )


def request(opener, base, path, method="GET", data=None, browser_origin=None):
    headers = {"Accept": "application/json"}
    if browser_origin is not None:
        headers["Origin"] = browser_origin
    payload = None if data is None else json.dumps(data).encode()
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    started = time.monotonic()
    try:
        response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(131_073)
        if len(raw) > 131_072:
            raise AssertionError("Response exceeds smoke-test bound")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            body = None
        return response.status, response.headers, body, round((time.monotonic() - started) * 1000)


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def ready(base):
    # RSA generation happens once at demo startup. Keep waiting bounded, and
    # never enable certificate bypasses for a deployment health check.
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            if request(client(), base, "/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise AssertionError("Application did not become healthy within startup deadline")


def demo(base, outcomes):
    browser = client()
    status, _, _, _ = request(browser, base, "/health")
    expect(status == 200, "Demo health failed")
    # Independent wire assertions: do not reuse the SDK discovery validator.
    status, headers, body, elapsed = request(browser, base, "/gnap", "OPTIONS")
    expect(status == 200 and isinstance(body, dict), "AS discovery is not a JSON object response")
    expect(headers.get_content_type() == "application/json", "AS discovery has the wrong media type")
    expect(body.get("grant_request_endpoint") == base + "/gnap", "Discovery changed the exact grant endpoint")
    expect(body.get("key_proofs_supported") == ["httpsig"], "Demo advertised unexpected proof capabilities")
    expect(body.get("key_rotation_supported") is False, "Demo advertised unsupported key rotation")
    expect(headers.get("cache-control") == "no-store", "Discovery response is cacheable")
    expect(headers.get("set-cookie") is None, "Discovery created browser state")
    expect(headers.get("location") is None, "Discovery redirected the request")
    expected_deviation = "insecure-loopback-discovery" if base.startswith("http://") else None
    expect(headers.get("gnap-development-only") == expected_deviation, "Discovery development mode is mislabelled")
    outcomes.append({"check": "as-options-discovery", "status": "pass", "elapsed_ms": elapsed})
    status, _, _, _ = request(browser, base, "/resource/folder")
    expect(status in (401, 403), "Resource did not reject an unauthenticated request")
    outcomes.append({"check": "resource-requires-authorization", "status": "pass"})
    status, _, _, _ = request(browser, base, "/api/start", "POST", {}, "https://untrusted.invalid")
    expect(status == 403, "Cross-origin action was not refused")
    outcomes.append({"check": "cross-origin-action-rejected", "status": "pass"})

    def action(name):
        status, _, body, elapsed = request(browser, base, "/api/" + name, "POST", {}, base)
        expect(status == 200 and isinstance(body, dict), "Demo action failed: " + name)
        outcomes.append({"check": "demo-" + name, "status": "pass", "elapsed_ms": elapsed})
        return body

    action("start")
    status, _, body, _ = request(client(), base, "/api/status")
    expect(status == 200 and body.get("state") == "new", "Anonymous browser inherited another session")
    outcomes.append({"check": "browser-session-isolation", "status": "pass"})
    body = action("approve")
    callback = urllib.parse.urlsplit(body.get("redirect", ""))
    expected = urllib.parse.urlsplit(base)
    expect(
        (callback.scheme, callback.netloc, callback.path) == (expected.scheme, expected.netloc, "/callback")
        and not callback.fragment,
        "Callback origin/path is not the explicitly configured demo",
    )
    callback_path = callback.path + "?" + callback.query
    status, _, _, _ = request(browser, base, callback_path)
    expect(status == 303, "Bound callback was rejected")
    outcomes.append({"check": "bound-callback", "status": "pass"})
    status, _, _, _ = request(client(), base, callback_path)
    expect(status == 401, "Callback accepted without its browser session")
    status, _, _, _ = request(browser, base, callback_path)
    expect(status == 400, "Callback was accepted twice")
    outcomes.append({"check": "callback-isolation-and-replay", "status": "pass"})
    wait_for_continuation(browser, base)
    body = action("continue")
    expect(body.get("state") == "approved" and body.get("token_present"), "No approved token after continuation")
    body = action("read")
    expect(bool(body.get("folder")), "Signed resource read returned no synthetic dossier")
    action("rotate")
    action("check-retired")
    action("read")
    body = action("revoke")
    expect(body.get("state") == "revoked" and not body.get("token_present"), "Revoked token remains usable in client")
    action("check-retired")

    # A separate disposable session exercises an explicit refusal, not a local
    # too-early error mislabelled as a server decision.
    denied = client()
    status, _, _, _ = request(denied, base, "/api/start", "POST", {}, base)
    expect(status == 200, "Could not create denial test session")
    status, _, body, _ = request(denied, base, "/api/deny", "POST", {}, base)
    expect(status == 200, "Explicit denial action failed")
    denied_callback = urllib.parse.urlsplit(body.get("redirect", ""))
    expect(
        (denied_callback.scheme, denied_callback.netloc, denied_callback.path)
        == (expected.scheme, expected.netloc, "/callback"),
        "Denial callback does not target the demo",
    )
    status, _, _, _ = request(denied, base, denied_callback.path + "?" + denied_callback.query)
    expect(status == 303, "Denial callback failed")
    wait_for_continuation(denied, base)
    status, _, body, _ = request(denied, base, "/api/continue", "POST", {}, base)
    expect(status == 200 and body.get("state") == "denied" and not body.get("token_present"), "AS denial was not preserved")
    outcomes.append({"check": "explicit-denial", "status": "pass"})


def wait_for_continuation(browser, base):
    status, _, body, _ = request(browser, base, "/api/status")
    expect(status == 200, "Could not read continuation wait")
    wait = body.get("continuation_wait_seconds")
    expect(isinstance(wait, int) and not isinstance(wait, bool) and 0 <= wait <= 30, "Invalid continuation wait hint")
    if wait:
        time.sleep(wait + 0.1)


def demo_alias(base, alias, outcomes):
    """Check an explicitly supplied alias without following its redirects."""
    browser = client()
    status, _, _, _ = request(browser, alias, "/health")
    expect(status == 200, "Demo alias health failed")
    for method in ("GET", "HEAD"):
        for path in ("/", "/interact/synthetic", "/callback?hash=a%2Bb%2F%3D&interact_ref=x%26y"):
            status, headers, _, _ = request(browser, alias, path, method)
            expect(status == 307, "Alias navigation did not redirect temporarily")
            expect(headers.get("location") == base + path, "Alias redirect changed the fixed origin or raw query")
            expect(headers.get("cache-control") == "no-store", "Alias redirect is cacheable")
            expect(headers.get("referrer-policy") == "no-referrer", "Alias redirect may leak callback data")
            expect(headers.get("set-cookie") is None, "Alias redirect created browser state")
    outcomes.append({"check": "alias-navigation-preserves-target", "status": "pass"})

    for method, path in (
        ("POST", "/api/start"),
        ("GET", "/api/status"),
        ("POST", "/gnap"),
        ("OPTIONS", "/gnap"),
        ("POST", "/continue"),
        ("POST", "/continue/synthetic"),
        ("DELETE", "/token/synthetic"),
        ("GET", "/resource/folder"),
    ):
        status, headers, _, _ = request(browser, alias, path, method, browser_origin=base)
        expect(status == 421, "Noncanonical API or protocol request was not rejected")
        expect(headers.get("location") is None, "Protocol request was redirected")
        expect(headers.get("set-cookie") is None, "Rejected alias request created browser state")
    outcomes.append({"check": "alias-protocol-does-not-redirect", "status": "pass"})

    status, headers, _, _ = request(browser, alias, "/unknown-smoke-route")
    expect(status == 404 and headers.get("location") is None, "Unknown alias route was redirected")
    outcomes.append({"check": "alias-health-and-unknown-route", "status": "pass"})


def workbench(base, outcomes):
    browser = client()
    status, _, _, _ = request(browser, base, "/health")
    expect(status == 200, "Workbench health failed")
    for label, body, expected in [
        ("valid-request", '{"client":"synthetic-client"}', "pass"),
        ("invalid-request", '{"client":42}', "fail"),
    ]:
        status, headers, result, elapsed = request(
            browser, base, "/api/analyze", "POST", {"kind": "grant_request", "body": body}
        )
        expect(status == 200 and result.get("certification") is False, "Workbench claimed certification or failed")
        expect(headers.get("cache-control") == "no-store", "Workbench response is cacheable")
        checks = {item["id"]: item["status"] for item in result["checks"]}
        expect(checks.get("message-shape") == expected, "Wrong shape diagnostic: " + label)
        expect(checks.get("request-proof") == "not_tested", "Import report claimed live signature verification")
        outcomes.append({"check": "workbench-" + label, "status": "pass", "elapsed_ms": elapsed})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", type=origin)
    parser.add_argument("--demo-alias", type=origin, help="An additional demo origin you control; requires --demo")
    parser.add_argument("--workbench", type=origin)
    args = parser.parse_args()
    if not args.demo and not args.workbench:
        parser.error("Provide --demo and/or --workbench; only test targets you control")
    if args.demo_alias and (not args.demo or args.demo_alias == args.demo):
        parser.error("--demo-alias requires a distinct --demo origin")
    outcomes = []
    try:
        if args.demo:
            ready(args.demo)
            demo(args.demo, outcomes)
            if args.demo_alias:
                demo_alias(args.demo, args.demo_alias, outcomes)
        if args.workbench:
            ready(args.workbench)
            workbench(args.workbench, outcomes)
    except (AssertionError, OSError, ValueError, TypeError, KeyError) as error:
        # Do not render arbitrary transport/parser errors, which may contain a
        # URL with a callback secret. Assertions above contain only fixed text.
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        print(json.dumps({"scope": "application-smoke", "status": "fail", "detail": detail, "checks": outcomes}, indent=2))
        return 1
    print(json.dumps({"scope": "application-smoke", "certification": False, "status": "pass", "checks": outcomes}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
