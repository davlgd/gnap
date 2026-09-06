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


def ready(base, *, registration=False):
    # The demo's one-time RSA/bootstrap work precedes grant readiness, not
    # liveness. Workbench health has no registration state. No TLS bypasses.
    deadline = time.monotonic() + (150 if registration else 45)
    while time.monotonic() < deadline:
        try:
            status, _, body, _ = request(client(), base, "/health")
            if status == 200:
                if not registration:
                    return
                expect(isinstance(body, dict), "Demo liveness response is not JSON")
                state = body.get("bootstrap")
                expect(state in ("starting", "ready", "failed"), "Demo bootstrap state is missing or unknown")
                expect(state != "failed", "Demo resource registration bootstrap failed")
                if state == "ready":
                    return
        except OSError:
            pass
        time.sleep(0.5)
    raise AssertionError("Application did not reach the required startup state")


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
    rs_api(base, outcomes)
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
    check_metadata(action("read-metadata"))
    action("rotate")
    action("check-retired")
    action("read")
    check_metadata(action("read-metadata"))
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


def check_metadata(body):
    folder = body.get("folder")
    expect(isinstance(folder, dict), "Downstream read returned no dossier")
    expect(folder.get("metadata") == {"source": "synthetic-archive", "document_count": 1},
           "Downstream service did not return the expected synthetic metadata")
    expect(folder.get("derived_right") == "archive-metadata:read",
           "Downstream read did not use the expected separate right")
    lifetime = folder.get("derived_lifetime_seconds")
    expect(isinstance(lifetime, int) and not isinstance(lifetime, bool) and 1 <= lifetime <= 60,
           "Downstream token lifetime left the selected profile")
    # These are visible scenario results, not independent proof of AS policy.
    # Cross-audience and state-race evidence comes from the HTTP/SDK tests.


def ongoing_demo(base, outcomes):
    """Observe rights changes through the browser adapter and actual RS reads."""
    browser = client()
    folder = "synthetic-folder:read"
    archive = "synthetic-archive:read"

    def action(name):
        status, _, body, elapsed = request(browser, base, "/api/" + name, "POST", {}, base)
        expect(status == 200 and isinstance(body, dict), "Ongoing grant action failed: " + name)
        outcomes.append({"check": "ongoing-" + name, "status": "pass", "elapsed_ms": elapsed})
        return body

    def approve():
        body = action("approve")
        callback = urllib.parse.urlsplit(body.get("redirect", ""))
        expected = urllib.parse.urlsplit(base)
        expect(
            (callback.scheme, callback.netloc, callback.path)
            == (expected.scheme, expected.netloc, "/callback") and not callback.fragment,
            "Ongoing callback left the configured origin/path",
        )
        status, _, _, _ = request(browser, base, callback.path + "?" + callback.query)
        expect(status == 303, "Ongoing callback was rejected")
        wait_for_continuation(browser, base)
        body = action("continue")
        expect(body.get("state") == "approved" and body.get("continuation_open") is True,
               "Approval did not leave an open grant")
        return body

    def read(name, expected_status):
        body = action(name)
        expect(body.get("last_resource_status") == expected_status,
               "Resource rights were not enforced: " + name)

    action("start")
    body = approve()
    expect(set(body.get("rights", [])) == {folder, archive}, "Initial rights differ from the approved request")
    read("read", 200)
    read("read-archive", 200)
    wait_for_continuation(browser, base)
    body = action("continue")
    expect(body.get("state") == "approved" and body.get("token_present") is True
           and body.get("continuation_open") is True, "Approved polling lost access or continuation")

    wait_for_continuation(browser, base)
    body = action("downscope")
    expect(body.get("state") == "approved" and body.get("rights") == [folder],
           "Downscope was not approved with only the remaining right")
    action("check-retired")
    read("read", 200)
    read("read-archive", 401)
    check_metadata(action("read-metadata"))

    wait_for_continuation(browser, base)
    body = action("expand")
    expect(body.get("state") == "pending" and body.get("rights") == [folder]
           and set(body.get("requested_rights", [])) == {folder, archive},
           "Expansion skipped consent or changed rights before approval")
    read("read", 200)
    read("read-archive", 401)
    body = approve()
    expect(set(body.get("rights", [])) == {folder, archive}, "Fresh approval did not grant the requested expansion")
    action("check-retired")
    read("read-archive", 200)
    wait_for_continuation(browser, base)
    body = action("revoke-grant")
    expect(body.get("state") == "grant_revoked" and body.get("token_present") is False
           and body.get("continuation_open") is False, "Grant revocation retained local authority")
    action("check-retired")


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
        ("GET", "/resource/folder-metadata"),
        ("GET", "/resource/archive-metadata"),
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

    for label, endpoint, captured, endpoint_status in [
        ("discovery", "https://test-as.example/gnap", True, "pass"),
        ("discovery-userinfo", "https://user@test-as.example/gnap", True, "fail"),
        ("discovery-without-http-context", "https://test-as.example/gnap", False, "pass"),
    ]:
        envelope = {
            "kind": "as_discovery",
            "body": json.dumps({"grant_request_endpoint": endpoint, "key_proofs_supported": ["httpsig"]}),
        }
        if captured:
            envelope.update({"headers": [["Content-Type", "application/json"]],
                             "http_status": 200, "queried_endpoint": endpoint})
        status, headers, result, elapsed = request(browser, base, "/api/analyze", "POST", envelope)
        expect(status == 200 and result.get("certification") is False, "Discovery import failed or claimed certification")
        expect(headers.get("cache-control") == "no-store", "Discovery report is cacheable")
        expect(result.get("observation", {}).get("source") == "import", "Synthetic discovery import claimed live provenance")
        checks = {item["id"]: item["status"] for item in result["checks"]}
        expect(checks.get("discovery-endpoint") == endpoint_status, "Wrong discovery endpoint diagnostic")
        context_status = "pass" if captured else "not_tested"
        for check in ("discovery-http-200", "discovery-media-type", "discovery-endpoint-match"):
            expect(checks.get(check) == context_status, "Wrong discovery HTTP context diagnostic")
        expect(checks.get("discovery-capability-behavior") == "not_tested", "Discovery import claimed capability execution")
        outcomes.append({"check": "workbench-" + label, "status": "pass", "elapsed_ms": elapsed})


def rs_imports(base, outcomes):
    """Check imported wire diagnostics, never infer live AS/RS authentication."""
    browser = client()
    discovery = {"grant_request_endpoint": "https://as.example/gnap"}
    active = {"active": True, "access": ["synthetic-folder:read"],
              "iss": "https://as.example/gnap", "key": "synthetic-client-key"}
    cases = [
        ("discovery", "rs_discovery", discovery,
         {"grant_request_endpoint": "https://as.example/gnap",
          "discovery_url": "https://as.example/.well-known/gnap-as-rs"},
         {"rs-discovery-grant-identity": "pass", "rs-discovery-declared-location": "pass"}),
        ("wrong-location", "rs_discovery", discovery,
         {"discovery_url": "https://as.example/other"},
         {"rs-discovery-declared-location": "fail", "rs-discovery-grant-identity": "not_tested"}),
        ("optional-request-context", "introspection_request",
         {"access_token": "synthetic-token", "resource_server": "synthetic-rs"}, None,
         {"introspection-request-proof": "not_tested", "introspection-request-access": "not_tested"}),
        ("inactive", "introspection_response", {"active": False}, None,
         {"introspection-inactive-only": "pass"}),
        ("inactive-disclosure", "introspection_response", {"active": False, "iss": "https://as.example/gnap"}, None,
         {"introspection-inactive-only": "fail"}),
        ("active", "introspection_response", active, {"token_binding": "bound"},
         {"introspection-active-access": "pass", "introspection-active-issuer": "pass", "introspection-key-condition": "pass"}),
        ("missing-issuer", "introspection_response", {k: v for k, v in active.items() if k != "iss"}, None,
         {"introspection-active-issuer": "fail"}),
        ("token-disclosure", "introspection_response", active | {"value": "synthetic-token"}, None,
         {"introspection-response-no-value": "fail"}),
        ("rs-error", "rs_error_response", {"error": "invalid_resource_server"}, {"http_status": 400},
         {"rs-error-shape": "pass", "rs-error-http-status": "pass"}),
        ("rs-error-status", "rs_error_response", {"error": "invalid_resource_server"}, {"http_status": 401},
         {"rs-error-http-status": "fail"}),
        ("registration-request", "resource_registration_request",
         {"access": ["synthetic-folder:read"], "resource_server": "synthetic-rs",
          "token_introspection_required": True}, None,
         {"registration-request-access": "pass", "registration-request-rs": "pass",
          "registration-request-introspection-required": "pass"}),
        ("registration-missing-type", "resource_registration_request",
         {"access": [{"actions": ["read"]}], "resource_server": "synthetic-rs"}, None,
         {"registration-request-access": "fail"}),
        ("registration-empty-formats", "resource_registration_request",
         {"access": [], "resource_server": "synthetic-rs", "token_formats_supported": []}, None,
         {"registration-request-access": "pass", "registration-request-token-formats": "pass"}),
        ("registration-response", "resource_registration_response",
         {"resource_reference": "a public reference, not a token"}, None,
         {"registration-response-reference": "pass", "registration-response-instance-id": "not_tested"}),
        ("registration-missing-reference", "resource_registration_response",
         {"instance_id": "synthetic-rs"}, None,
         {"registration-response-reference": "fail"}),
    ]
    for label, kind, body, context, expected in cases:
        payload = {"kind": kind, "body": json.dumps(body)}
        if context is not None:
            payload["rs_context"] = context
        status, headers, result, elapsed = request(browser, base, "/api/analyze", "POST", payload)
        expect(status == 200 and isinstance(result, dict) and result.get("certification") is False,
               "RS import diagnostic failed or claimed certification: " + label)
        expect(headers.get("cache-control") == "no-store", "RS import report is cacheable")
        checks = {item["id"]: item["status"] for item in result["checks"]}
        for name, expected_status in expected.items():
            expect(checks.get(name) == expected_status, "Wrong RS import diagnostic: " + label + "/" + name)
        expect(checks.get("rs-authentication-and-state") == "not_tested"
               and checks.get("rs-http-and-discovery-publication") == "not_tested",
               "Imported RS message was mistaken for a live observation")
        if kind.startswith("resource_registration_"):
            expect(all(checks.get(name) == "not_tested" for name in (
                "registration-format-compatibility", "registration-introspection-support",
                "registration-authentication-and-state")),
                "Registration import claimed AS capabilities or a persisted reference")
        outcomes.append({"check": "workbench-rs-" + label, "status": "pass", "elapsed_ms": elapsed})


def rs_api(base, outcomes):
    """Wire checks independent of the SDK; no claim of RS authentication here."""
    browser = client()
    status, headers, body, elapsed = request(browser, base, "/.well-known/gnap-as-rs")
    expect(status == 200 and isinstance(body, dict), "RS-facing discovery is not a JSON object response")
    expect(headers.get_content_type() == "application/json", "RS-facing discovery has the wrong media type")
    expect(body.get("grant_request_endpoint") == base + "/gnap", "RS-facing discovery changed the grant endpoint")
    expect(body.get("introspection_endpoint") == base + "/introspect", "RS-facing discovery changed the introspection endpoint")
    expect(body.get("key_proofs_supported") == ["httpsig"], "RS-facing discovery advertised unsupported proofs")
    expect("token_formats_supported" not in body, "RS-facing discovery invented an opaque token-format name")
    expect(body.get("resource_registration_endpoint") == base + "/register-resources",
           "RS-facing discovery changed the registration endpoint")
    expect(headers.get("cache-control") == "no-store", "RS-facing discovery response is cacheable")
    expect(headers.get("set-cookie") is None and headers.get("location") is None,
           "RS-facing discovery created browser state or redirected")
    expected_deviation = "insecure-loopback-discovery" if base.startswith("http://") else None
    expect(headers.get("gnap-development-only") == expected_deviation,
           "RS-facing discovery development mode is mislabelled")
    outcomes.append({"check": "rs-facing-discovery", "status": "pass", "elapsed_ms": elapsed})
    # These are refusal cases, not evidence that a valid RS proof is accepted.
    for label, payload, expected_error in [
        ("unsigned", {"access_token": "synthetic-not-issued", "resource_server": "delegation-demo-rs"},
         "invalid_resource_server"),
        ("missing-token", {"resource_server": "delegation-demo-rs"}, "invalid_request"),
    ]:
        status, headers, body, elapsed = request(browser, base, "/introspect", "POST", payload)
        expect(status == 400 and body == {"error": expected_error},
               "Introspection refusal must use HTTP 400 and a single error field: " + label)
        expect(headers.get_content_type() == "application/json" and headers.get("cache-control") == "no-store",
               "Introspection refusal has unsafe headers: " + label)
        outcomes.append({"check": "rs-introspection-rejects-" + label, "status": "pass", "elapsed_ms": elapsed})
    status, headers, body, elapsed = request(browser, base, "/register-resources", "POST", {
        "access": ["synthetic-folder:read"], "resource_server": "delegation-demo-rs",
        "token_introspection_required": True,
    })
    expect(status == 400 and body == {"error": "invalid_resource_server"},
           "Unsigned resource registration was not refused with a single RS error")
    expect(headers.get("cache-control") == "no-store", "Registration refusal is cacheable")
    outcomes.append({"check": "rs-registration-rejects-unsigned", "status": "pass", "elapsed_ms": elapsed})


def derivation_imports(base, outcomes):
    """Inspect selected shapes without claiming a successful delegation chain."""
    browser = client()
    grant = {"client": "synthetic-rs1", "existing_access_token": "synthetic-parent",
             "access_token": {"access": ["synthetic-metadata:read"]}}
    cases = [
        ("request", "derivation_request", grant,
         {"derivation-request-parent": "pass", "derivation-request-client": "pass",
          "derivation-request-access": "pass"}),
        ("missing-parent", "derivation_request",
         {key: value for key, value in grant.items() if key != "existing_access_token"},
         {"derivation-request-parent": "fail"}),
        ("wrong-parent-type", "derivation_request", grant | {"existing_access_token": 42},
         {"derivation-request-parent": "fail"}),
        ("missing-labels", "derivation_request",
         grant | {"access_token": [{"access": ["a"]}, {"access": ["b"]}]},
         {"derivation-request-labels": "fail"}),
        ("response", "derivation_response",
         {"access_token": {"value": "synthetic-child", "access": ["synthetic-metadata:read"]}},
         {"derivation-response-value": "pass", "derivation-response-access": "pass"}),
        ("missing-value", "derivation_response", {"access_token": {"access": ["a"]}},
         {"derivation-response-value": "fail"}),
        ("error-response", "derivation_response", {"error": "request_denied"},
         {"derivation-response-token-shape": "not_tested"}),
    ]
    for label, kind, body, expected in cases:
        status, headers, result, elapsed = request(browser, base, "/api/analyze", "POST",
                                                   {"kind": kind, "body": json.dumps(body)})
        expect(status == 200 and isinstance(result, dict) and result.get("certification") is False,
               "Derivation import failed or claimed certification: " + label)
        expect(headers.get("cache-control") == "no-store", "Derivation import is cacheable")
        checks = {item["id"]: item["status"] for item in result["checks"]}
        for name, expected_status in expected.items():
            expect(checks.get(name) == expected_status,
                   "Wrong derivation diagnostic: " + label + "/" + name)
        expect(all(checks.get(name) == "not_tested" for name in (
            "derivation-proof-and-parent-validity", "derivation-parent-rs-suitability",
            "derivation-effective-rights-and-audience", "derivation-revocation-and-lineage",
            "derivation-grant-exchange")),
            "An imported derivation message was mistaken for an authenticated exchange")
        rendered = json.dumps(result)
        expect(all(value not in rendered for value in ("synthetic-parent", "synthetic-child")),
               "Derivation report reflected a submitted credential")
        outcomes.append({"check": "workbench-derivation-" + label,
                         "status": "pass", "elapsed_ms": elapsed})


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
            ready(args.demo, registration=True)
            demo(args.demo, outcomes)
            ongoing_demo(args.demo, outcomes)
            if args.demo_alias:
                demo_alias(args.demo, args.demo_alias, outcomes)
        if args.workbench:
            ready(args.workbench)
            workbench(args.workbench, outcomes)
            rs_imports(args.workbench, outcomes)
            derivation_imports(args.workbench, outcomes)
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
