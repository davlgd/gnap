#!/usr/bin/env python3
"""Exercise only explicitly authorized GNAP demo/workbench deployments.

The driver, not the workbench, acts as the synthetic resource owner in a
separate cookie jar. No credential, callback value or response body is printed.
The registration-only mode outputs PUBLIC client configuration, never a key
that can sign requests. This is application acceptance, not certification.
"""
import argparse
from html.parser import HTMLParser
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from smoke_ecosystem import client, expect, origin, request

CHECK_IDS = {
    "lifecycle-pending-no-store", "lifecycle-pending-json", "lifecycle-manual-consent-required",
    "lifecycle-finish-binding-sdk", "lifecycle-issued-no-store", "lifecycle-issued-json",
    "lifecycle-issued-token-profile", "lifecycle-valid-token-read", "lifecycle-replay-refused",
    "lifecycle-other-key-refused", "lifecycle-valid-after-negative-probes", "lifecycle-rotated-no-store",
    "lifecycle-rotated-json", "lifecycle-rotated-token-profile", "lifecycle-rotation-changes-value",
    "lifecycle-rotated-value-refused", "lifecycle-rotated-token-read", "lifecycle-token-revocation-response",
    "lifecycle-revoked-value-refused", "lifecycle-denial-no-store", "lifecycle-denial-json",
    "lifecycle-owner-denial-no-token", "lifecycle-completion",
}


class ConsentForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tickets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("name") == "ticket":
            self.tickets.append(values.get("value"))


def registration(workbench):
    status, _, body, _ = request(client(), workbench, "/api/lifecycle/key")
    expect(status == 200 and isinstance(body, dict), "Public workbench key unavailable")
    jwk = body.get("jwk")
    expect(isinstance(jwk, dict) and jwk.get("kty") == "RSA" and jwk.get("alg") == "PS256", "Unexpected public key profile")
    expect(not set(jwk).intersection({"d", "p", "q", "dp", "dq", "qi", "oth", "k"}), "Public key contains private material")
    expect(body.get("callback") == workbench + "/lifecycle/callback", "Unexpected workbench callback")
    return [{"jwk": jwk, "callback": body["callback"]}]


def local_path(url, base, prefix, *, exact=False):
    expect(isinstance(url, str), "Response destination is missing")
    parsed = urllib.parse.urlsplit(url)
    approved = urllib.parse.urlsplit(base)
    expect((parsed.scheme, parsed.netloc) == (approved.scheme, approved.netloc), "Response destination is not approved")
    path_matches = parsed.path == prefix if exact else parsed.path.startswith(prefix)
    expect(not parsed.fragment and path_matches, "Unexpected response path")
    return parsed.path + ("?" + parsed.query if parsed.query else "")


def observed_checks(state):
    report = state.get("report")
    if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
        return []
    # Neither arbitrary identifiers nor upstream explanations are printable.
    return [c["id"] + ":" + c["status"] for c in report["checks"]
            if isinstance(c, dict) and isinstance(c.get("id"), str)
            and c["id"] in CHECK_IDS and isinstance(c.get("status"), str)
            and c["status"] in {"pass", "fail", "not_tested"}]


def form(browser, demo, path, ticket, choice):
    payload = urllib.parse.urlencode({"ticket": ticket, "choice": choice}).encode()
    outgoing = urllib.request.Request(demo + path, data=payload, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Origin": demo,
    })
    try:
        response = browser.open(outgoing, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        expect(response.status == 303, "Manual consent did not return its bound callback")
        expect(len(response.read(8193)) <= 8192, "Consent response exceeds its bound")
        return response.headers.get("Location")


def scenario(demo, workbench, choice):
    browser, owner, stranger = client(), client(), client()
    status, _, targets, _ = request(browser, workbench, "/api/lifecycle/targets")
    expect(status == 200 and isinstance(targets, list), "Lifecycle targets unavailable")
    selected = next((t for t in targets if isinstance(t, dict) and t.get("grant") == demo + "/gnap" and t.get("resource") == demo + "/resource/folder"), None)
    expect(selected is not None, "This demo/RS pair is not operator-approved")
    status, headers, _, _ = request(browser, workbench, "/api/lifecycle/start", "POST", {"target_id": selected["id"], "consent": True}, workbench)
    expect(status == 202, "Lifecycle start refused; check operator key approval, cooldown and capacity")
    cookies = headers.get_all("Set-Cookie") or []
    expect(len(cookies) == 1 and "HttpOnly" in cookies[0] and "SameSite=Lax" in cookies[0], "Lifecycle cookie protection missing")
    expect(workbench.startswith("http:") or "Secure" in cookies[0], "HTTPS lifecycle cookie lacks Secure")
    deadline = time.monotonic() + 35
    while True:
        status, _, state, _ = request(browser, workbench, "/api/lifecycle/status")
        expect(status == 200 and isinstance(state, dict), "Lifecycle status unavailable")
        if state.get("status") == "pending":
            break
        expect(state.get("status") == "running" and time.monotonic() < deadline, "Lifecycle did not reach manual consent")
        time.sleep(0.2)
    interaction = local_path(state.get("redirect", ""), demo, "/interact/")
    status, headers, page, _ = request(owner, demo, interaction, html=True)
    expect(status == 200 and isinstance(page, str), "External owner page unavailable")
    owner_cookies = headers.get_all("Set-Cookie") or []
    expect(any("gnap_external_owner=" in c and "HttpOnly" in c for c in owner_cookies), "Separate owner cookie missing")
    parser = ConsentForm()
    parser.feed(page)
    expect(len(parser.tickets) == 1 and parser.tickets[0], "Owner form has no unique ticket")
    callback = form(owner, demo, interaction, parser.tickets[0], choice)
    callback_path = local_path(callback, workbench, "/lifecycle/callback", exact=True)
    status, _, _, _ = request(stranger, workbench, callback_path)
    expect(status == 404, "Callback without the initiating client session was accepted")
    status, headers, _, _ = request(browser, workbench, callback_path)
    expect(status == 303 and headers.get("Location") == "/lifecycle", "Bound client callback was not accepted")
    status, _, _, _ = request(browser, workbench, callback_path)
    expect(status in (400, 404), "Repeated callback was accepted")
    deadline = time.monotonic() + 75
    while True:
        status, _, state, _ = request(browser, workbench, "/api/lifecycle/status")
        expect(status == 200 and isinstance(state, dict), "Final lifecycle status unavailable")
        if state.get("status") not in ("running", "pending"):
            break
        expect(time.monotonic() < deadline, "Lifecycle completion timed out")
        time.sleep(0.2)
    if state.get("status") != ("complete" if choice == "allow" else "denied"):
        raise AssertionError("Lifecycle incomplete; observed checks: " + ", ".join(observed_checks(state)))
    report = state.get("report")
    expect(isinstance(report, dict) and report.get("certification") is False, "Unexpected lifecycle report")
    checks = report.get("checks")
    expect(isinstance(checks, list) and checks and all(
        isinstance(c, dict) and c.get("status") == "pass"
        and isinstance(c.get("id"), str) and c["id"] in CHECK_IDS
        for c in checks), "An observed lifecycle check failed, remained untested or was unknown")
    ids = [c["id"] for c in checks]
    expect(len(ids) == len(set(ids)), "Duplicate check identifiers in lifecycle report")
    required = {"lifecycle-manual-consent-required", "lifecycle-finish-binding-sdk"}
    required |= {"lifecycle-owner-denial-no-token"} if choice == "deny" else {
        "lifecycle-valid-token-read", "lifecycle-replay-refused", "lifecycle-other-key-refused",
        "lifecycle-valid-after-negative-probes", "lifecycle-rotation-changes-value",
        "lifecycle-rotated-value-refused", "lifecycle-rotated-token-read",
        "lifecycle-token-revocation-response", "lifecycle-revoked-value-refused",
    }
    expect(required.issubset(ids), "Required lifecycle observations are missing")
    raw = json.dumps(report)
    for sensitive in [parser.tickets[0], callback, interaction, cookies[0]]:
        expect(sensitive not in raw, "Report reflects private flow material")
    return {"scope": "application-lifecycle-smoke", "certification": False, "choice": choice,
            "status": "pass", "checks": len(checks), "observed_checks": ids}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench", required=True, type=origin)
    parser.add_argument("--demo", type=origin)
    parser.add_argument("--choice", choices=["allow", "deny"], default="allow")
    parser.add_argument("--registration-only", action="store_true", help="Print only the public AS allowlist configuration; no grant is started")
    args = parser.parse_args()
    if not args.registration_only and not args.demo:
        parser.error("--demo is required for the authenticated scenario")
    try:
        result = registration(args.workbench) if args.registration_only else scenario(args.demo, args.workbench, args.choice)
        print(json.dumps(result, indent=2))
    except AssertionError as error:
        # All assertion messages in this driver are fixed strings.
        print(json.dumps({"scope":"application-lifecycle-smoke", "status":"fail", "detail":str(error)}))
        raise SystemExit(1) from None
    except (OSError, ValueError, TypeError, KeyError):
        # Exception texts can contain callback URLs or credentials. Diagnostics
        # remain deliberately bounded rather than echoing library exceptions.
        print(json.dumps({"scope":"application-lifecycle-smoke", "status":"fail", "detail":"Acceptance failed; inspect configured targets, key approval, cooldown and redacted workbench checks."}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
