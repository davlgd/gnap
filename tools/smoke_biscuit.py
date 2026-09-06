#!/usr/bin/env python3
"""Check an explicitly authorized, synthetic Biscuit deployment.

No signing key is loaded. Resource outcomes are reported by the browser-facing
client, not captured independently on the client-to-RS connection. This is
application acceptance, not GNAP certification. Maintenance mode requires an
operator to stop/restart services; the driver never executes deployment commands.
"""

import argparse
from http.cookies import CookieError, SimpleCookie
import json
import select
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from smoke_ecosystem import client, origin


class Failure(Exception):
    """Only a locally authored check identifier is exposed in the report."""


class Inconclusive(Failure):
    """A transport or timing limit prevented a meaningful observation."""


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Ambiguous JSON")
        result[name] = value
    return result


def canonical_origin(value):
    value = origin(value)
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid origin port") from None
    host = parsed.hostname
    if ":" in host:
        host = "[" + host + "]"
    default = 443 if parsed.scheme == "https" else 80
    canonical = parsed.scheme + "://" + host + (f":{port}" if port and port != default else "")
    if value != canonical or "@" in value:
        raise argparse.ArgumentTypeError("Use a canonical origin without credentials or a default port")
    return value


def exchange(browser, base, path, method="GET", data=None, browser_origin=None):
    headers = {"Accept": "application/json"}
    if browser_origin is not None:
        headers["Origin"] = browser_origin
    payload = None if data is None else json.dumps(data).encode()
    if payload is not None:
        headers["Content-Type"] = "application/json"
    outgoing = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    try:
        response = browser.open(outgoing, timeout=40 if path == "/action/rotate-key" else 10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(32_769)
        if len(raw) > 32_768:
            raise ValueError("Response exceeds the acceptance bound")
        try:
            body = json.loads(raw, object_pairs_hook=unique_object)
        except (ValueError, UnicodeDecodeError):
            body = None
        return response.status, response.headers, body


def session_cookie(headers, secure):
    cookies = headers.get_all("Set-Cookie") or []
    if len(cookies) != 1:
        return False
    jar = SimpleCookie()
    try:
        jar.load(cookies[0])
    except CookieError:
        return False
    if set(jar) != {"biscuit_session"}:
        return False
    cookie = jar["biscuit_session"]
    return (len(cookie.value) == 22 and all(c.isascii() and (c.isalnum() or c in "-_") for c in cookie.value)
            and cookie["path"] == "/" and cookie["httponly"]
            and cookie["samesite"].lower() == "strict" and cookie["max-age"] == "1200"
            and (not secure or bool(cookie["secure"])))


def pause(instruction):
    print(instruction + " Then press Enter within five minutes.", file=sys.stderr, flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], 300)
    if not ready or sys.stdin.readline() == "":
        raise Inconclusive("maintenance-operator-confirmation")


class Scenario:
    def __init__(self, as_origin, rs_origin, client_origin):
        self.as_origin, self.rs_origin, self.client_origin = as_origin, rs_origin, client_origin
        self.checks = []
        self.sessions = []
        self.started = time.monotonic()

    def check(self, name, condition):
        self.checks.append({"check": name, "status": "pass" if condition else "fail"})
        if not condition:
            raise Failure(name)

    def call(self, browser, base, path, method="GET", data=None, browser_origin=None):
        if time.monotonic() - self.started >= 900:
            raise Inconclusive("scenario-deadline")
        try:
            result = exchange(browser, base, path, method, data, browser_origin)
        except (OSError, ValueError, TypeError, OverflowError):
            raise Inconclusive("bounded-http-exchange") from None
        if time.monotonic() - self.started >= 900:
            raise Inconclusive("scenario-deadline")
        return result

    def action(self, browser, name, data=None):
        status, headers, body = self.call(browser, self.client_origin, "/action/" + name,
                                          "POST", {} if data is None else data, self.client_origin)
        # The envelope is an application contract, not a GNAP message.
        if (status != 200 or not isinstance(body, dict)
                or headers.get("cache-control") != "no-store"
                or headers.get_content_type() != "application/json"):
            raise Failure("client-action-" + name)
        expected = {"event"}
        if name == "status":
            expected |= {"attenuated", "retired_available", "key_rotations"}
        elif name == "attenuate":
            expected |= {"file", "seconds"}
        elif name in {"rotate", "rotate-key"}:
            expected.add("key_rotations")
        elif name in {"read", "write", "read-draft", "write-notes", "check-retired", "check-old-key"}:
            expected |= {"status", "result"}
        if set(body) != expected or not isinstance(body.get("event"), str):
            raise Failure("client-response-shape")
        return headers, body

    def start(self, name="session"):
        browser = client()
        # Retain the jar for best-effort cleanup even if the response is lost.
        self.sessions.append(browser)
        headers, _ = self.action(browser, "start")
        self.check(name + "-cookie-protection", session_cookie(headers, self.client_origin.startswith("https:")))
        return browser

    def resource(self, browser, action, expected, name):
        _, body = self.action(browser, action)
        result = body.get("result")
        valid = body.get("status") == expected and isinstance(result, dict)
        if expected == 200:
            if action == "write":
                valid = valid and set(result) == {"written_bytes"} and type(result["written_bytes"]) is int and result["written_bytes"] > 0
            else:
                valid = valid and set(result) == {"content"} and result["content"] == "Synthetic notes: local attenuation preserves the client's key.\n"
        else:
            valid = valid and set(result) == {"error"} and result["error"] == "request refused"
        self.check(name, valid)

    def run(self, maintenance=False):
        for role, base in [("as", self.as_origin), ("rs", self.rs_origin), ("client", self.client_origin)]:
            status, _, _ = self.call(client(), base, "/health")
            self.check(role + "-health", status == 200)
        for base, path, method in [(self.rs_origin, "/files/notes", "GET"),
                                   (self.as_origin, "/resource-check", "POST"),
                                   (self.as_origin, "/gnap", "POST")]:
            status, _, _ = self.call(client(), base, path, method, {} if method == "POST" else None)
            self.check("unsigned-" + path.strip("/").replace("/", "-"), status in (400, 401, 403))
        status, _, _ = self.call(client(), self.client_origin, "/action/start", "POST", {}, "https://untrusted.invalid")
        self.check("cross-origin-start-refused", status == 403)
        browser = self.start()
        status, _, _ = self.call(client(), self.client_origin, "/action/read", "POST", {}, self.client_origin)
        self.check("anonymous-session-isolation", status == 401)
        self.resource(browser, "read", 200, "initial-read-notes")
        self.resource(browser, "write", 200, "initial-write-draft")
        self.resource(browser, "read-draft", 403, "read-draft-refused")
        self.resource(browser, "write-notes", 403, "write-notes-refused")
        attenuation_started = time.monotonic()
        self.action(browser, "attenuate", {"file": "notes", "seconds": 120})
        _, state = self.action(browser, "status")
        self.check("local-attenuation-selected", state.get("attenuated") is True)
        self.resource(browser, "read", 200, "attenuated-read-notes")
        self.resource(browser, "write", 403, "attenuated-write-refused")
        self.action(browser, "rotate")
        self.unexpired_descendant(attenuation_started)
        self.resource(browser, "check-retired", 403, "value-rotation-retires-descendant")
        self.unexpired_descendant(attenuation_started)
        self.resource(browser, "read", 200, "value-rotation-read")
        self.resource(browser, "write", 200, "value-rotation-restores-parent-rights")
        for generation in (1, 2):
            attenuation_started = time.monotonic()
            self.action(browser, "attenuate", {"file": "notes", "seconds": 120})
            self.resource(browser, "read", 200, f"key-rotation-{generation}-live-descendant")
            _, state = self.action(browser, "rotate-key")
            self.check(f"key-rotation-{generation}-adopted", state.get("key_rotations") == generation)
            for action, status in [("read", 200), ("write", 200), ("check-old-key", 403), ("check-retired", 403)]:
                self.unexpired_descendant(attenuation_started)
                self.resource(browser, action, status, f"key-rotation-{generation}-{action}")
                self.unexpired_descendant(attenuation_started)
        attenuation_started = time.monotonic()
        self.action(browser, "attenuate", {"file": "notes", "seconds": 120})
        self.resource(browser, "read", 200, "live-descendant-before-revocation")
        self.action(browser, "revoke")
        self.unexpired_descendant(attenuation_started)
        self.resource(browser, "check-retired", 403, "revocation-retires-descendant")
        self.unexpired_descendant(attenuation_started)
        self.sessions.remove(browser)
        fresh = self.start("independent-session")
        self.resource(fresh, "read", 200, "independent-session-remains-available")
        self.action(fresh, "revoke")
        self.resource(fresh, "check-retired", 403, "independent-session-revocation")
        self.sessions.remove(fresh)
        if maintenance:
            self.maintenance()

    @staticmethod
    def unexpired_descendant(started):
        # Refusal after a selected descendant has expired cannot demonstrate
        # parent retirement. Keep a margin for a final bounded resource call.
        if time.monotonic() - started >= 100:
            raise Inconclusive("descendant-retirement-window")

    def maintenance(self):
        browser = self.start("maintenance-session")
        self.resource(browser, "read", 200, "maintenance-initial-read")
        pause("Restart ONLY the RS and wait until it is ready; leave the AS and client running.")
        self.resource(browser, "read", 200, "fresh-read-after-rs-restart")
        pause("Stop ONLY the AS and wait until it is unavailable; leave the RS and client running.")
        self.resource(browser, "read", 503, "as-outage-refuses-resource")
        pause("Restart the AS with the same configuration and wait until it is ready.")
        self.resource(browser, "read", 403, "as-restart-retires-old-authority")
        self.sessions.remove(browser)
        fresh = self.start("recovery-session")
        self.resource(fresh, "read", 200, "new-grant-after-as-restart")
        self.action(fresh, "revoke")
        self.resource(fresh, "check-retired", 403, "maintenance-final-revocation")
        self.sessions.remove(fresh)

    def cleanup(self):
        # No retries: an interrupted action may already have changed remote
        # state. Only this driver's retained sessions are addressed.
        results = []
        for browser in self.sessions:
            try:
                self.action(browser, "revoke")
                results.append("revocation-acknowledged")
            except Failure:
                results.append("unconfirmed")
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as", dest="as_origin", required=True, type=canonical_origin)
    parser.add_argument("--rs", dest="rs_origin", required=True, type=canonical_origin)
    parser.add_argument("--client", dest="client_origin", required=True, type=canonical_origin)
    parser.add_argument("--consent", action="store_true", help="Authorize disposable grants, synthetic writes and negative probes on these services")
    parser.add_argument("--maintenance", action="store_true", help="Pause for operator-controlled RS restart and AS outage/restart; affects other sessions")
    args = parser.parse_args()
    if not args.consent:
        parser.error("--consent is required; only test deployments you are authorized to exercise")
    if args.maintenance and not sys.stdin.isatty():
        parser.error("--maintenance requires an interactive terminal for operator confirmations")
    if len({args.as_origin, args.rs_origin, args.client_origin}) != 3:
        parser.error("Supply three distinct role origins")
    scenario = Scenario(args.as_origin, args.rs_origin, args.client_origin)
    failure = None
    outcome = "pass"
    try:
        scenario.run(args.maintenance)
    except Failure as error:
        failure = str(error)
        outcome = "inconclusive" if isinstance(error, Inconclusive) else "fail"
    except (OSError, ValueError, TypeError, KeyError, EOFError, KeyboardInterrupt):
        failure = "scenario-interrupted"
        outcome = "inconclusive"
    cleanup = scenario.cleanup()
    report = {"scope": "biscuit-application-acceptance", "certification": False,
              "status": outcome, "failed_check": failure,
              "checks": scenario.checks, "maintenance": args.maintenance,
              "cleanup": cleanup,
              "limitations": "Resource results are reported by the client application. No independent wire, browser-engine, exact-request replay, full Biscuit grammar or RFC 9767 introspection verdict. No deployment revision is inferred from HTTP health."}
    print(json.dumps(report, indent=2))
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
