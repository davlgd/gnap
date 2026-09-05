#!/usr/bin/env python3
"""Fetch GNAP's 23 IANA registries and vendor them into registries/.

Vendoring rather than downloading at build time keeps generation reproducible
and offline, and a `git diff` shows exactly what IANA changed between updates.

Usage: python3 tools/fetch_registries.py
"""
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "registries"
INDEX = "https://www.iana.org/assignments/gnap/gnap.xhtml"
BASE = "https://www.iana.org/assignments/gnap/{}.csv"

# 16 registries created by RFC 9635 + 7 by RFC 9767.
# (RFC 9767 §5 announces five; it creates seven.)
REGISTRIES = [
    "gnap-access-token-flags",
    "gnap-assertion-formats",
    "gnap-authorization-server-discovery-fields",
    "gnap-client-instance-display-fields",
    "gnap-client-instance-fields",
    "gnap-error-codes",
    "gnap-grant-request-parameters",
    "gnap-grant-response-parameters",
    "gnap-interaction-finish-methods",
    "gnap-interaction-hints",
    "gnap-interaction-mode-responses",
    "gnap-interaction-start-modes",
    "gnap-key-formats",
    "gnap-key-proofing-methods",
    "gnap-subject-information-request-fields",
    "gnap-subject-information-response-fields",
    "gnap-resource-set-registration-request-parameters",
    "gnap-resource-set-registration-response-parameters",
    "gnap-rs-facing-discovery-document-fields",
    "gnap-rs-facing-error-codes",
    "gnap-token-formats",
    "gnap-token-introspection-request",
    "gnap-token-introspection-response",
]


def main():
    OUT.mkdir(exist_ok=True)

    # Sanity check: does the index list registries this script does not know?
    with urllib.request.urlopen(INDEX) as r:
        index = r.read().decode("utf-8", "replace")
    import re
    seen = set(re.findall(r"gnap-[a-z0-9-]+", index))
    unknown = sorted(seen - set(REGISTRIES))
    if unknown:
        print(f"WARNING: registries not listed in this script: {unknown}",
              file=sys.stderr)

    for name in REGISTRIES:
        with urllib.request.urlopen(BASE.format(name)) as r:
            data = r.read()
        (OUT / f"{name}.csv").write_bytes(data)
        entries = data.decode("utf-8").strip().count("\n")
        print(f"  {name:<52} {entries} entries")

    print(f"\n{len(REGISTRIES)} registries vendored into {OUT}")


if __name__ == "__main__":
    main()
