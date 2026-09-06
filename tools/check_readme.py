#!/usr/bin/env python3
"""Check the published grant walkthrough against the real example output.

The historical command name is retained. The transcript lives in
docs/getting-started.md, linked from the root README. This checks that one
walkthrough, not every documentation claim or the support matrix.
No private requirements files are consulted.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def flatten(text):
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def check_transcript(guide):
    """Require one narrated flow transcript and compare it with a locked run."""
    blocks = re.findall(
        r"```console\n\$ cargo run -p gnap-as --example flow(?: --locked)?\n+(.*?)```",
        guide, re.S)
    if len(blocks) != 1:
        print("Getting started must contain exactly one narrated flow transcript.")
        return 1
    try:
        run = subprocess.run(
            ["cargo", "run", "-q", "--locked", "--example", "flow", "-p", "gnap-as"],
            capture_output=True, text=True, cwd=ROOT, check=False, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        print("The flow example could not be executed within the check's limits.")
        return 1
    if run.returncode:
        print("The flow example failed; run it directly for build diagnostics.")
        return 1
    if flatten(blocks[0]) != flatten(run.stdout):
        print("The Getting started transcript differs from the flow example output.")
        return 1
    return 0


def main():
    try:
        guide = (ROOT / "docs/getting-started.md").read_text(encoding="utf-8")
    except OSError:
        print("The Getting started guide could not be read.")
        return 1
    result = check_transcript(guide)
    if result == 0:
        print("The published grant walkthrough matches the example.")
    return result


if __name__ == "__main__":
    sys.exit(main())
