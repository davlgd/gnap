#!/usr/bin/env python3
"""Check crate-local metadata, embedded files and canonical asset copies.

Read-only, standard-library check. This does not build archives, contact a
registry, resolve dependencies or authorize publication.
"""

import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def inside(root, relative):
    """Resolve an existing file without allowing a path outside the root."""
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("missing file or path outside its allowed root")
    return path


def check_copies(root, mapping):
    errors = []
    for destination, source in mapping.items():
        try:
            actual, canonical = inside(root, destination), inside(root, source)
            if actual.read_bytes() != canonical.read_bytes():
                errors.append(f"Asset differs from its canonical source: {destination}")
        except (OSError, ValueError):
            errors.append(f"Missing or external asset: {destination}")
    return errors


def check_crate(crate):
    errors = []
    package = tomllib.loads((crate / "Cargo.toml").read_text())["package"]
    if package.get("readme") != "README.md" or not (crate / "README.md").is_file():
        errors.append(f"{crate.name}: a crate-local README.md is required")
    if package.get("documentation") != f"https://docs.rs/{crate.name}":
        errors.append(f"{crate.name}: missing crate-specific documentation URL")
    if package.get("license") != {"workspace": True} or not (crate / "LICENSE").is_file():
        errors.append(f"{crate.name}: inherit the SPDX license and include its text")
    for folder in ("src", "tests", "examples"):
        for source in (crate / folder).rglob("*.rs"):
            for relative in re.findall(r'include_(?:str|bytes)!\(\s*"([^"\n]+)"\s*\)', source.read_text()):
                try:
                    included = (source.parent / relative).resolve()
                    if not included.is_relative_to(crate.resolve()) or not included.is_file():
                        raise ValueError("nonlocal embedded file")
                except (OSError, ValueError):
                    errors.append(f"{crate.name}: embedded file outside package or missing in {source.relative_to(crate)}")
    return errors


def main():
    try:
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
        mapping = json.loads((ROOT / "tools/package-assets.json").read_text())
        errors = check_copies(ROOT, mapping)
        inside(ROOT, "LICENSE")
        for member in workspace["members"]:
            errors.extend(check_crate(ROOT / member))
            for fixture in (ROOT / member / "tests/fixtures").glob("*"):
                if fixture.name != "README.md" and fixture.relative_to(ROOT).as_posix() not in mapping:
                    errors.append(f"Unmapped fixture: {fixture.relative_to(ROOT)}")
    except (OSError, ValueError, KeyError, TypeError):
        print("Package asset configuration could not be checked.")
        return 1
    for error in errors:
        print(error)
    if not errors:
        print(f"{len(workspace['members'])} crate asset layouts and {len(mapping)} canonical asset copies verified; no publication performed.")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
