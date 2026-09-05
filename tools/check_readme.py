#!/usr/bin/env python3
"""Verifie deux affirmations precises du README :

  1. la transcription du flux, censee etre la sortie de l'exemple ;
  2. la liste des sections non implementees, censee correspondre au perimetre
     que `requirements/perimeter.toml` declare.

Les libelles des sections et les autres affirmations ne sont pas verifies.
La comparaison du perimetre est sautee si la base locale est absente.

Usage : python3 tools/check_readme.py
Sortie : 0 si les controles executes passent, 1 sinon.
"""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def flatten(text):
    return "\n".join(l.rstrip() for l in text.strip().splitlines())


def check_transcript(readme):
    """La transcription est-elle la sortie actuelle de l'exemple ?"""
    run = subprocess.run(
        ["cargo", "run", "-q", "--example", "flow", "-p", "gnap-as"],
        capture_output=True, text=True, cwd=ROOT, check=False)
    if run.returncode != 0:
        print("l'exemple `flow` ne s'execute pas :")
        print(run.stderr[-600:])
        return 1

    block = re.search(
        r"```console\n\$ cargo run [^\n]*--example flow\n+(.*?)```", readme, re.S)
    if not block:
        print("aucune transcription trouvee dans le README")
        return 1

    shown, actual = flatten(block.group(1)), flatten(run.stdout)
    if shown == actual:
        return 0

    print("la transcription du README n'est plus la sortie de l'exemple :")
    for n, (a, b) in enumerate(zip(shown.splitlines(), actual.splitlines()), 1):
        if a != b:
            print(f"  ligne {n}\n    README   : {a}\n    exemple  : {b}")
            break
    else:
        print(f"  longueurs differentes : README {len(shown.splitlines())} "
              f"lignes, exemple {len(actual.splitlines())}")
    return 1


def check_scope(readme):
    """Les sections annoncees non implementees sont-elles celles du perimetre ?"""
    declared_in = ROOT / "requirements/perimeter.toml"
    if not declared_in.exists():
        # `requirements/` est le plan de travail local, pas un livrable. Sans
        # lui il n'y a rien a confronter, et le dire vaut mieux que de compter
        # un controle qui n'a pas eu lieu.
        print("note : requirements/perimeter.toml absent, le perimetre annonce "
              "par le README n'est pas confronte")
        return None
    perimeter = tomllib.loads(declared_in.read_text(encoding="utf-8"))
    declared = {s for block in perimeter["out_of_scope"]
                for s in block["sections"]}

    table = re.search(r"## What is implemented, and what is not(.*?)\n## ",
                      readme, re.S)
    if not table:
        print("aucune section de perimetre trouvee dans le README")
        return 1
    announced = set(re.findall(r"^\| §([0-9.]+?)[ |]", table.group(1), re.M))
    announced |= {s for row in re.findall(r"^\| §([0-9.]+)–§([0-9.]+)", table.group(1), re.M)
                  for s in row}

    # Le README regroupe des sections voisines ; ce qui compte est qu'il
    # n'annonce rien qui soit en perimetre, et n'en oublie aucune racine.
    lying = sorted(s for s in announced if s not in declared)
    if lying:
        print("le README annonce non implementees des sections que le "
              f"perimetre ne declare pas hors perimetre : {', '.join(lying)}")
        return 1

    roots = {s.split(".")[0] for s in declared}
    silent = sorted(r for r in roots
                    if not any(a.startswith(r) for a in announced)
                    and r not in {"2", "3", "4"})  # sous-sections d'interaction
    if silent:
        print("le perimetre exclut des sections que le README ne mentionne "
              f"pas : {', '.join(silent)}")
        return 1
    return 0


def main():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    transcript = check_transcript(readme)
    scope = check_scope(readme)
    failures = transcript + (scope or 0)
    if failures:
        print(f"{failures} incoherence(s)")
    else:
        print("Controles du README reussis : transcription, "
              + ("perimetre local" if scope is not None else "perimetre non verifie"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
