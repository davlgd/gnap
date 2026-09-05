#!/usr/bin/env python3
"""Verifie que chaque citation de RFC dans le code est litterale.

Le code de ce projet cite abondamment les RFC, entre guillemets droits, pour
justifier ce qu'il fait. Une citation approximative est pire qu'aucune : elle
donne au lecteur l'autorite du texte normatif pour une phrase que le groupe de
travail n'a pas ecrite.

Cet outil extrait toute chaine entre guillemets d'un commentaire (`///` ou `//`)
qui se trouve dans un voisinage citant une RFC, et verifie qu'elle apparait mot
pour mot dans le texte de la RFC correspondante.

Les RFC sont formatees en colonnes : une citation est donc comparee apres
normalisation des espaces et des retours a la ligne, des deux cotes.

Usage : python3 tools/check_quotes.py
Sortie : 0 si tout est litteral, 1 sinon.
"""
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RFCS = {"9635": ROOT / "rfc/rfc9635.txt",
        "9767": ROOT / "rfc/rfc9767.txt",
        "9421": ROOT / "rfc/rfc9421.txt",
        "9530": ROOT / "rfc/rfc9530.txt",
        "9651": ROOT / "rfc/rfc9651.txt",
        "3986": ROOT / "rfc/rfc3986.txt",
        "7517": ROOT / "rfc/rfc7517.txt",
        "9493": ROOT / "rfc/rfc9493.txt"}

# Une citation courte n'en est pas une : « MUST » ou « no-store » se trouvent
# partout et ne pretendent rien.
MIN_WORDS = 5

QUOTE = re.compile(r'"([^"]{20,})"')
RFC_NEAR = re.compile(r"RFC (9635|9767|9421|9530|9651|3986|7517|9493)|§")


def fetch_missing(rfcs):
    """Telecharge les RFC absentes, plutot que de les ignorer en silence.

    Une citation qu'on ne peut pas verifier n'est pas une citation verifiee.
    Sur un clone frais, `rfc/` est vide : sans cela l'outil passerait au vert
    en n'ayant rien controle, ce qui est le pire des resultats.
    """
    for number, path in rfcs.items():
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://www.rfc-editor.org/rfc/rfc{number}.txt"
        print(f"telechargement de la RFC {number}…", file=sys.stderr)
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                path.write_bytes(response.read())
        except (urllib.error.URLError, OSError) as e:
            print(f"  echec : {e}", file=sys.stderr)


def flatten(text):
    """Un texte comparable.

    Deux normalisations, et pas une de plus :

      - les espaces, parce que les RFC sont formatees en colonnes et qu'un
        retour a la ligne ne change pas ce qui est dit ;
      - les backticks et les guillemets, parce que citer dans une chaine Rust
        interdit les guillemets et que la documentation met les noms de champs
        en `code`. Ni l'un ni l'autre n'est un mot du texte ;
      - la cesure de fin de ligne : le .txt coupe « security-sensitive » en
        « security- sensitive ». Le trait d'union est la, la coupure non ; et
        comme la normalisation s'applique des deux cotes, une citation qui
        contiendrait vraiment « - » se retrouve quand meme.

    Tout le reste est compare tel quel : un mot retire est un mot retire.
    """
    text = text.replace("`", "").replace('"', "")
    # Le .txt d'une RFC rend l'emphase du XML par des tirets bas : « the
    # _approved_ state ». C'est un artefact de rendu, pas un mot.
    text = re.sub(r"(?<![\w])_([A-Za-z]+)_(?![\w])", r"\1", text)
    text = " ".join(text.split())
    return re.sub(r"(\w)- (\w)", r"\1-\2", text)


def comment_blocks(path):
    """(numero de ligne, texte) pour chaque bloc de commentaires contigu."""
    lines = path.read_text(encoding="utf-8").splitlines()
    block, start, in_example = [], 0, False
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("///", "//!", "//")):
            body = re.sub(r"^(///|//!|//)\s?", "", stripped)
            # Un exemple de doc est du code, pas de la prose : ses chaines ne
            # pretendent rien citer.
            if body.strip().startswith("```"):
                in_example = not in_example
                continue
            if in_example:
                continue
            if not block:
                start = n
            block.append(body)
        elif block:
            in_example = False
            yield start, " ".join(block)
            block = []
    if block:
        yield start, " ".join(block)


def main():
    fetch_missing(RFCS)
    corpus = {n: flatten(p.read_text(encoding="utf-8")) for n, p in RFCS.items()
              if p.exists()}
    missing = sorted(n for n, p in RFCS.items() if not p.exists())
    if missing:
        # Sans le texte, l'outil ne peut rien affirmer. Il le dit et echoue,
        # plutot que d'annoncer un vert qu'il n'a pas verifie.
        print(f"RFC indisponibles, verification impossible : {', '.join(missing)}",
              file=sys.stderr)
        return 1
    if not corpus:
        print("aucune RFC en local : rien a verifier", file=sys.stderr)
        return 0

    checked = bad = misattributed = 0
    for path in sorted(ROOT.glob("crates/*/src/*.rs")) + \
            sorted(ROOT.glob("crates/*/tests/*.rs")) + \
            sorted(ROOT.glob("crates/*/examples/*.rs")):
        for line, block in comment_blocks(path):
            if not RFC_NEAR.search(block):
                continue
            # Une chaine dans un span de code (`"@method"`) est un litteral du
            # protocole, pas une citation ; ses guillemets ne doivent pas
            # s'apparier avec ceux de la prose voisine.
            block = re.sub(r"`[^`]*`", lambda m: m.group(0).replace('"', ""), block)
            named = set(re.findall(r"RFC (9635|9767|9421|9530|9651|3986|7517|9493)", block))
            for quote in QUOTE.findall(block):
                # Les guillemets refermes sur du code (`"no-store"`) ou une
                # valeur de champ ne sont pas des citations de prose.
                if len(quote.split()) < MIN_WORDS:
                    continue
                # Une elision explicite est honnete : chaque fragment doit se
                # retrouver, dans l'ordre, ce qui laisse passer « a [...] b »
                # et refuse « a b » quand le texte dit « a c b ».
                parts = [flatten(f) for f in re.split(r"\[\.\.\.\]|\[…\]",
                                                     quote.rstrip(". "))]
                parts = [f for f in parts if f]
                where = named or set(corpus)
                if named and not (named & set(corpus)):
                    continue  # cite une RFC qu'on n'a pas : rien a affirmer
                checked += 1

                def found(rfc, parts=parts):
                    at = 0
                    for fragment in parts:
                        at = corpus[rfc].find(fragment, at)
                        if at < 0:
                            return False
                        at += len(fragment)
                    return True

                if any(found(n) for n in where if n in corpus):
                    continue

                # Introuvable la ou le commentaire renvoie. Deux cas tres
                # differents : le texte existe ailleurs — le commentaire cite la
                # mauvaise RFC — ou il n'existe nulle part, et alors la citation
                # est inventee.
                needle = " [...] ".join(parts)
                elsewhere = sorted(n for n in corpus if n not in where and found(n))
                rel = path.relative_to(ROOT)
                bad += 1
                if elsewhere:
                    misattributed += 1
                    print(f"{rel}:{line}: attribuee a {'/'.join(sorted(where))}, "
                          f"le texte est dans {'/'.join(elsewhere)}")
                else:
                    print(f"{rel}:{line}: introuvable dans "
                          f"{'/'.join(sorted(where))}")
                print(f"    « {needle[:110]}{'…' if len(needle) > 110 else ''} »")

    print(f"\n{checked} citations verifiees, {bad} a corriger "
          f"({bad - misattributed} introuvable(s), {misattributed} mal attribuee(s))")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
