"""Offline regressions of source selection and quotation checking, not GNAP evidence."""

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_quotes", ROOT / "tools/check_quotes.py")
quotes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quotes)


class QuoteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, relative, text="// source\n"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def selected(self):
        return [str(path.relative_to(self.root)) for path in quotes.rust_sources(self.root)]

    def check(self, corpus):
        files = {number: self.write(f"rfc/{number}.txt", text) for number, text in corpus.items()}
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(quotes, "ROOT", self.root), mock.patch.object(quotes, "RFCS", files), \
                mock.patch.object(quotes, "fetch_missing") as fetch, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = quotes.main()
        fetch.assert_called_once_with(files)
        return result, output.getvalue(), errors.getvalue()

    def test_selects_nested_source_tests_examples_in_both_categories(self):
        expected = []
        for category in ("crates", "apps"):
            for source in ("src", "tests", "examples"):
                for name in ("root.rs", "nested/deeper/case.rs"):
                    path = f"{category}/sample/{source}/{name}"
                    self.write(path)
                    expected.append(path)
        self.assertEqual(self.selected(), expected)

    def test_usual_cargo_outputs_are_not_walked_and_non_rust_inputs_are_excluded(self):
        good = "apps/sample/src/nested/main.rs"
        self.write(good)
        for path in ("target/debug/build/output.rs", "apps/sample/target/debug/output.rs",
                     "crates/sample/target/src/output.rs", "apps/sample/fixtures/input.rs",
                     "crates/sample/tests/vector.json", "apps/sample/src/notes.txt",
                     "apps/sample/build.rs", "other/sample/src/outside.rs"):
            self.write(path)
        # Record directories actually visited, not just filtered output paths.
        original_walk = quotes.os.walk
        visited = []
        def walk(*args, **kwargs):
            for item in original_walk(*args, **kwargs):
                visited.append(Path(item[0]).relative_to(self.root).parts)
                yield item
        with mock.patch.object(quotes.os, "walk", side_effect=walk):
            self.assertEqual(self.selected(), [good])
        self.assertTrue(visited)
        self.assertTrue(all("target" not in parts for parts in visited))

    def test_fixture_target_vendor_and_external_names_do_not_hide_rust_modules(self):
        expected = []
        for category in ("crates", "apps"):
            for source in ("src", "tests", "examples"):
                for name in ("external", "fixtures", "target", "vendor"):
                    path = f"{category}/sample/{source}/{name}/helper.rs"
                    self.write(path)
                    self.write(f"{category}/sample/{source}/{name}/data.json")
                    expected.append(path)
        self.assertEqual(self.selected(), expected)

    def test_invalid_quote_under_source_target_is_not_ignored(self):
        self.write("crates/sample/src/target/helper.rs", '// RFC 9767: "This invented sentence does not exist anywhere."\n')
        result, output, _ = self.check({"9767": "The actual source says something different."})
        self.assertEqual(result, 1)
        self.assertIn("crates/sample/src/target/helper.rs:1: introuvable dans 9767", output)

    def test_invalid_quote_under_source_fixtures_is_not_ignored(self):
        self.write("apps/sample/src/fixtures/helper.rs", '// RFC 9767: "This invented sentence does not exist anywhere."\n')
        result, output, _ = self.check({"9767": "The actual source says something different."})
        self.assertEqual(result, 1)
        self.assertIn("apps/sample/src/fixtures/helper.rs:1: introuvable dans 9767", output)

    def test_does_not_follow_file_directory_package_or_source_symlinks(self):
        external = self.write("outside/source.rs")
        self.write("crates/real/src/main.rs")
        (self.root / "crates/real/src/linked.rs").symlink_to(external)
        (self.root / "crates/real/src/linked-dir").symlink_to(external.parent, target_is_directory=True)
        (self.root / "crates/linked-package").symlink_to(self.root / "crates/real", target_is_directory=True)
        (self.root / "crates/real/tests").symlink_to(external.parent, target_is_directory=True)
        (self.root / "apps").symlink_to(self.root / "crates", target_is_directory=True)
        self.assertEqual(self.selected(), ["crates/real/src/main.rs"])

    def test_unreadable_walk_is_not_silently_ignored(self):
        self.write("apps/sample/src/main.rs")
        def denied(*args, **kwargs):
            kwargs["onerror"](PermissionError("synthetic read failure"))
            return iter(())
        with mock.patch.object(quotes.os, "walk", side_effect=denied):
            with self.assertRaises(PermissionError):
                self.selected()

    def test_exact_quote_in_nested_app_is_checked(self):
        self.write("apps/sample/tests/nested/scenario.rs", '// RFC 9767 §3.3: "The AS MUST validate the access token value."\n')
        result, output, _ = self.check({"9767": "The AS MUST validate\n the access token value."})
        self.assertEqual(result, 0)
        self.assertIn("1 citations verifiees, 0 a corriger", output)

    def test_absent_quote_in_nested_crate_is_detected(self):
        self.write("crates/sample/src/nested/invalid.rs", '// RFC 9767: "This invented sentence does not exist anywhere."\n')
        result, output, _ = self.check({"9767": "The actual source says something different."})
        self.assertEqual(result, 1)
        self.assertIn("crates/sample/src/nested/invalid.rs:1: introuvable dans 9767", output)

    def test_misattributed_quote_is_not_accepted_from_another_rfc(self):
        text = "This synthetic quotation belongs to the other document."
        self.write("apps/sample/src/main.rs", f'// RFC 9635: "{text}"\n')
        result, output, _ = self.check({"9635": "Different source.", "9767": text})
        self.assertEqual(result, 1)
        self.assertIn("attribuee a 9635, le texte est dans 9767", output)
        self.assertIn("1 mal attribuee(s)", output)

    def test_explicit_ellipsis_preserves_fragment_order(self):
        path = self.write("apps/sample/examples/nested/example.rs", '// RFC 9767: "The first required fragment [...] and the final required fragment."\n')
        source = "The first required fragment, with additional context, and the final required fragment."
        self.assertEqual(self.check({"9767": source})[0], 0)
        path.write_text('// RFC 9767: "and the final required fragment [...] The first required fragment."\n')
        self.assertEqual(self.check({"9767": source})[0], 1)

    def test_code_fences_protocol_literals_and_short_fragments_are_not_prose_quotes(self):
        self.write("apps/sample/src/main.rs", '''//! RFC 9767
//! ```rust
//! let text = "Not a quotation of an RFC sentence";
//! ```
//! A protocol value `"some-field"` is not prose. Nor is "MUST NOT".
''')
        result, output, _ = self.check({"9767": "No quoted prose here."})
        self.assertEqual(result, 0)
        self.assertIn("0 citations verifiees", output)

    def test_missing_rfc_prevents_a_successful_verification(self):
        missing = {"9767": self.root / "rfc/missing.txt"}
        errors = io.StringIO()
        with mock.patch.object(quotes, "ROOT", self.root), mock.patch.object(quotes, "RFCS", missing), \
                mock.patch.object(quotes, "fetch_missing"), contextlib.redirect_stderr(errors):
            self.assertEqual(quotes.main(), 1)
        self.assertIn("RFC indisponibles", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
