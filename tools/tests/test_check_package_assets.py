"""Offline tests for package asset checks; no Cargo or registry access."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "check_package_assets", Path(__file__).resolve().parents[1] / "check_package_assets.py")
assets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets)


class PackageAssetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_fixture_bytes_must_match_including_final_newlines(self):
        (self.root / "canonical").write_bytes(b"fixture\n")
        (self.root / "copy").write_bytes(b"fixture\n")
        mapping = {"copy": "canonical"}
        self.assertEqual(assets.check_copies(self.root, mapping), [])
        (self.root / "copy").write_bytes(b"fixture")
        self.assertEqual(len(assets.check_copies(self.root, mapping)), 1)

    def test_missing_and_escaping_files_are_refused(self):
        for name in ("missing", "../outside"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                assets.inside(self.root, name)

    def test_symlink_to_an_external_file_is_refused(self):
        with tempfile.TemporaryDirectory() as external:
            file = Path(external) / "fixture"
            file.write_bytes(b"test")
            (self.root / "linked").symlink_to(file)
            with self.assertRaises(ValueError):
                assets.inside(self.root, "linked")

    def crate(self):
        crate = self.root / "gnap-example"
        (crate / "src").mkdir(parents=True)
        (crate / "README.md").write_text("# Example\n")
        (crate / "LICENSE").write_text("Test license\n")
        (crate / "Cargo.toml").write_text(
            '[package]\nreadme="README.md"\n'
            'documentation="https://docs.rs/gnap-example"\nlicense.workspace=true\n')
        return crate

    def test_embedded_assets_cannot_escape_the_crate(self):
        crate = self.crate()
        (crate / "src/local").write_text("fixture")
        source = crate / "src/lib.rs"
        source.write_text('const A: &str = include_str!("local");\n')
        self.assertEqual(assets.check_crate(crate), [])
        (self.root / "outside").write_text("fixture")
        source.write_text('const A: &str = include_str!("../../outside");\n')
        self.assertEqual(len(assets.check_crate(crate)), 1)

    def test_metadata_needs_a_local_readme_and_docs_url(self):
        crate = self.crate()
        (crate / "Cargo.toml").write_text('[package]\nreadme="../../README.md"\n')
        self.assertEqual(len(assets.check_crate(crate)), 3)


if __name__ == "__main__":
    unittest.main()
