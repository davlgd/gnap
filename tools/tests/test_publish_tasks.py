"""Check publication-task boundaries without executing mise or Cargo."""

from pathlib import Path
import shlex
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PublishTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tasks"]

    def test_dry_run_cannot_invoke_an_upload_or_a_dependency_task(self):
        task = self.tasks["publish:dry-run"]
        self.assertEqual(set(task), {"description", "dir", "run"})
        self.assertEqual(task["dir"], "{{ config_root }}")
        self.assertEqual(shlex.split(task["run"]), [
            "cargo", "publish", "--workspace", "--registry", "crates-io", "--locked", "--dry-run"])

    def test_publication_is_explicit_and_confirmation_defaults_to_no(self):
        task = self.tasks["publish"]
        self.assertEqual(set(task), {"description", "dir", "confirm", "run"})
        self.assertEqual(task["dir"], "{{ config_root }}")
        self.assertEqual(task["confirm"]["default"], "no")
        self.assertIn("crates.io", task["confirm"]["message"])
        self.assertEqual(shlex.split(task["run"]), [
            "cargo", "publish", "--workspace", "--registry", "crates-io", "--locked"])


if __name__ == "__main__":
    unittest.main()
