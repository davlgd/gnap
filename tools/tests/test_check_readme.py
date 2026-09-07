"""Regression tests for the published grant transcript check."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "check_readme", Path(__file__).resolve().parents[1] / "check_readme.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def guide(output="A grant happens.\n", locked=False):
    return "```console\n$ cargo run -p gnap-as --example flow" + (
        " --locked" if locked else "") + "\n\n" + output + "```\n"


class WalkthroughTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_matching_output_accepts_both_documented_command_forms(self):
        for locked in (False, True):
            with self.subTest(locked=locked), patch.object(
                    checker.subprocess, "run", return_value=subprocess.CompletedProcess(
                        [], 0, stdout="A grant happens.\n")) as run:
                self.assertEqual(checker.check_transcript(guide(locked=locked)), 0)
                self.assertIn("--locked", run.call_args.args[0])
                self.assertEqual(run.call_args.kwargs["cwd"], checker.ROOT)
                self.assertEqual(run.call_args.kwargs["timeout"], 300)

    def test_missing_or_duplicate_transcripts_fail_without_running_cargo(self):
        for document in ("No transcript", guide() + guide()):
            with self.subTest(document=document), patch.object(checker.subprocess, "run") as run:
                self.assertEqual(checker.check_transcript(document), 1)
                run.assert_not_called()

    def test_changed_or_truncated_output_is_rejected(self):
        for output in ("Different\n", "A grant happens.\nMore output\n", ""):
            with self.subTest(output=output), patch.object(
                    checker.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=output)):
                self.assertEqual(checker.check_transcript(guide()), 1)

    def test_whitespace_normalization_does_not_reorder_lines(self):
        self.assertEqual(checker.flatten("\nfirst  \nsecond\n"), "first\nsecond")
        self.assertNotEqual(checker.flatten("second\nfirst"), "first\nsecond")

    def test_process_failures_are_not_reported_as_a_match(self):
        with patch.object(checker.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 1, stdout="A grant happens.\n", stderr="private build context")):
            self.assertEqual(checker.check_transcript(guide()), 1)
        for error in (OSError("private path"), subprocess.TimeoutExpired("cargo", 300)):
            with self.subTest(error=type(error).__name__), patch.object(checker.subprocess, "run", side_effect=error):
                self.assertEqual(checker.check_transcript(guide()), 1)
        self.assertNotIn("private", self.output.getvalue())

    def test_main_reads_the_public_guide_and_not_local_scope_notes(self):
        with patch.object(Path, "read_text", autospec=True, return_value=guide()) as read, \
                patch.object(checker, "check_transcript", return_value=0) as check:
            self.assertEqual(checker.main(), 0)
        self.assertEqual(read.call_args.args[0], checker.ROOT / "docs/getting-started.md")
        check.assert_called_once_with(guide())


if __name__ == "__main__":
    unittest.main()
