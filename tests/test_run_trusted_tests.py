from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from qa.run_trusted_tests import TrustedSuite


class CandidateSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.spec = {
            "candidate_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "max_total_files": 10,
            "max_file_size_bytes": 1024,
            "candidate_test_timeout_seconds": 10,
        }
        self.suite = TrustedSuite(Path(self.temp.name), self.spec)

    def test_exact_clean_unittest_result_is_accepted(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="\n----------------------------------------------------------------------\n"
            "Ran 8 tests in 0.100s\n\nOK\n",
            stderr="",
        )
        with patch("qa.run_trusted_tests.subprocess.run", return_value=completed):
            detail, metrics = self.suite.candidate_unittest_suite(
                ["-m", "unittest", "tests.test_self_hosting_policy"],
                8,
            )
        self.assertIn("exactly 8", detail)
        self.assertEqual(metrics["executed"], 8)
        self.assertEqual(metrics["failures"], 0)
        self.assertEqual(metrics["errors"], 0)
        self.assertEqual(metrics["skipped"], 0)

    def test_wrong_test_count_fails_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="Ran 1 test in 0.010s\n\nOK\n",
            stderr="",
        )
        with patch("qa.run_trusted_tests.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "expected exactly 8"):
                self.suite.candidate_unittest_suite(
                    ["-m", "unittest", "tests.test_self_hosting_policy"],
                    8,
                )

    def test_skipped_tests_fail_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="Ran 8 tests in 0.100s\n\nOK (skipped=1)\n",
            stderr="",
        )
        with patch("qa.run_trusted_tests.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "skipped=1"):
                self.suite.candidate_unittest_suite(
                    ["-m", "unittest", "tests.test_self_hosting_policy"],
                    8,
                )


if __name__ == "__main__":
    unittest.main()
