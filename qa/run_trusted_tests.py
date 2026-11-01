#!/usr/bin/env python3
"""Controller-owned FPF test suite and isolated Candidate test launcher.

The trusted checks never delegate their decision to Candidate tests. In
Candidate mode, the exact target and full regression suites are also executed
as supporting evidence inside the Controller's network-disabled container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Callable


def files_under(root: Path) -> list[str]:
    result: list[str] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            item = Path(current) / name
            rel = item.relative_to(root)
            if ".." in rel.parts:
                raise ValueError(f"path traversal component in {rel}")
            mode = item.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ValueError(f"symbolic link forbidden: {rel}")
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError(f"non-regular file forbidden: {rel}")
        for name in files:
            result.append((Path(current) / name).relative_to(root).as_posix())
    return result


class TrustedSuite:
    def __init__(self, candidate: Path, spec: dict[str, object]):
        self.candidate = candidate.resolve()
        self.spec = spec
        self.results: list[dict[str, object]] = []

    def run(self, name: str, check: Callable[[], str | tuple[str, dict]]) -> None:
        try:
            outcome = check()
            if isinstance(outcome, tuple):
                detail, metrics = outcome
            else:
                detail = outcome
                metrics = {}
            self.results.append(
                {
                    "name": name,
                    "status": "PASS",
                    "exit_code": 0,
                    "detail": detail,
                    "metrics": metrics,
                }
            )
        except Exception as exc:
            self.results.append(
                {
                    "name": name,
                    "status": "FAIL",
                    "exit_code": 1,
                    "detail": str(exc),
                    "metrics": {},
                }
            )

    def candidate_sha_binding(self) -> str:
        expected = str(self.spec["candidate_sha"]).lower()
        if not re.fullmatch(r"[0-9a-f]{40}", expected):
            raise ValueError("spec candidate_sha is not a 40-character Git SHA")
        expected_tree = str(self.spec.get("source_tree_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_tree):
            raise ValueError("spec source_tree_sha256 is not a SHA-256 digest")
        items = files_under(self.candidate)
        if len(items) > int(self.spec["max_total_files"]):
            raise ValueError("candidate file count exceeds trust limit")
        digest = hashlib.sha256()
        for rel in items:
            path = self.candidate / rel
            if path.stat().st_size > int(self.spec["max_file_size_bytes"]):
                raise ValueError(f"candidate file exceeds size limit: {rel}")
            digest.update(rel.encode("utf-8") + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        actual_tree = digest.hexdigest()
        if actual_tree != expected_tree:
            raise ValueError("candidate source-tree digest mismatch")
        return f"candidate SHA {expected} bound to source tree {actual_tree}"

    def allowed_paths_only(self) -> str:
        actual = sorted(files_under(self.candidate))
        allowed = {str(item) for item in self.spec["allowed_paths"]}
        if self.spec.get("mode") == "synthetic":
            unexpected = [item for item in actual if item not in allowed]
            if unexpected:
                raise ValueError(f"unexpected synthetic candidate paths: {unexpected}")
            missing = sorted(allowed - set(actual))
            if missing:
                raise ValueError(f"required synthetic candidate paths missing: {missing}")
            return f"exact synthetic allowed-path set: {actual}"

        changed_value = self.spec.get("changed_files")
        if not isinstance(changed_value, list):
            raise ValueError("admission specification lacks changed_files")
        changed = sorted(str(item) for item in changed_value)
        unexpected = [item for item in changed if item not in allowed]
        if unexpected:
            raise ValueError(f"changed paths outside allowlist: {unexpected}")
        missing = sorted(allowed - set(changed))
        if missing:
            raise ValueError(f"required allowed paths not changed: {missing}")
        for rel in allowed:
            if rel not in actual:
                raise ValueError(f"required candidate path missing: {rel}")
        return f"exact allowed changed-file set: {changed}"

    def no_symlinks_or_traversal(self) -> str:
        items = files_under(self.candidate)
        if len(items) > int(self.spec["max_total_files"]):
            raise ValueError("candidate file count exceeds trust limit")
        for rel in items:
            path = self.candidate / rel
            if path.stat().st_size > int(self.spec["max_file_size_bytes"]):
                raise ValueError(f"candidate file exceeds size limit: {rel}")
        return f"no symlinks or traversal across {len(items)} files"

    def protocol_required_sections(self) -> str:
        rel = "docs/coordination/SELF-HOSTING-PROTOCOL.md"
        text = (self.candidate / rel).read_text(encoding="utf-8")
        missing = [phrase for phrase in self.spec["protocol_required_phrases"] if phrase not in text]
        if missing:
            raise ValueError(f"protocol missing required phrases: {missing}")
        return f"protocol contains all {len(self.spec['protocol_required_phrases'])} required phrases"

    def protected_policy_contains_protocol(self) -> str:
        rel = "packages/fpf_policy/protected.py"
        text = (self.candidate / rel).read_text(encoding="utf-8").lower()
        missing = [
            marker.lower()
            for marker in self.spec["protected_policy_markers"]
            if marker.lower() not in text
        ]
        if missing:
            raise ValueError(f"protected policy missing markers: {missing}")
        return "protected policy contains the self-hosting protocol path"

    def policy_test_required(self) -> str:
        rel = "tests/test_self_hosting_policy.py"
        text = (self.candidate / rel).read_text(encoding="utf-8")
        missing = [marker for marker in self.spec["policy_test_markers"] if marker not in text]
        if missing:
            raise ValueError(f"policy test missing markers: {missing}")
        return "policy test contains protected-path and protocol assertions"

    def candidate_unittest_suite(
        self,
        args: list[str],
        expected_count: int,
    ) -> tuple[str, dict[str, int]]:
        """Run one Candidate unittest command and verify its raw exit/output."""
        if expected_count <= 0:
            raise ValueError("expected Candidate test count must be positive")
        timeout_seconds = int(self.spec.get("candidate_test_timeout_seconds", 1200))
        env = {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(self.candidate),
            "TMPDIR": "/tmp",
        }
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC"):
            if os.environ.get(key):
                env[key] = os.environ[key]
        completed = subprocess.run(
            [sys.executable, *args],
            cwd=self.candidate,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        combined = completed.stdout + "\n" + completed.stderr
        print("=== Candidate unittest stdout begin ===")
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
        print("=== Candidate unittest stdout end ===")
        if completed.stderr:
            print("=== Candidate unittest stderr begin ===")
            print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n")
            print("=== Candidate unittest stderr end ===")

        counts = list(re.finditer(r"^Ran (\d+) tests? in ", combined, flags=re.MULTILINE))
        if not counts:
            raise ValueError("unittest output did not report an executed test count")
        executed = int(counts[-1].group(1))

        def count_label(label: str) -> int:
            match = re.search(rf"{label}=(\d+)", combined)
            return int(match.group(1)) if match else 0

        failures = count_label("failures")
        errors = count_label("errors")
        skipped = count_label("skipped")
        unexpected_successes = count_label("unexpected successes")
        if completed.returncode != 0:
            raise ValueError(f"unittest exited {completed.returncode}")
        if executed != expected_count:
            raise ValueError(
                f"unittest executed {executed} tests, expected exactly {expected_count}"
            )
        if failures or errors or skipped or unexpected_successes:
            raise ValueError(
                "unittest reported non-clean results: "
                f"failures={failures}, errors={errors}, skipped={skipped}, "
                f"unexpected_successes={unexpected_successes}"
            )
        if not re.search(r"^OK(?: \(|$)", combined, flags=re.MULTILINE):
            raise ValueError("unittest output lacks a clean OK result")
        return (
            f"unittest executed exactly {executed} tests with exit code 0",
            {
                "executed": executed,
                "failures": failures,
                "errors": errors,
                "skipped": skipped,
                "unexpected_successes": unexpected_successes,
            },
        )

    def candidate_target_suite(self) -> tuple[str, dict[str, int]]:
        module = str(
            self.spec.get(
                "candidate_target_test_module",
                "tests.test_self_hosting_policy",
            )
        )
        expected = int(self.spec.get("candidate_target_test_count", 8))
        return self.candidate_unittest_suite(["-m", "unittest", "-v", module], expected)

    def candidate_full_regression_suite(self) -> tuple[str, dict[str, int]]:
        pattern = str(self.spec.get("candidate_full_test_pattern", "test_*.py"))
        expected = int(self.spec.get("candidate_full_regression_test_count", 188))
        return self.candidate_unittest_suite(
            ["-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"],
            expected,
        )

    def execute(self) -> None:
        self.run("candidate_sha_binding", self.candidate_sha_binding)
        self.run("allowed_paths_only", self.allowed_paths_only)
        self.run("no_symlinks_or_traversal", self.no_symlinks_or_traversal)
        self.run("protocol_required_sections", self.protocol_required_sections)
        self.run("protected_policy_contains_protocol", self.protected_policy_contains_protocol)
        self.run("policy_test_required", self.policy_test_required)
        if self.spec.get("mode") == "candidate":
            self.run("candidate_target_suite", self.candidate_target_suite)
            self.run("candidate_full_regression_suite", self.candidate_full_regression_suite)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    expected_tests = list(spec.get("expected_tests") or [])
    if not expected_tests:
        raise SystemExit("trusted specification contains no expected tests")

    suite = TrustedSuite(args.candidate, spec)
    suite.execute()

    output = {
        "schema": "fpf-trusted-test-results-v1",
        "task_id": spec["task_id"],
        "controller_repo": spec["controller_repo"],
        "controller_sha": spec["controller_sha"],
        "candidate_repo": spec["candidate_repo"],
        "candidate_sha": spec["candidate_sha"],
        "source_tree_sha256": spec["source_tree_sha256"],
        "test_count": len(suite.results),
        "skipped_count": sum(1 for item in suite.results if item["status"] == "SKIP"),
        "failed_count": sum(1 for item in suite.results if item["status"] != "PASS"),
        "tests": suite.results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Controller suite completed: {len(suite.results)} tests executed")
    for item in suite.results:
        print(f"[{item['status']}] {item['name']}: {item['detail']}")
    return 0 if output["failed_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
