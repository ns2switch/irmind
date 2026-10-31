"""Offline tests for the POSIX installer; no GitHub request or binary execution."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = (
    "awk", "basename", "chmod", "cp", "grep", "mkdir", "mktemp",
    "mv", "rm", "sha256sum", "uname",
)


class InstallerTests(unittest.TestCase):
    def run_installer(self, *, tamper: bool = False, verifiers: bool = False, failure: bool = False, old_gh: bool = False):
        with tempfile.TemporaryDirectory(prefix="irmind-installer-test-") as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            for name in TOOLS:
                source = shutil.which(name)
                if source is None:
                    self.skipTest(f"{name} is unavailable")
                (tools / name).symlink_to(source)
            fixture = root / "fixture"
            fixture.mkdir()
            binary = b"synthetic IRMind release binary; never executed\n"
            (fixture / "binary").write_bytes(binary)
            (fixture / "tampered").write_bytes(b"modified bytes\n")
            (fixture / "SHA256SUMS").write_text(
                f"{hashlib.sha256(binary).hexdigest()}  irmind-linux-x86_64\n",
                encoding="ascii",
            )
            (fixture / "releases.json").write_text('[{"tag_name":"v0.1.1"}]', encoding="ascii")
            (fixture / "bundle").write_text("{}", encoding="ascii")
            mock_curl = tools / "curl"
            mock_curl.write_text(
                "#!/bin/sh\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case $1 in --output) destination=$2; shift 2;; *) url=$1; shift;; esac\n"
                "done\n"
                "case $url in\n"
                "  *releases\\?*) source=releases.json;;\n"
                "  */SHA256SUMS) source=SHA256SUMS;;\n"
                "  *.sigstore.json) source=bundle;;\n"
                "  */irmind-linux-x86_64) source=${BINARY_FIXTURE:-binary};;\n"
                "  *) exit 8;;\n"
                "esac\n"
                "cp \"$FIXTURE_ROOT/$source\" \"$destination\"\n",
                encoding="ascii",
            )
            mock_curl.chmod(0o700)
            log = root / "verifications.log"
            if verifiers:
                for name in ("cosign", "gh"):
                    tool = tools / name
                    script = (
                        "#!/bin/sh\n"
                        "printf '%s %s\\n' \"$0\" \"$*\" >> \"$VERIFY_LOG\"\n"
                    )
                    if name == "gh" and old_gh:
                        script += "case $* in *--help*) exit 1;; esac\n"
                    script += "[ \"${VERIFY_FAIL:-0}\" != 1 ]\n"
                    tool.write_text(script, encoding="ascii")
                    tool.chmod(0o700)
            home = root / "home"
            home.mkdir()
            target = home / "bin"
            env = {
                "PATH": str(tools), "HOME": str(home), "TMPDIR": str(root),
                "FIXTURE_ROOT": str(fixture), "VERIFY_LOG": str(log),
                "BINARY_FIXTURE": "tampered" if tamper else "binary",
                "VERIFY_FAIL": "1" if failure else "0",
            }
            result = subprocess.run(
                ["/bin/sh", str(ROOT / "install.sh"), "latest", str(target)],
                env=env, capture_output=True, text=True, check=False,
            )
            installed = target / "irmind"
            self.assertEqual(installed.is_file(), not (tamper or failure), result.stderr)
            if installed.is_file():
                self.assertEqual(installed.read_bytes(), binary)
            self.assertEqual(list(root.glob("irmind-install.*")), [])
            return result, log.read_text() if log.exists() else ""

    def test_installs_only_after_matching_checksum(self):
        result, _ = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        result, _ = self.run_installer(tamper=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)

    def test_available_verifiers_are_called_and_failure_prevents_install(self):
        result, log = self.run_installer(verifiers=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.count("cosign verify-blob"), 2)
        self.assertIn(".github/workflows/ci.yml@refs/tags/v0.1.1", log)
        self.assertIn("gh attestation verify", log)
        result, _ = self.run_installer(verifiers=True, failure=True)
        self.assertNotEqual(result.returncode, 0)

    def test_old_gh_without_attestation_support_is_reported(self):
        result, log = self.run_installer(verifiers=True, old_gh=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install a current GitHub CLI", result.stderr)
        self.assertIn("gh attestation verify --help", log)
        self.assertNotIn("gh attestation verify /", log)


if __name__ == "__main__":
    unittest.main()
