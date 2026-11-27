"""Run the staged release verifier on both portable synthetic Sigma cases."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def expected_digest(path):
    value = path.read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"invalid SHA-256 in {path.name}")
    return value


def verify(executable, directory):
    archive = directory / "sigma-report-v12.irmind"
    expected = expected_digest(directory / "archive-sha256.txt")
    key = expected_digest(directory / "expected-key.txt")
    if sha256(archive) != expected:
        raise ValueError("the received archive differs from the Linux export")
    with archive.open("rb") as source:
        if source.read(len(b"IRMIND-EXPORT-V12\0")) != b"IRMIND-EXPORT-V12\0":
            raise ValueError("expected a V12 archive")

    with tempfile.TemporaryDirectory() as scratch:
        home = Path(scratch) / "unused"
        base = [str(executable), "--home", str(home), "verify-export", str(archive)]
        result = subprocess.run(
            [*base, "--expected-key", key],
            check=True, capture_output=True, text=True, timeout=60,
        )
        if f"analyst key fingerprint {key}" not in result.stdout or home.exists():
            raise ValueError("verification did not report the expected key without a vault")
        wrong_key = ("1" if key[0] == "0" else "0") + key[1:]
        rejected = subprocess.run(
            [*base, "--expected-key", wrong_key],
            capture_output=True, text=True, timeout=60,
        )
        if rejected.returncode == 0 or "fingerprint" not in rejected.stderr.lower():
            raise ValueError("verification did not reject the wrong key")
        changed = Path(scratch) / "changed.irmind"
        shutil.copyfile(archive, changed)
        with changed.open("r+b") as output:
            output.seek(-1, os.SEEK_END)
            byte = output.read(1)
            output.seek(-1, os.SEEK_END)
            output.write(bytes([byte[0] ^ 1]))
        rejected = subprocess.run(
            [*base[:-1], str(changed), "--expected-key", key],
            capture_output=True, text=True, timeout=60,
        )
        if rejected.returncode == 0 or home.exists():
            raise ValueError("verification accepted the altered archive or created a vault")
        print(result.stdout.strip())

    message = f"Linux {directory.name} export verified on {os.environ.get('RUNNER_OS', os.name)} ({expected})."
    print(message)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as report:
            report.write(f"{message}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("artifact", type=lambda path: Path(path).resolve(strict=True))
    options = parser.parse_args()
    for scenario in ("cloudtrail", "windows"):
        verify(options.executable, options.artifact / scenario)
