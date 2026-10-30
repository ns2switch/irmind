#!/usr/bin/env python3
"""Capture the synthetic TUI screens with pinned, offline VHS."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
IMAGE = (
    "ghcr.io/charmbracelet/vhs@"
    "sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93"
)
PNG = ("new.png", "remote.png", "modules.png", "config.png", "case.png")


def capture(tape: str, expected: tuple[str, ...], text_marker: str, scratch: Path) -> None:
    command = [
        "docker", "run", "--rm", "--init", "--network", "none", "--pull=never",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--env", "HOME=/tmp/irmind-capture-home",
        "--mount", f"type=bind,src={ROOT},dst=/vhs,readonly",
        "--mount", f"type=bind,src={scratch},dst=/vhs/docs/ux/recent-case-and-forms/after",
        "--workdir", "/vhs", IMAGE,
        f"docs/ux/recent-case-and-forms/{tape}",
    ]
    for _ in range(3):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        transcript = scratch / tape.replace(".tape", ".ascii")
        if (
            result.returncode == 0
            and all((scratch / name).is_file() for name in expected)
            and transcript.is_file()
            and text_marker in transcript.read_text(encoding="utf-8", errors="replace")
        ):
            return
    available = ", ".join(sorted(path.name for path in scratch.iterdir()))
    raise RuntimeError(f"VHS capture failed: {tape}; files: {available}; {result.stderr[-500:]}")


def validate(scratch: Path) -> None:
    transcript = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in scratch.glob("*.ascii")
    )
    for value in (
        str(Path.home()), getpass.getuser(), os.uname().nodename,
        "/home/", "/Users/", "C:\\Users\\", "Analyst key:",
    ):
        if value and value in transcript:
            raise ValueError("capture contains a personal path, identity, or key")
    for label in (
        "Remote scope", "Resume the most recent open case on startup: on",
        "Resumed · /home to view all cases", "Missing: model",
    ):
        if label not in transcript:
            raise ValueError(f"capture omits {label}")
    for name in PNG:
        raw = (scratch / name).read_bytes()[:24]
        if raw[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", raw[16:24]) != (1230, 660):
            raise ValueError(f"invalid screenshot: {name}")


def main() -> None:
    binary = ROOT / "target/debug/examples/demo"
    if not binary.is_file():
        raise SystemExit("build the fixture: cargo build -p irmind --example demo --locked")
    with tempfile.TemporaryDirectory(prefix="irmind-ux-") as directory:
        scratch = Path(directory)
        capture("forms.tape", PNG[:4], "Resume the most recent open case on startup: on", scratch)
        capture("resumed.tape", PNG[4:], "Resumed · /home to view all cases", scratch)
        validate(scratch)
        for name in PNG:
            shutil.copyfile(scratch / name, HERE / "after" / name)
    print("Synthetic before/after captures regenerated; temporary files removed.")


if __name__ == "__main__":
    main()
