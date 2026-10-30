#!/usr/bin/env python3
"""Render the current TUI demo from synthetic, offline inputs only."""

from __future__ import annotations

import getpass
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "docs" / "assets"
IMAGE = (
    "ghcr.io/charmbracelet/vhs@"
    "sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93"
)
EXAMPLE_SHA256 = "0b7f3a97647d64d5d917b09002f069f2cf15a058ea2406bceaf2d5fe5f02d055"
FILES = (
    "demo.gif", "resumed.png", "home.png", "model.png", "modules.png",
    "new.png", "command-menu.png", "conversation.png", "approval-card.png",
    "settings.png", "keystore.png", "preferences.png",
)
EXPECTED_FLOW = (
    "Resumed · /home to view all cases",
    "Recent cases",
    "Settings",
    "Model setup",
    "Connectors",
    "Keystore",
    "Preferences",
    "New case",
    "Demo CloudTrail alert",
    "Evidence ingested",
    "Commands",
    "⏺ The synthetic record",
    "Approval required",
    "UNTRUSTED",
    "example.com",
    "1. Approve",
    "2. Deny with reason",
    "3. Edit arguments",
    "approval executed",
    "Verify: Verified",
    "audit entries",
)


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--pull=never", *args],
        check=False, text=True, capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"VHS container failed: {result.stderr.strip()}")
    return result.stdout


def validate(directory: Path) -> None:
    transcript = (directory / "demo.ascii").read_text(encoding="utf-8", errors="replace")
    missing = [phrase for phrase in EXPECTED_FLOW if phrase not in transcript]
    if missing:
        raise ValueError(f"demo flow is incomplete: {', '.join(missing)}")
    for value in (
        str(Path.home()), getpass.getuser(), os.uname().nodename,
        "/home/", "/Users/", "C:\\Users\\",
        "analyst_key_fingerprint",
    ):
        if value and value in transcript:
            raise ValueError("demo contains a personal path, identity, or key fingerprint")
    if any("Analyst key:" in line and "Analyst key: ephemeral demo key" not in line
           for line in transcript.splitlines()):
        raise ValueError("demo contains an unreviewed analyst fingerprint")
    for name in FILES:
        path = directory / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing demo image: {name}")
        if name.endswith(".png"):
            raw = path.read_bytes()[:24]
            if raw[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", raw[16:24]) != (1230, 660):
                raise ValueError(f"wrong screenshot dimensions: {name}")
    gif = directory / "demo.gif"
    if gif.stat().st_size >= 5_000_000:
        raise ValueError("demo GIF exceeds 5 MB")
    duration = float(docker(
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,src={directory},dst=/out,readonly",
        "--entrypoint", "ffprobe", IMAGE,
        "-v", "error", "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1", "/out/demo.gif",
    ).strip())
    if not 20 <= duration <= 30:
        raise ValueError(f"demo duration must be 20–30 seconds, got {duration:.2f}")


def install(source: Path, destination: Path) -> None:
    with tempfile.NamedTemporaryFile(prefix=".demo-", dir=destination.parent, delete=False) as item:
        staged = Path(item.name)
        try:
            with source.open("rb") as input_file:
                shutil.copyfileobj(input_file, item)
            item.flush()
            os.fsync(item.fileno())
        except BaseException:
            staged.unlink(missing_ok=True)
            raise
    try:
        staged.replace(destination)
    finally:
        staged.unlink(missing_ok=True)


def main() -> None:
    binary = ROOT / "target/debug/examples/demo"
    if not binary.is_file():
        raise SystemExit("build the fixture: cargo build -p irmind --example demo --locked")
    example = ROOT / "examples/cloudtrail-alert.json"
    if hashlib.sha256(example.read_bytes()).hexdigest() != EXAMPLE_SHA256:
        raise ValueError("the synthetic example differs from the reviewed fixture")
    if "v0.11.0" not in docker("--entrypoint", "vhs", IMAGE, "--version"):
        raise ValueError("unexpected VHS version")
    with tempfile.TemporaryDirectory(prefix="irmind-demo-") as directory:
        output = Path(directory)
        docker(
            "--init", "--user", f"{os.getuid()}:{os.getgid()}",
            "--env", "HOME=/tmp/irmind-demo-home",
            "--mount", f"type=bind,src={ROOT},dst=/vhs,readonly",
            "--mount", f"type=bind,src={output},dst=/vhs/docs/assets",
            "--workdir", "/vhs", IMAGE, "docs/demo/demo.tape",
        )
        validate(output)
        for name in FILES:
            install(output / name, ASSETS / name)
    print("Generated the synthetic TUI GIF and screenshots; temporary files removed.")


if __name__ == "__main__":
    main()
