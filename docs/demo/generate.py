#!/usr/bin/env python3
"""Regenerate the offline VHS demo and publish only validated image files."""

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
FILES = ("demo.gif", "conversation.png", "command-menu.png", "approval-card.png")
EXPECTED_FLOW = (
    "Demo CloudTrail alert",
    "Evidence ingested",
    "Commands",
    "IRMind · streaming",
    "Approval required",
    "TAINTED File",
    "example.com",
    "approval executed",
    "Verify: Verified",
    "audit entries",
)


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--pull=never", *args],
        check=True,
        text=True,
        capture_output=True,
    )


def validate_transcript(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [item for item in EXPECTED_FLOW if item not in text]
    if missing:
        raise ValueError(f"demo flow is incomplete: {', '.join(missing)}")
    personal = (
        str(Path.home()),
        getpass.getuser(),
        os.uname().nodename,
        "/home/",
        "/Users/",
        "C:\\Users\\",
        "Analyst key:",
        "analyst_key_fingerprint",
    )
    if any(value and value in text for value in personal):
        raise ValueError("demo capture contains a personal path, identity or key fingerprint")


def validate_images(directory: Path) -> None:
    for name in FILES:
        path = directory / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing demo image: {name}")
        if name.endswith(".png"):
            raw = path.read_bytes()[:24]
            if raw[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", raw[16:24]) != (
                1230,
                660,
            ):
                raise ValueError(f"wrong screenshot dimensions: {name}")
    gif = directory / "demo.gif"
    if gif.stat().st_size >= 5_000_000:
        raise ValueError("demo GIF exceeds 5 MB")
    probe = docker(
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,src={directory},dst=/out,readonly",
        "--entrypoint", "ffprobe", IMAGE,
        "-v", "error", "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1", "/out/demo.gif",
    )
    duration = float(probe.stdout.strip())
    if not 20 <= duration <= 30:
        raise ValueError(f"demo duration must be 20–30 seconds, got {duration:.2f}")


def install_images(directory: Path) -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        with tempfile.NamedTemporaryFile(prefix=".demo-", dir=ASSETS, delete=False) as item:
            staged = Path(item.name)
            try:
                with (directory / name).open("rb") as source:
                    shutil.copyfileobj(source, item)
                item.flush()
                os.fsync(item.fileno())
            except BaseException:
                staged.unlink(missing_ok=True)
                raise
        try:
            staged.replace(ASSETS / name)
        finally:
            staged.unlink(missing_ok=True)


def main() -> None:
    binary = ROOT / "target" / "debug" / "examples" / "demo"
    if not binary.is_file():
        raise SystemExit("build the fixture first: cargo build -p irmind --example demo --locked")
    example = ROOT / "examples" / "cloudtrail-alert.json"
    if hashlib.sha256(example.read_bytes()).hexdigest() != EXAMPLE_SHA256:
        raise ValueError("the demo example differs from the reviewed synthetic fixture")
    version = docker("--entrypoint", "vhs", IMAGE, "--version").stdout.strip()
    if "v0.11.0" not in version:
        raise ValueError(f"unexpected VHS version: {version}")
    with tempfile.TemporaryDirectory(prefix="irmind-demo-") as scratch:
        output = Path(scratch)
        result = docker(
            "--init", "--user", f"{os.getuid()}:{os.getgid()}",
            "--env", "HOME=/tmp/irmind-demo-home",
            "--mount", f"type=bind,src={ROOT},dst=/vhs,readonly",
            "--mount", f"type=bind,src={output},dst=/vhs/docs/assets",
            "--workdir", "/vhs", IMAGE, "docs/demo/demo.tape",
        )
        validate_transcript(output / "demo.ascii")
        validate_images(output)
        install_images(output)
        print("Generated synthetic demo: 20–30 s, <5 MB, three screenshots; privacy scan passed.")
        if result.stderr.strip():
            print(result.stderr.strip())


if __name__ == "__main__":
    main()
