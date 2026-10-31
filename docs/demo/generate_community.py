#!/usr/bin/env python3
"""Render and privacy-check the isolated public demo GIF."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "docs" / "assets"
IMAGE = "ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93"


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--pull=never", *args],
        check=False, text=True, capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"VHS failed: {result.stderr.strip()}")
    return result.stdout


def validate(directory: Path) -> None:
    transcript = (directory / "demo.ascii").read_text(encoding="utf-8", errors="replace")
    for required in ("Demo · synthetic data", "scripted demo model", "What happened", "Approval", "Demo check"):
        if required not in transcript:
            raise ValueError(f"demo does not show {required}")
    for private in (str(Path.home()), getpass.getuser(), os.uname().nodename, "/home/", "/Users/", "C:\\Users\\", "api_key"):
        if private and private in transcript:
            raise ValueError("demo transcript contains an environment-specific value")
    gif = directory / "demo.gif"
    if not gif.is_file() or gif.stat().st_size >= 5_000_000:
        raise ValueError("demo GIF is missing or exceeds 5 MB")
    duration = float(docker(
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,src={directory},dst=/out,readonly",
        "--entrypoint", "ffprobe", IMAGE,
        "-v", "error", "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1", "/out/demo.gif",
    ).strip())
    if not 20 <= duration <= 30:
        raise ValueError(f"demo must last 20–30 seconds, got {duration:.2f}")


def main() -> None:
    if not (ROOT / "target/debug/irmind").is_file():
        raise SystemExit("build first: cargo build -p irmind --no-default-features --features keystore-file --locked")
    if "v0.11.0" not in docker("--entrypoint", "vhs", IMAGE, "--version"):
        raise ValueError("unexpected VHS version")
    with tempfile.TemporaryDirectory(prefix="irmind-community-demo-") as temporary:
        output = Path(temporary)
        docker(
            "--init", "--user", f"{os.getuid()}:{os.getgid()}",
            "--env", "HOME=/tmp/irmind-demo-home",
            "--mount", f"type=bind,src={ROOT},dst=/vhs,readonly",
            "--mount", f"type=bind,src={output},dst=/vhs/docs/assets",
            "--workdir", "/vhs", IMAGE, "docs/demo/community.tape",
        )
        validate(output)
        staged = ASSETS / ".demo-community.tmp"
        try:
            shutil.copyfile(output / "demo.gif", staged)
            staged.replace(ASSETS / "demo.gif")
        finally:
            staged.unlink(missing_ok=True)
    print("Regenerated the synthetic community demo; temporary files removed.")


if __name__ == "__main__":
    main()
