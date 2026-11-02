#!/usr/bin/env python3
"""Capture the offline tutorial with the pinned VHS image and disposable files."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
IMAGE = (
    "ghcr.io/charmbracelet/vhs@"
    "sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93"
)
IMAGES = ("welcome.png", "evidence.png", "explore.png", "approval.png", "custody.png")


def main() -> None:
    if not (TARGET / "debug" / "irmind").is_file():
        raise SystemExit("Build the local binary first: cargo build -p irmind --locked")
    with tempfile.TemporaryDirectory(prefix="irmind-demo-guide-") as disposable:
        output = Path(disposable)
        command = [
            "docker", "run", "--rm", "--network", "none", "--pull=never",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--mount", f"type=bind,src={ROOT},dst=/vhs,readonly",
            "--mount", f"type=bind,src={TARGET},dst=/vhs/target,readonly",
            "--mount", f"type=bind,src={output},dst=/out",
            "--workdir", "/vhs", IMAGE, "docs/ux/demo-guide/capture.tape",
        ]
        subprocess.run(command, check=True)
        transcript = (output / "preview.ascii").read_text(errors="replace")
        for private in (str(Path.home()), getpass.getuser(), os.uname().nodename):
            if private and private in transcript:
                raise ValueError("a screenshot transcript contains a personal identifier")
        for image in IMAGES:
            source = output / image
            if not source.is_file() or source.stat().st_size == 0:
                names = ", ".join(sorted(path.name for path in output.iterdir()))
                raise ValueError(f"missing tutorial screenshot: {image}; captured: {names}")
            with tempfile.NamedTemporaryFile(dir=HERE, prefix=".capture-", delete=False) as item:
                staged = Path(item.name)
            try:
                shutil.copyfile(source, staged)
                staged.replace(HERE / image)
            finally:
                staged.unlink(missing_ok=True)
    print("Captured five synthetic tutorial screens; disposable files removed.")


if __name__ == "__main__":
    main()
