#!/usr/bin/env python3
"""Pinned source/checksum and exact-score helpers for the manual benchmark.

Execution is in hunteval_benchmark.py; these helpers never call a model.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

PINNED_COMMIT = "4cbb555a56bc17cb03b988ad2f15b1374eecf183"


def verify_checksum(root: Path, relative: Path) -> None:
    checksum_file = Path(__file__).with_name("hunteval.sha256")
    checksums = {
        path: digest for digest, path in (
            line.split(maxsplit=1) for line in checksum_file.read_text().splitlines()
        )
    }
    expected = checksums.get(relative.as_posix())
    if expected is None:
        raise ValueError("Unknown episode or missing pinned checksum")
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"HuntEval checksum mismatch: {relative}")


def checked_files(root: Path, episode: str) -> tuple[Path, Path]:
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if commit != PINNED_COMMIT:
        raise ValueError("HuntEval checkout is not at the pinned commit")
    provider = episode.split("-", 1)[0]
    base = Path("datasets") / provider / episode
    public = base / "source/events.json"
    hidden = base / "private/ground-truth.json"
    verify_checksum(root, public)
    return root / public, root / hidden


def score(expected: set[str], reported: set[str]) -> dict[str, object]:
    matched = expected & reported
    return {
        "matched": len(matched),
        "expected": len(expected),
        "reported": len(reported),
        "precision": len(matched) / len(reported) if reported else None,
        "recall": len(matched) / len(expected) if expected else 1.0,
    }


if __name__ == "__main__":
    raise SystemExit("Use scripts/hunteval_benchmark.py; the old single-episode command has been replaced.")
