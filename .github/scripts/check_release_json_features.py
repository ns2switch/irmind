#!/usr/bin/env python3
"""Fail release preparation if the shipped dependency graph enables map ordering."""

from __future__ import annotations

import os
import subprocess


def forbidden_feature(tree: str) -> bool:
    return any(
        line.strip() == 'serde_json feature "preserve_order"'
        or line.strip().startswith('serde_json feature "preserve_order" (')
        for line in tree.splitlines()
    )


def main() -> None:
    # Match cargo build --release -p irmind --locked. Dev dependencies are not
    # part of that build. Honor the job's cross-compilation target when present.
    command = [
        "cargo", "tree", "--locked", "-p", "irmind", "-e",
        "normal,build,features", "-i", "serde_json", "--prefix", "none",
    ]
    if target := os.environ.get("CARGO_BUILD_TARGET"):
        command.extend(["--target", target])
    result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE)
    if forbidden_feature(result.stdout):
        raise SystemExit(
            "Release blocked: serde_json/preserve_order is enabled in the shipped "
            "dependency graph. Review custody compatibility before publishing."
        )
    print("Release JSON feature isolation passed: preserve_order is absent.")


if __name__ == "__main__":
    main()
