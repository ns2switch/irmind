#!/usr/bin/env python3
"""Reject Rust source includes; data includes remain valid."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = re.compile(r"\binclude!\s*\(")


def main() -> int:
    violations = []
    paths = sorted((ROOT / "crates").rglob("*.rs")) + sorted(
        (ROOT / "fuzz").rglob("*.rs")
    )
    for path in paths:
        source = path.read_text(encoding="utf-8")
        for match in INCLUDE.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            violations.append(f"{path.relative_to(ROOT)}:{line}")
    if violations:
        print("Rust include! is forbidden; use a module:\n" + "\n".join(violations))
        return 1
    print("No Rust include! macros")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
