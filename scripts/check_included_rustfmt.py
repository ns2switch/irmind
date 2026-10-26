#!/usr/bin/env python3
"""Check Rust sources that cargo fmt does not traverse through include!."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = re.compile(r'include!\("([^"]+\.rs)"\)')


def main() -> int:
    paths: set[Path] = set()
    for source in (ROOT / "crates").rglob("*.rs"):
        for relative in INCLUDE.findall(source.read_text(encoding="utf-8")):
            target = (source.parent / relative).resolve()
            if not target.is_relative_to(ROOT / "crates") or not target.is_file():
                raise SystemExit(f"invalid included Rust source: {source}: {relative}")
            paths.add(target)
    for path in sorted(paths):
        result = subprocess.run(
            ["rustfmt", "--check", "--edition", "2024", str(path)],
            cwd=ROOT,
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
    print(f"Checked {len(paths)} included Rust sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
