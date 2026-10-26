#!/usr/bin/env python3
"""Report Rust source files and function bodies over the project size limits."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNCTION = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z_0-9]*)\b")


def mask_source(source: str) -> str:
    """Keep braces outside comments and literals, preserving line positions."""
    out: list[str] = []
    index = 0
    block = 0
    raw_end: str | None = None
    quoted = False
    while index < len(source):
        char = source[index]
        pair = source[index : index + 2]
        if block:
            if pair == "/*":
                block += 1
                index += 2
                continue
            if pair == "*/":
                block -= 1
                index += 2
                continue
        elif raw_end is not None:
            if source.startswith(raw_end, index):
                index += len(raw_end)
                raw_end = None
                continue
        elif quoted:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quoted = False
        elif pair == "//":
            index = source.find("\n", index)
            if index == -1:
                break
            continue
        elif pair == "/*":
            block = 1
            index += 2
            continue
        elif char == '"':
            quoted = True
        elif char == "r":
            match = re.match(r'r(#{0,16})"', source[index:])
            if match:
                raw_end = '"' + match.group(1)
                index += len(match.group(0))
                continue
        elif char == "'":
            match = re.match(r"'(?:\\.|[^'\\])'", source[index:])
            if match:
                index += len(match.group(0))
                continue
        if char == "\n":
            out.append("\n")
        elif not (block or raw_end is not None or quoted):
            out.append(char)
        else:
            out.append(" ")
        index += 1
    return "".join(out)


def functions(path: Path) -> list[tuple[str, int, int]]:
    masked = mask_source(path.read_text(encoding="utf-8"))
    results: list[tuple[str, int, int]] = []
    pending: tuple[str, int] | None = None
    body: tuple[str, int, int] | None = None
    for number, line in enumerate(masked.splitlines(), 1):
        if body is None and pending is None:
            match = FUNCTION.search(line)
            if match:
                pending = (match.group(1), number)
                line = line[match.end() :]
        if pending is not None and body is None:
            if ";" in line and ("{" not in line or line.index(";") < line.index("{")):
                pending = None
                continue
            if "{" in line:
                name, start = pending
                body = (name, start, 0)
                line = line[line.index("{") :]
                pending = None
        if body is not None:
            name, start, depth = body
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                results.append((name, start, number - start + 1))
                body = None
            else:
                body = (name, start, depth)
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file-limit", type=int, default=400)
    parser.add_argument("--function-limit", type=int, default=80)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    files = sorted((ROOT / "crates").rglob("*.rs"))
    long_files = []
    long_functions = []
    for path in files:
        relative = str(path.relative_to(ROOT))
        length = len(path.read_text(encoding="utf-8").splitlines())
        if length > args.file_limit:
            long_files.append((relative, length))
        for name, start, count in functions(path):
            if count > args.function_limit:
                long_functions.append((f"{relative}:{start}:{name}", count))
    report = {
        "file_limit": args.file_limit,
        "function_limit": args.function_limit,
        "files_over_limit": long_files,
        "functions_over_limit": long_functions,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Files over {args.file_limit} lines: {len(long_files)}")
        for name, count in long_files:
            print(f"  {count:4} {name}")
        print(f"Functions over {args.function_limit} lines: {len(long_functions)}")
        for name, count in long_functions:
            print(f"  {count:4} {name}")


if __name__ == "__main__":
    main()
