"""Append the public code-signing policy without replacing release notes."""

from pathlib import Path
import argparse


POLICY_URL = "https://github.com/ns2switch/irmind/blob/main/CODE_SIGNING.md"
FOOTER = f"Code signing policy: {POLICY_URL}"


def append_policy(notes: str) -> str:
    """Keep manual/generated notes and avoid duplicates on publication retries."""
    lines = notes.splitlines(keepends=True)
    retained = [line for line in lines if not line.startswith("Free code signing provided by ")]
    if len(retained) != len(lines):
        notes = "".join(retained).rstrip() + "\n"
    if FOOTER in notes:
        return notes
    prefix = notes.rstrip()
    separator = "\n\n---\n\n" if prefix else ""
    return f"{prefix}{separator}{FOOTER}\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("notes", type=Path, help="UTF-8 release notes to update in place")
    args = parser.parse_args()
    args.notes.write_text(append_policy(args.notes.read_text(encoding="utf-8")), encoding="utf-8")


if __name__ == "__main__":
    main()
