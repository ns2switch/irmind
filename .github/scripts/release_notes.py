"""Append the public code-signing policy without replacing release notes."""

from pathlib import Path
import argparse


POLICY_URL = "https://github.com/ns2switch/irmind/blob/main/CODE_SIGNING.md"
ATTRIBUTION = (
    "Free code signing provided by [SignPath.io](https://about.signpath.io/), "
    "certificate by [SignPath Foundation](https://signpath.org/)"
)
FOOTER = f"Code signing policy: {POLICY_URL}\n\n{ATTRIBUTION}"


def append_policy(notes: str) -> str:
    """Keep manual/generated notes and avoid duplicates on publication retries."""
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
