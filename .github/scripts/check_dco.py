#!/usr/bin/env python3
"""Require an author-matching DCO sign-off on every commit in a PR."""

import os
import re
import subprocess
import sys


SHA = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\Z")
SIGNOFF = re.compile(r"Signed-off-by:\s+.+\s+<([^<>\s]+@[^<>\s]+)>\Z", re.I)


def git(*args: str, input_text: str | None = None) -> str:
    return subprocess.run(
        ["git", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    ).stdout


def main() -> int:
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        print("DCO: BASE_SHA y HEAD_SHA deben ser hashes de commit completos", file=sys.stderr)
        return 2
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not commits:
        print("DCO: no hay commits en el rango del PR", file=sys.stderr)
        return 2
    missing = []
    for commit in commits:
        author_email = git("show", "-s", "--format=%ae", commit).strip().casefold()
        message = git("show", "-s", "--format=%B", commit)
        trailers = git("interpret-trailers", "--parse", input_text=message)
        signed_by_author = any(
            (match := SIGNOFF.fullmatch(line.strip()))
            and match.group(1).casefold() == author_email
            for line in trailers.splitlines()
        )
        if not signed_by_author:
            missing.append(commit[:12])
    if missing:
        print("DCO: falta Signed-off-by del autor en: " + ", ".join(missing), file=sys.stderr)
        return 1
    print(f"DCO: {len(commits)} commits verificados")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
