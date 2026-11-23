#!/usr/bin/env python3
"""Check the production mapping closure on every supported release target."""

import subprocess


TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
FORBIDDEN = {"irmind-app", "url", "form_urlencoded"}
ROOTS = ["irmind-mod-mapping-*", "irmind-mapping-tables", "irmind-mapping-contracts"]


def main():
    for target in TARGETS:
        command = [
            "cargo", "tree", "--locked", "--all-features", "--edges", "normal,build",
            "--target", target, "--prefix", "none", "--format", "{p}",
        ]
        for root in ROOTS:
            command.extend(("-p", root))
        result = subprocess.run(command, text=True, check=True, stdout=subprocess.PIPE)
        packages = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
        forbidden = packages & FORBIDDEN
        if forbidden:
            raise SystemExit(f"{target}: forbidden mapping dependencies: {', '.join(sorted(forbidden))}")
        print(f"{target}: {len(packages)} production mapping packages, no application or URL stack")


if __name__ == "__main__":
    main()
