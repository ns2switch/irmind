#!/usr/bin/env python3
"""Resolve every locked workspace and keep shipped package versions aligned."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = (
    "Cargo.toml", "fuzz/Cargo.toml", "helpers/evtx/Cargo.toml",
    "helpers/evtx/fuzz/Cargo.toml",
)
SHIPPED = {"irmind", "irmind-tui", "irmind-evtx"}


def main():
    versions = {name: set() for name in SHIPPED}
    for manifest in MANIFESTS:
        # --no-deps would skip dependency resolution and miss an incompatible
        # local path dependency or a stale lockfile.
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1",
             "--manifest-path", manifest],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True,
        )
        for package in json.loads(result.stdout)["packages"]:
            if package["name"] in SHIPPED and package["source"] is None:
                versions[package["name"]].add(package["version"])
        print(f"Locked graph valid: {manifest}")
    values = set().union(*versions.values())
    if any(len(value) != 1 for value in versions.values()) or len(values) != 1:
        raise SystemExit(f"Shipping package versions disagree: {versions}")
    print(f"Shipping package versions match: {next(iter(values))}")


if __name__ == "__main__":
    main()
