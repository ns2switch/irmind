#!/usr/bin/env python3
"""Measure ELF sections and approximate Rust namespace text size with binutils.

Development-only: accepts already verified release artifacts. Never runs them.
"""

import argparse
import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path


SECTION = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+"
    r"([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([A-Z]*)"
)
SYMBOL = re.compile(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+([tT])\s+(.+)$")
NAMESPACE = re.compile(r"(?:^|<)([A-Za-z_][A-Za-z_0-9]*)(?:\[[^]]+\])?::")


def sections(binary):
    output = subprocess.check_output(
        ["readelf", "--wide", "--sections", str(binary)], text=True
    )
    result = {}
    with binary.open("rb") as stream:
        for line in output.splitlines():
            match = SECTION.match(line)
            if match is None:
                continue
            name, kind, address, offset, length, flags = match.groups()
            address, offset, length = (int(value, 16) for value in (address, offset, length))
            digest = None
            if "A" in flags and kind != "NOBITS":
                hasher = hashlib.sha256()
                stream.seek(offset)
                remaining = length
                while remaining:
                    block = stream.read(min(remaining, 1024 * 1024))
                    if not block:
                        raise ValueError("ELF section exceeds the file")
                    hasher.update(block)
                    remaining -= len(block)
                digest = hasher.hexdigest()
            result[f"{name}@{address:x}"] = {
                "name": name, "type": kind, "address": address,
                "size": length, "flags": flags, "sha256": digest,
            }
    return result


def namespace(name):
    match = NAMESPACE.search(name)
    if match:
        return match[1]
    if name.startswith("aws_lc_"):
        return "_".join(name.split("_")[:5])
    if name.startswith("sqlite3"):
        return "sqlite3 native"
    if name.startswith("ring_"):
        return "ring native"
    return "other C, runtime or generic"


def symbol_sizes(binary):
    output = subprocess.run(
        ["nm", "--defined-only", "--print-size", "--demangle=rust", str(binary)],
        check=True, capture_output=True, text=True,
    )
    # Same-address aliases are one code body, not several crate contributions.
    addresses = {}
    for line in output.stdout.splitlines():
        match = SYMBOL.match(line)
        if match is None:
            continue
        address, size = int(match[1], 16), int(match[2], 16)
        if address not in addresses or size > addresses[address][0]:
            addresses[address] = (size, match[4])
    totals = collections.Counter()
    for size, name in addresses.values():
        totals[namespace(name)] += size
    return {
        "method": "defined text symbols, maximum-size alias per address, first Rust namespace or native prefix",
        "limitation": "Inlining, shared generics and overlapping symbols prevent exact marginal crate attribution.",
        "unique_text_symbol_bytes": sum(size for size, _ in addresses.values()),
        "namespace_bytes": dict(totals.most_common()),
    }


def measure(binary):
    return {
        "file": binary.name,
        "bytes": binary.stat().st_size,
        "sections": sections(binary),
        "text_symbols": symbol_sizes(binary),
    }


def allocated_equal(before, after):
    def allocated(measurement):
        return {
            key: {
                "address": value["address"], "size": value["size"],
                "type": value["type"], "sha256": value["sha256"],
                "runtime_flags": "".join(flag for flag in value["flags"] if flag in "WAXT"),
            }
            for key, value in measurement["sections"].items()
            if "A" in value["flags"]
        }
    return allocated(before) == allocated(after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("comparison", type=Path, nargs="?")
    args = parser.parse_args()
    result = {"before": measure(args.binary)}
    if args.comparison is not None:
        result["after"] = measure(args.comparison)
        result["allocated_layout_and_payloads_identical"] = allocated_equal(
            result["before"], result["after"]
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
