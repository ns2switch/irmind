"""Measure pre-release-signing differences without modifying an executable."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from reproduce_release_profile import build_once, output


def digest(data):
    return hashlib.sha256(data).hexdigest()


def name(data):
    return data.split(b"\0", 1)[0].decode("ascii")


def read_u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def macho_metadata(data, file):
    fields = {"macho_uuid": None, "code_signature": None, "dylib_timestamps": []}
    masks = {"uuid": [], "code_signature": [], "timestamps": []}
    sections = {}
    cursor = 32
    for _ in range(read_u32(data, 16)):
        command, size = struct.unpack_from("<II", data, cursor)
        if command == 0x1B:  # LC_UUID
            fields["macho_uuid"] = data[cursor + 8:cursor + 24].hex()
            masks["uuid"].append((cursor + 8, 16))
        elif command == 0x1D:  # LC_CODE_SIGNATURE
            start, length = struct.unpack_from("<II", data, cursor + 8)
            checked = subprocess.run(["codesign", "-dvv", file], capture_output=True)
            fields["code_signature"] = {
                "offset": start, "bytes": length, "sha256": digest(data[start:start + length]),
                "ad_hoc": b"Signature=adhoc" in checked.stderr,
            }
            masks["code_signature"].append((start, length))
        elif command & 0x7FFF_FFFF in (0xC, 0xD, 0x18, 0x1F, 0x20, 0x23):
            fields["dylib_timestamps"].append(read_u32(data, cursor + 12))
            masks["timestamps"].append((cursor + 12, 4))
        elif command == 0x19:  # LC_SEGMENT_64
            for index in range(read_u32(data, cursor + 64)):
                section = cursor + 72 + index * 80
                section_name = name(data[section + 16:section + 32]) + "," + name(data[section:section + 16])
                length, start = struct.unpack_from("<QI", data, section + 40)
                if start and length:
                    sections[section_name] = (start, length)
        cursor += size
    return fields, masks, sections


def pe_metadata(data, _file):
    pe = read_u32(data, 0x3C)
    assert data[pe:pe + 4] == b"PE\0\0"
    coff = pe + 4
    count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    assert magic in (0x10B, 0x20B)
    directories = optional + (112 if magic == 0x20B else 96)
    sections = {}
    addresses = []
    for index in range(count):
        section = optional + optional_size + 40 * index
        section_name = name(data[section:section + 8])
        _, rva, length, start = struct.unpack_from("<IIII", data, section + 8)
        if start and length:
            sections[section_name] = (start, length)
            addresses.append((rva, length, start))
    debug_rva, debug_size = struct.unpack_from("<II", data, directories + 6 * 8)
    _, certificate_size = struct.unpack_from("<II", data, directories + 4 * 8)
    fields = {
        "coff_timestamp": read_u32(data, coff + 4),
        "checksum": read_u32(data, optional + 64),
        "certificate_bytes": certificate_size,
        "debug_entries": [],
    }
    masks = {"timestamps": [(coff + 4, 4)], "checksum": [(optional + 64, 4)], "debug": []}
    if debug_rva:
        debug_start = next(start + debug_rva - rva for rva, length, start in addresses
                           if rva <= debug_rva and debug_rva + debug_size <= rva + length)
        for cursor in range(debug_start, debug_start + debug_size, 28):
            kind, length, _, start = struct.unpack_from("<IIII", data, cursor + 12)
            record = data[start:start + length]
            entry = {"type": kind, "timestamp": read_u32(data, cursor + 4),
                     "bytes": length, "sha256": digest(record)}
            if kind == 2 and record[:4] == b"RSDS":
                pdb = record[24:].split(b"\0", 1)[0]
                entry.update(pdb_path_bytes=len(pdb), absolute_pdb_path=(
                    pdb.startswith((b"/", b"\\")) or pdb[1:3] in (b":\\", b":/")))
            fields["debug_entries"].append(entry)
            masks["timestamps"].append((cursor + 4, 4))
            if length:
                masks["debug"].append((start, length))
    return fields, masks, sections


def masked(data, ranges):
    result = bytearray(data)
    for start, size in ranges:
        assert start + size <= len(result)
        result[start:start + size] = bytes(size)
    return result


def inspect(file):
    data = file.read_bytes()
    if data.startswith(b"\xcf\xfa\xed\xfe"):
        metadata, masks, sections = macho_metadata(data, file)
    elif data.startswith(b"MZ"):
        metadata, masks, sections = pe_metadata(data, file)
    else:
        raise ValueError("Expected 64-bit Mach-O or PE")
    normalized = masked(data, [span for ranges in masks.values() for span in ranges])
    return {
        "sha256": digest(data),
        "bytes": len(data),
        "metadata": metadata,
        "masked_sha256": {kind: digest(masked(data, ranges)) for kind, ranges in masks.items()},
        "all_metadata_masked_sha256": digest(normalized),
        "sections": {key: digest(data[start:start + size]) for key, (start, size) in sections.items()},
        "masked_sections": {key: digest(normalized[start:start + size])
                            for key, (start, size) in sections.items()},
    }


def compare(left, right):
    def different(key):
        a, b = left[key], right[key]
        return sorted(prop for prop in a.keys() | b.keys() if a.get(prop) != b.get(prop))

    return {
        "same_binary": left["sha256"] == right["sha256"],
        "same_after_masking_metadata": left["all_metadata_masked_sha256"] == right["all_metadata_masked_sha256"],
        "matching_single_masks": sorted(key for key in left["masked_sha256"]
                                        if left["masked_sha256"][key] == right["masked_sha256"][key]),
        "different_sections": different("sections"),
        "different_sections_after_masking_metadata": different("masked_sections"),
        "different_metadata": different("metadata"),
        "same_mappings": left["release"]["mappings"] == right["release"]["mappings"],
    }


def run_probe(platform, target, mode):
    commit = output(["git", "rev-parse", "HEAD"])
    command = ["git", "-c", "core.longpaths=true", "worktree"]
    builds = {}
    paths = [("first", "a"), ("different", "longer-second-source")]
    if mode == "default":
        paths.append(("same", "a"))
    with tempfile.TemporaryDirectory(prefix="repro-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        for test, path in paths:
            checkout = Path(temp) / path
            subprocess.run([*command, "add", "--detach", checkout, commit], check=True)
            try:
                flags = []
                if mode == "remap":
                    for prefix in sorted({str(checkout), checkout.as_posix()}):
                        flags.append(f"--remap-path-prefix={prefix}=/irmind-source")
                if mode == "brepro":
                    flags = ["-C", "link-arg=/Brepro"]
                os.environ["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
                release = build_once(checkout, "default", target)
                file = checkout / "out" / target / "release" / ("irmind.exe" if os.name == "nt" else "irmind")
                builds[test] = inspect(file) | {"release": release}
            finally:
                subprocess.run([*command, "remove", "--force", checkout], check=True)
    comparisons = {name: compare(builds["first"], build) for name, build in builds.items() if name != "first"}
    receipt = {"commit": commit, "builds": builds, "comparisons": comparisons}
    Path(f"native-diagnostic-{platform}-{mode}.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(comparisons, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", required=True, choices=("default", "remap", "brepro"))
    args = parser.parse_args()
    run_probe(args.platform, args.target, args.mode)
