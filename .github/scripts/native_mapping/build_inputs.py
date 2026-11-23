"""Prepare and validate the common native-mapping input file for a release."""
import argparse
import json
from pathlib import Path
import re
import sys
from time import monotonic

from .codec import combine, TARGETS
from .observe import canonical_json

FORMAT = "irmind-native-mapping-inputs-v2"
MAX_OBSERVATION_BYTES = 4 * 1024 * 1024
MAX_INPUT_BYTES = MAX_OBSERVATION_BYTES * len(TARGETS)


def read_json(path, limit):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Native mapping input data exceeds its size limit")
    value = json.loads(raw)
    if canonical_json(value) + b"\n" != raw:
        raise ValueError("Noncanonical native mapping input data")
    return value


def write_json(path, value):
    path.write_bytes(canonical_json(value) + b"\n")


def read_inputs(path):
    record = read_json(path, MAX_INPUT_BYTES)
    if set(record) != {"format", "observations"} or record["format"] != FORMAT:
        raise ValueError("Unsupported native mapping input file")
    observations = record["observations"]
    if [item["destination"] for item in observations] != list(TARGETS):
        raise ValueError("Native mapping observations are missing or out of order")
    return observations


def prepare(path, directory):
    started = monotonic()
    observations = read_inputs(path)
    manifests = combine(observations)
    for name, encoded in manifests.items():
        if not re.fullmatch(r"irmind-mod-mapping-[a-z0-9-]+", name):
            raise ValueError("Invalid native mapping package name")
        (directory / f"{name}.bin").write_bytes(encoded)
    lengths = [len(encoded) for encoded in manifests.values()]
    print(f"Prepared {len(lengths)} native manifests, {min(lengths)}–{max(lengths)} bytes each "
          f"and {sum(lengths)} bytes total in {monotonic() - started:.3f} s")
    return {entry["destination"]: entry for entry in observations}


def assemble(root, output):
    observations = [read_json(root / f"mapping-input-{target}" / "observation.json", MAX_OBSERVATION_BYTES)
                    for target in TARGETS]
    if [entry["destination"] for entry in observations] != list(TARGETS):
        raise ValueError("A per-target mapping artifact used the wrong target label")
    combine(observations)
    write_json(output, {"format": FORMAT, "observations": observations})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        assemble(args.artifacts, args.output)
    except ValueError as error:
        sys.exit(f"Invalid native mapping observations: {error}")


if __name__ == "__main__":
    main()
