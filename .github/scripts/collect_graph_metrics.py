#!/usr/bin/env python3
"""Collect only bounded, allowlisted numeric and categorical benchmark results."""
import argparse
import json
import math
import re
from pathlib import Path

from evaluate_v3_gates import SCENARIOS, one

MAX_LOG = 50 * 1024 * 1024
SCENARIO = r"(?:cloud|endpoint-(?:1|64|1024|1025)(?:-chronological)?)"
FIELDS = {
    "PARQUET_WRITER": "name",
    "PARQUET_SCENARIO": "name size normalized_stage_peak_bytes",
    "PARQUET_INGEST_LIMIT": "seconds met required",
    "PARQUET_INGEST_EXACT": "wall_ns",
    "PARQUET_QUERY_EXACT": "scenario scope name p50_ns p95_ns errors time_budget_hits",
    "PARQUET_INGEST": "bytes files hash_seconds conversion_seconds row_seconds parquet_seconds wall_seconds parquet_bytes coobservation_bytes",
    "PARQUET_COMPACTION": "bundles",
    "PARQUET_RETAINED_PARENTS": "scenario inactive_parent_bytes active_artifact_bytes retained_case_bytes inactive_case_basis_points inactive_active_basis_points",
    "PARQUET_LAYOUT_TIME": "seconds",
    "PARQUET_TEMPORARY_DISK": "sampled_peak_bytes interval_ms scan_errors",
    "MAPPING_PHASE": "decoder_seconds mapper_seconds",
    "CUSTODY_PHASE": "sign_seconds verify_signature_seconds append_seconds",
    "MAPPING_ADAPTER_PHASE": "select_validate_commit_and_map_seconds projection_seconds input_commit_finalize_seconds",
    "PARQUET_COLD_QUERY": "seconds error",
    "PARQUET_WRITE_PHASE": "stage_seconds sort_seconds replay_seconds source_verify_seconds publish_seconds",
    "PARQUET_QUERY": "scenario scope name p50_seconds p95_seconds errors",
    "PARQUET_LAYOUT": "scenario historical_files active_files partitions ordinary_hosts overflow_artifacts active_bytes",
    "PARQUET_COLUMN": "scenario column compressed_bytes",
    "PARQUET_COOBS_COLUMN": "scenario column compressed_bytes",
    "PARQUET_COOBS_BUDGET": "scenario active_file_bytes repeated_time_column_bytes",
    "PARQUET_QUERY_PHASE": "verify_seconds scan_seconds",
    "PARQUET_QUERY_PROFILE": "scenario scope name verify_seconds scan_seconds normalize_seconds aggregate_seconds",
    "PARQUET_WORST_PATH": "seconds truncated time_budget error",
    "HUNTEVAL_RECALL": "corpus provider events entities path parse_errors",
    "HUNTEVAL_QUERY": "corpus provider query samples p50_seconds p95_seconds",
}


def metric(prefix, key, raw):
    if key == "name" and prefix == "PARQUET_WRITER":
        pattern = r"mapped-v3"
    elif key == "scenario" or (key == "name" and prefix == "PARQUET_SCENARIO"):
        pattern = SCENARIO
    elif key in {"size", "corpus"}:
        pattern = r"(?:1|15)g(?:i)?b|50mb|smoke"
    elif key == "scope":
        pattern = r"all|endpoint-[0-9]{4}"
    elif key == "provider":
        pattern = r"aws|azure|gcp"
    elif key in {"column", "query", "name"}:
        pattern = r"[a-z_]+"
    elif key in {"events", "entities", "path"}:
        pattern = r"[0-9]+/[0-9]+"
    elif key in {"truncated", "time_budget", "error", "met", "required"}:
        if raw not in {"true", "false"}:
            raise ValueError("invalid benchmark boolean")
        return raw == "true"
    elif key.endswith("seconds"):
        value = float(raw)
        if not math.isfinite(value) or value < 0:
            raise ValueError("invalid benchmark duration")
        return value
    else:
        if not re.fullmatch(r"[0-9]+", raw):
            raise ValueError("invalid benchmark counter")
        return int(raw)
    if not re.fullmatch(pattern, raw):
        raise ValueError("invalid benchmark identifier")
    return raw


def parse_log(data):
    if len(data) > MAX_LOG:
        raise ValueError("benchmark log limit exceeded")
    records = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        prefix = line.partition(" ")[0]
        if prefix not in FIELDS:
            continue
        if len(line) > 8192:
            raise ValueError("oversized benchmark metric")
        allowed = set(FIELDS[prefix].split())
        values = {}
        for key, raw in re.findall(r"([a-z][a-z0-9_]*)=([^ ]+)", line):
            if key not in allowed:
                continue
            if key in values:
                raise ValueError("duplicate benchmark metric field")
            values[key] = metric(prefix, key, raw)
        if len(records) >= 20_000:
            raise ValueError("benchmark metric count limit exceeded")
        records.append({"metric": prefix, **values})
    return records

def collect(root, run_url, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid measured revision")
    scenarios = []
    for scenario in sorted(SCENARIOS):
        path = root / f"current-v3-{scenario}" / "current-v3.txt"
        with path.open("rb") as source:
            rows = parse_log(source.read(MAX_LOG + 1))
        writer = one(rows, "PARQUET_WRITER")["name"]
        scenarios.append({"scenario": scenario, "writer": writer, "records": rows})
    return {"schema": "irmind-v3-measurements-v1", "run_url": run_url,
            "commit": commit, "scenarios": scenarios}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    result = collect(args.root, args.run_url, args.commit)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
