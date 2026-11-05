#!/usr/bin/env python3
"""Collect bounded, allowlisted synthetic metrics from a paired benchmark run."""
import argparse
import hashlib
import io
import json
import math
import re
import subprocess
import time
import zipfile
from pathlib import Path

REPO = "ns2switch/irmind"
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_LOG = 50 * 1024 * 1024
SCENARIO = r"(?:cloud-v[12]|endpoint-v[12]-(?:1|64|1024|1025)(?:-chronological)?)"
FIELDS = {
    "PAIRED_REVISION": "stage commit scenario",
    "PARQUET_SCENARIO": "name size normalized_stage_peak_bytes",
    "PARQUET_INGEST": "bytes files hash_seconds conversion_seconds row_seconds parquet_seconds wall_seconds parquet_bytes coobservation_bytes",
    "PARQUET_COMPACTION": "bundles",
    "PARQUET_COLD_QUERY": "seconds error",
    "PARQUET_V2_PHASE": "stage_seconds sort_seconds replay_seconds source_verify_seconds publish_seconds",
    "PARQUET_QUERY": "scenario scope name p50_seconds p95_seconds errors",
    "PARQUET_LAYOUT": "scenario historical_files active_files partitions ordinary_hosts overflow_artifacts active_bytes",
    "PARQUET_COLUMN": "scenario column compressed_bytes",
    "PARQUET_COOBS_COLUMN": "scenario column compressed_bytes",
    "PARQUET_COOBS_BUDGET": "scenario active_file_bytes repeated_time_column_bytes",
    "PARQUET_QUERY_PHASE": "verify_seconds scan_seconds",
    "PARQUET_QUERY_PROFILE": "scenario scope name verify_seconds scan_seconds normalize_seconds aggregate_seconds",
    "PARQUET_WORST_PATH": "seconds truncated time_budget",
    "HUNTEVAL_RECALL": "corpus provider events entities path parse_errors",
    "HUNTEVAL_QUERY": "corpus provider query samples p50_seconds p95_seconds",
}


def fetch(endpoint):
    for attempt in range(2):
        result = subprocess.run(
            ["gh", "api", f"repos/{REPO}/{endpoint}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if len(result.stdout) > MAX_ARCHIVE:
            raise RuntimeError("benchmark download limit exceeded")
        if result.returncode == 0:
            return result.stdout
        if attempt == 0:
            time.sleep(1)
    raise RuntimeError("cannot fetch bounded benchmark metadata or artifact")


def metric(prefix, key, raw):
    if key == "commit":
        pattern = r"[0-9a-f]{40}"
    elif key == "scenario" or (key == "name" and prefix == "PARQUET_SCENARIO"):
        pattern = SCENARIO
    elif key == "stage":
        pattern = r"baseline|candidate"
    elif key in {"size", "corpus"}:
        pattern = r"(?:1|15)gb|50mb|smoke"
    elif key == "scope":
        pattern = r"all|endpoint-[0-9]{4}"
    elif key == "provider":
        pattern = r"aws|azure|gcp"
    elif key in {"column", "query", "name"}:
        pattern = r"[a-z_]+"
    elif key in {"events", "entities", "path"}:
        pattern = r"[0-9]+/[0-9]+"
    elif key in {"truncated", "time_budget", "error"}:
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
    records = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        prefix = line.partition(" ")[0]
        if prefix not in FIELDS:
            continue
        if len(line) > 8192:
            raise ValueError("oversized benchmark metric")
        allowed = set(FIELDS[prefix].split())
        values = {
            key: metric(prefix, key, raw)
            for key, raw in re.findall(r"([a-z][a-z0-9_]*)=([^ ]+)", line)
            if key in allowed
        }
        if len(records) >= 20_000:
            raise ValueError("benchmark metric count limit exceeded")
        records.append({"metric": prefix, **values})
    return records


def collect(run_id):
    metadata = json.loads(fetch(f"actions/runs/{run_id}/artifacts?per_page=100"))
    results = []
    for artifact in sorted(metadata["artifacts"], key=lambda item: item["name"]):
        name = artifact["name"]
        if not name.startswith("parquet-pair-") or artifact["expired"]:
            continue
        if not re.fullmatch("parquet-pair-" + SCENARIO, name):
            raise ValueError("unexpected paired artifact name")
        if artifact["size_in_bytes"] > MAX_ARCHIVE:
            raise ValueError("benchmark archive limit exceeded")
        raw = fetch(f"actions/artifacts/{artifact['id']}/zip")
        stages = {}
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                if info.filename not in {"benchmark-pair-baseline.txt", "benchmark-pair-candidate.txt"}:
                    raise ValueError("unexpected benchmark archive member")
                if info.file_size > MAX_LOG:
                    raise ValueError("benchmark log limit exceeded")
                with archive.open(info) as source:
                    data = source.read(MAX_LOG + 1)
                if len(data) > MAX_LOG:
                    raise ValueError("benchmark log limit exceeded")
                stages[info.filename.split("-")[-1].removesuffix(".txt")] = parse_log(data)
        results.append({"artifact_id": artifact["id"], "name": name,
                        "download_sha256": hashlib.sha256(raw).hexdigest(), "stages": stages})
    return {"run_url": f"https://github.com/{REPO}/actions/runs/{run_id}", "artifacts": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = collect(args.run)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Collected {len(result['artifacts'])} paired artifacts")


if __name__ == "__main__":
    main()
