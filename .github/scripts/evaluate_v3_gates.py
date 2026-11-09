#!/usr/bin/env python3
"""Evaluate activation evidence without changing the experimental writer setting."""
import argparse
import json
from pathlib import Path

SCENARIOS = {"cloud-v2"} | {
    f"endpoint-v2-{hosts}{order}"
    for hosts in (1, 64, 1024, 1025)
    for order in ("", "-chronological")
}
QUERIES = {"term", "entity", "neighbors", "timeline", "path"}
SECOND = 1_000_000_000


def one(records, kind):
    matches = [row for row in records if row["metric"] == kind]
    if len(matches) != 1:
        raise ValueError(f"expected one {kind}, found {len(matches)}")
    return matches[0]


def duration(value):
    if type(value) is not int or value <= 0:
        raise ValueError("missing or invalid exact nanosecond duration")
    return value


def full_sample(records, scenario):
    starts = [i for i, row in enumerate(records)
              if row["metric"] == "PARQUET_SCENARIO" and row.get("size") == "15gb"]
    if len(starts) != 1:
        raise ValueError("expected exactly one complete 15 GB sample")
    rows = records[starts[0]:]
    if rows[0].get("name") != scenario:
        raise ValueError("scenario does not match its artifact")
    wall = duration(one(rows, "PARQUET_INGEST_EXACT").get("wall_ns"))
    if one(rows, "PARQUET_INGEST").get("bytes", 0) < 15_000_000_000:
        raise ValueError("corpus is smaller than 15 GB")
    if one(rows, "PARQUET_COLD_QUERY").get("error") is not False:
        raise ValueError("cold summary failed or is missing")
    hosts = None if scenario == "cloud-v2" else int(scenario.split("-")[2])
    scopes = {"all"} if hosts is None else {"all", "endpoint-0000", f"endpoint-{hosts - 1:04}"}
    expected = {(scope, query) for scope in scopes for query in QUERIES}
    queries = {}
    for row in rows:
        if row["metric"] != "PARQUET_QUERY_EXACT":
            continue
        key = row.get("scope"), row.get("name")
        if key in queries or row.get("scenario") != scenario or row.get("errors") != 0 or row.get("time_budget_hits") != 0:
            raise ValueError("duplicate, mismatched or failed query sample")
        queries[key] = duration(row.get("p95_ns"))
    if queries.keys() != expected:
        raise ValueError("query coverage is incomplete")
    if hosts is None and one(rows, "PARQUET_WORST_PATH").get("time_budget") is not False:
        raise ValueError("worst-case path exhausted its time budget")
    return wall, queries


def evaluate(data):
    results = []
    seen = set()
    for artifact in data["artifacts"]:
        scenario = artifact["name"].removeprefix("common-schema-")
        if scenario not in SCENARIOS or scenario in seen:
            raise ValueError("unexpected or duplicate scenario")
        seen.add(scenario)
        reference = artifact["stages"]["reference"]
        ref_wall, ref_queries = full_sample(reference, scenario)
        candidate = artifact["stages"]["candidate"]
        wall, queries = full_sample(candidate, scenario)
        limit = (900 if scenario == "cloud-v2" or scenario.endswith("-chronological") else 1350) * SECOND
        relative_ingest = wall * 10 <= ref_wall * 11
        relative_queries = all(queries[key] * 10 <= ref_queries[key] * 11 for key in queries)
        deadlines = all(value < 10 * SECOND for value in queries.values())
        # The analyst permits the relative gate when the paired reference itself
        # misses the absolute ingestion target. Query deadlines are never waived.
        absolute = wall < limit
        eligible = relative_ingest and relative_queries and deadlines and (absolute or ref_wall >= limit)
        results.append({"scenario": scenario, "reference_wall_ns": ref_wall,
                        "candidate_wall_ns": wall, "absolute_ingest": absolute,
                        "relative_ingest": relative_ingest, "relative_queries": relative_queries,
                        "query_deadlines": deadlines, "eligible": eligible})
    if seen != SCENARIOS:
        raise ValueError("full nine-scenario matrix is required")
    return {"run_url": data["run_url"], "eligible": all(row["eligible"] for row in results),
            "scenarios": sorted(results, key=lambda row: row["scenario"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metrics", type=Path)
    args = parser.parse_args()
    result = evaluate(json.loads(args.metrics.read_text()))
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["eligible"] else 1)


if __name__ == "__main__":
    main()
