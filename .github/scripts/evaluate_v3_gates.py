#!/usr/bin/env python3
"""Check current mapped-V3 absolute performance evidence."""
import argparse
import json
from pathlib import Path

SCENARIOS = {"cloud"} | {
    f"endpoint-{hosts}{order}"
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


def worst_path(rows):
    row = one(rows, "PARQUET_WORST_PATH")
    error = row.get("error")
    truncated, timeout = row.get("truncated"), row.get("time_budget")
    if any(type(value) is not bool for value in (error, truncated, timeout)):
        raise ValueError("worst-case path outcome is missing or invalid")
    if timeout and not truncated:
        raise ValueError("time-budget path lacks its partial-result marker")
    return {"error": error, "truncated": truncated, "time_budget": timeout}


def full_sample(records, scenario):
    starts = [i for i, row in enumerate(records)
              if row["metric"] == "PARQUET_SCENARIO" and row.get("size") == "15gb"]
    if len(starts) != 1:
        raise ValueError("expected exactly one complete 15 GB sample")
    rows = records[starts[0]:]
    if rows[0].get("name") != scenario:
        raise ValueError("scenario does not match its artifact")
    wall = duration(one(rows, "PARQUET_INGEST_EXACT").get("wall_ns"))
    if type(one(rows, "PARQUET_INGEST").get("bytes")) is not int or one(rows, "PARQUET_INGEST").get("bytes", 0) < 15_000_000_000:
        raise ValueError("corpus is smaller than 15 GB")
    cold_error = one(rows, "PARQUET_COLD_QUERY").get("error")
    if type(cold_error) is not bool:
        raise ValueError("cold summary outcome is missing")
    successful = not cold_error
    hosts = None if scenario == "cloud" else int(scenario.split("-")[1])
    scopes = {"all"} if hosts is None else {"all", "endpoint-0000", f"endpoint-{hosts - 1:04}"}
    expected = {(scope, query) for scope in scopes for query in QUERIES}
    queries = {}
    for row in rows:
        if row["metric"] != "PARQUET_QUERY_EXACT":
            continue
        key = row.get("scope"), row.get("name")
        if key in queries or row.get("scenario") != scenario:
            raise ValueError("duplicate or mismatched query sample")
        errors, timeouts = row.get("errors"), row.get("time_budget_hits")
        if any(type(value) is not int or not 0 <= value <= 5 for value in (errors, timeouts)) or errors + timeouts > 5:
            raise ValueError("query outcomes are missing or invalid")
        queries[key] = duration(row.get("p95_ns"))
        successful &= errors == 0 and timeouts == 0 and queries[key] < 10 * SECOND
    if queries.keys() != expected:
        raise ValueError("query coverage is incomplete")
    worst = worst_path(rows) if hosts is None else None
    return wall, queries, successful, worst


def evaluate(data):
    if data.get("schema") != "irmind-v3-measurements-v1":
        raise ValueError("unsupported performance measurement format")
    results = []
    seen = set()
    for sample in data["scenarios"]:
        scenario = sample["scenario"]
        if sample.get("writer") != "mapped-v3":
            raise ValueError("performance evidence must use the sole mapped V3 writer")
        if scenario not in SCENARIOS or scenario in seen:
            raise ValueError("unexpected or duplicate scenario")
        seen.add(scenario)
        wall, queries, successful, worst = full_sample(sample["records"], scenario)
        stress = scenario.startswith("endpoint-") and not scenario.endswith("-chronological")
        limit = (1350 if stress else 900) * SECOND
        absolute = wall < limit
        required = scenario != "endpoint-1025"
        worst_ok = worst is None or not worst["error"]
        passed = (absolute or not required) and successful and worst_ok
        results.append({"scenario": scenario, "wall_ns": wall,
                        "ingest_target_ns": limit, "ingest_goal_met": absolute,
                        "ingest_gate_required": required,
                        "ordinary_queries_successful": successful,
                        "ordinary_query_p95_ns": [
                            {"scope": scope, "query": name, "p95_ns": value}
                            for (scope, name), value in sorted(queries.items())],
                        "deliberate_worst_path": worst, "passed": passed})
    if seen != SCENARIOS:
        raise ValueError("full nine-scenario matrix is required")
    return {"criteria": "analyst-v3-absolute-v1", "run_url": data["run_url"],
            "passed": all(row["passed"] for row in results),
            "all_ingest_goals_met": all(row["ingest_goal_met"] for row in results),
            "scenarios": sorted(results, key=lambda row: row["scenario"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metrics", type=Path)
    args = parser.parse_args()
    result = evaluate(json.loads(args.metrics.read_text()))
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
