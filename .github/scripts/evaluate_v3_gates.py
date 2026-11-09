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
QUERY_SLACK = SECOND // 4


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
    # Historical harnesses emit this metric only after graph_path(...).unwrap().
    # Its presence therefore records a successful call, not a caught error.
    error = row.get("error", False)
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
    if one(rows, "PARQUET_INGEST").get("bytes", 0) < 15_000_000_000:
        raise ValueError("corpus is smaller than 15 GB")
    cold_error = one(rows, "PARQUET_COLD_QUERY").get("error")
    if type(cold_error) is not bool:
        raise ValueError("cold summary outcome is missing")
    successful = not cold_error
    hosts = None if scenario == "cloud-v2" else int(scenario.split("-")[2])
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


def worst_path_gate(reference, candidate):
    if candidate is None:
        return True
    if candidate["error"]:
        return False
    if not candidate["time_budget"]:
        return True
    return (not reference["error"] and reference["time_budget"]
            and reference["truncated"] and candidate["truncated"])


def query_regressions(reference, candidate):
    return [
        {"scope": scope, "query": query, "reference_p95_ns": reference[scope, query],
         "candidate_p95_ns": latency}
        for (scope, query), latency in sorted(candidate.items())
        if latency * 10 > reference[scope, query] * 11
        and latency - reference[scope, query] > QUERY_SLACK
    ]


def evaluate(data):
    results = []
    seen = set()
    for artifact in data["artifacts"]:
        scenario = artifact["name"].removeprefix("common-schema-")
        if scenario not in SCENARIOS or scenario in seen:
            raise ValueError("unexpected or duplicate scenario")
        seen.add(scenario)
        stages = artifact["stages"]
        # Two-stage runs compare default V2 (baseline) directly with mapped V3.
        # Older three-stage runs keep their explicit V2 reference.
        reference = stages["reference"] if "reference" in stages else stages["baseline"]
        ref_wall, ref_queries, reference_ok, ref_worst = full_sample(reference, scenario)
        candidate = artifact["stages"]["candidate"]
        wall, queries, candidate_ok, worst = full_sample(candidate, scenario)
        stress = scenario.startswith("endpoint-") and not scenario.endswith("-chronological")
        limit = (1350 if stress else 900) * SECOND
        relative_ingest = wall * 10 <= ref_wall * 11
        regressions = query_regressions(ref_queries, queries)
        relative_queries = not regressions
        worst_ok = worst_path_gate(ref_worst, worst)
        deadlines = candidate_ok and worst_ok
        absolute = wall < limit
        eligible = absolute and (stress or relative_ingest) and relative_queries and deadlines
        results.append({"scenario": scenario, "reference_wall_ns": ref_wall,
                        "candidate_wall_ns": wall, "absolute_ingest": absolute,
                        "relative_ingest": relative_ingest, "relative_ingest_required": not stress,
                        "relative_queries": relative_queries, "query_regressions": regressions,
                        "query_deadlines": deadlines, "ordinary_queries_successful": candidate_ok,
                        "reference_queries_successful": reference_ok,
                        "worst_path_gate": worst_ok, "reference_worst_path": ref_worst,
                        "candidate_worst_path": worst, "eligible": eligible})
    if seen != SCENARIOS:
        raise ValueError("full nine-scenario matrix is required")
    return {"criteria": "analyst-v3-activation-v2", "run_url": data["run_url"],
            "eligible": all(row["eligible"] for row in results),
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
