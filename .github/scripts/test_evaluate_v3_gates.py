#!/usr/bin/env python3
"""Fail closed on incomplete evidence and test the analyst's exact boundaries."""
import copy
import unittest
import evaluate_v3_gates as gates


def sample(scenario, wall=800 * gates.SECOND, latency=gates.SECOND):
    rows = [
        {"metric": "PARQUET_SCENARIO", "name": scenario, "size": "15gb"},
        {"metric": "PARQUET_INGEST", "bytes": 15_000_000_000},
        {"metric": "PARQUET_INGEST_EXACT", "wall_ns": wall},
        {"metric": "PARQUET_COLD_QUERY", "error": False},
    ]
    hosts = None if scenario == "cloud-v2" else int(scenario.split("-")[2])
    scopes = {"all"} if hosts is None else {"all", "endpoint-0000", f"endpoint-{hosts - 1:04}"}
    rows += [{"metric": "PARQUET_QUERY_EXACT", "scenario": scenario, "scope": scope,
              "name": name, "p95_ns": latency, "errors": 0, "time_budget_hits": 0}
             for scope in sorted(scopes) for name in sorted(gates.QUERIES)]
    if hosts is None:
        rows.append({"metric": "PARQUET_WORST_PATH", "time_budget": False})
    return rows


def matrix():
    return {"run_url": "synthetic test", "artifacts": [
        {"name": f"common-schema-{scenario}",
         "stages": {"reference": sample(scenario), "candidate": sample(scenario)}}
        for scenario in sorted(gates.SCENARIOS)]}


class ActivationGates(unittest.TestCase):
    def test_exact_ten_percent_and_one_nanosecond_regression(self):
        data = matrix()
        candidate = data["artifacts"][0]["stages"]["candidate"]
        query = next(row for row in candidate if row["metric"] == "PARQUET_QUERY_EXACT")
        query["p95_ns"] = 1_100_000_000
        self.assertTrue(gates.evaluate(data)["eligible"])
        query["p95_ns"] += 1
        self.assertFalse(gates.evaluate(data)["eligible"])

    def test_reference_absolute_miss_uses_relative_gate_without_deadline_waiver(self):
        data = matrix()
        stages = data["artifacts"][0]["stages"]
        stages["reference"] = sample("cloud-v2", 1000 * gates.SECOND)
        stages["candidate"] = sample("cloud-v2", 1090 * gates.SECOND)
        self.assertTrue(gates.evaluate(data)["eligible"])
        stages["candidate"][-1]["time_budget"] = True
        with self.assertRaisesRegex(ValueError, "time budget"):
            gates.evaluate(data)

    def test_missing_scenario_query_or_exact_duration_is_not_evidence(self):
        complete = matrix()
        for mutation in ("scenario", "query", "duration"):
            data = copy.deepcopy(complete)
            candidate = data["artifacts"][0]["stages"]["candidate"]
            if mutation == "scenario":
                data["artifacts"].pop()
            elif mutation == "query":
                candidate.pop(4)
            else:
                candidate[2]["wall_ns"] = 1.5
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gates.evaluate(data)

    def test_reported_time_budget_truncation_is_not_a_success(self):
        data = matrix()
        data["artifacts"][0]["stages"]["candidate"][4]["time_budget_hits"] = 1
        with self.assertRaisesRegex(ValueError, "failed query"):
            gates.evaluate(data)

    def test_query_deadline_is_never_waived(self):
        data = matrix()
        for stage in data["artifacts"][0]["stages"].values():
            for row in stage:
                if row["metric"] == "PARQUET_QUERY_EXACT":
                    row["p95_ns"] = 10 * gates.SECOND
        self.assertFalse(gates.evaluate(data)["eligible"])


if __name__ == "__main__":
    unittest.main()
