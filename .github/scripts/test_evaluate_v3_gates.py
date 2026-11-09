#!/usr/bin/env python3
"""Require current-V3 absolute evidence without a comparison implementation."""
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
    hosts = None if scenario == "cloud" else int(scenario.split("-")[1])
    scopes = {"all"} if hosts is None else {"all", "endpoint-0000", f"endpoint-{hosts - 1:04}"}
    rows += [{"metric": "PARQUET_QUERY_EXACT", "scenario": scenario, "scope": scope,
              "name": name, "p95_ns": latency, "errors": 0, "time_budget_hits": 0}
             for scope in sorted(scopes) for name in sorted(gates.QUERIES)]
    if hosts is None:
        rows.append({"metric": "PARQUET_WORST_PATH", "time_budget": False,
                     "truncated": False, "error": False})
    return {"scenario": scenario, "writer": "mapped-v3", "records": rows}


def matrix():
    return {"schema": "irmind-v3-measurements-v1", "run_url": "synthetic test",
            "scenarios": [sample(scenario) for scenario in sorted(gates.SCENARIOS)]}


def measured(data, scenario="cloud"):
    return next(row for row in data["scenarios"] if row["scenario"] == scenario)


class AbsoluteTargets(unittest.TestCase):
    def test_current_single_writer_matrix_needs_no_reference(self):
        result = gates.evaluate(matrix())
        self.assertTrue(result["passed"])
        self.assertTrue(result["all_ingest_goals_met"])
        self.assertNotIn("relative", str(result))

    def test_only_current_measurement_format_and_writer_are_accepted(self):
        for mutation in ("schema", "writer"):
            data = matrix()
            if mutation == "schema": data["schema"] = "unknown-format"
            else: measured(data)["writer"] = "another-writer"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gates.evaluate(data)

    def test_cloud_and_chronological_absolute_boundaries_remain_strict(self):
        for scenario in sorted(gates.SCENARIOS):
            if scenario != "cloud" and not scenario.endswith("-chronological"): continue
            data = matrix()
            measured(data, scenario)["records"][2]["wall_ns"] = 900 * gates.SECOND - 1
            self.assertTrue(gates.evaluate(data)["passed"])
            measured(data, scenario)["records"][2]["wall_ns"] += 1
            self.assertFalse(gates.evaluate(data)["passed"])

    def test_other_stress_targets_are_not_waived(self):
        for hosts in (1, 64, 1024):
            data = matrix()
            measured(data, f"endpoint-{hosts}")["records"][2]["wall_ns"] = 1350 * gates.SECOND
            self.assertFalse(gates.evaluate(data)["passed"])

    def test_1025_stress_miss_is_reported_as_nonblocking(self):
        data = matrix()
        measured(data, "endpoint-1025")["records"][2]["wall_ns"] = 1_363_429_007_765
        result = gates.evaluate(data)
        self.assertTrue(result["passed"])
        self.assertFalse(result["all_ingest_goals_met"])
        row = next(r for r in result["scenarios"] if r["scenario"] == "endpoint-1025")
        self.assertFalse(row["ingest_goal_met"])
        self.assertFalse(row["ingest_gate_required"])

    def test_waived_ingestion_never_waives_an_ordinary_query_limit(self):
        data = matrix()
        query = measured(data, "endpoint-1025")["records"][4]
        query["time_budget_hits"] = 1
        self.assertFalse(gates.evaluate(data)["passed"])

    def test_ordinary_latency_is_only_checked_against_its_absolute_limit(self):
        data = matrix()
        measured(data)["records"][4]["p95_ns"] = 9_999_999_999
        self.assertTrue(gates.evaluate(data)["passed"])
        measured(data)["records"][4]["p95_ns"] += 1
        self.assertFalse(gates.evaluate(data)["passed"])

    def test_errors_and_cold_summary_failures_are_not_successes(self):
        for mutation in ("errors", "cold"):
            data = matrix()
            rows = measured(data)["records"]
            if mutation == "errors": rows[4]["errors"] = 1
            else: rows[3]["error"] = True
            with self.subTest(mutation=mutation): self.assertFalse(gates.evaluate(data)["passed"])

    def test_only_explicit_successful_deliberate_partial_results_are_valid(self):
        data = matrix()
        worst = measured(data)["records"][-1]
        worst.update(time_budget=True, truncated=True)
        self.assertTrue(gates.evaluate(data)["passed"])
        worst["error"] = True
        self.assertFalse(gates.evaluate(data)["passed"])
        for mutation in ("missing", "wrong_type", "no_partial"):
            bad = matrix()
            worst = measured(bad)["records"][-1]
            if mutation == "missing": del worst["error"]
            elif mutation == "wrong_type": worst["error"] = "false"
            else: worst.update(time_budget=True, truncated=False)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): gates.evaluate(bad)

    def test_missing_or_duplicate_scenario_or_query_is_rejected(self):
        for mutation in ("scenario", "duplicate_scenario", "query", "duplicate_query"):
            data = matrix()
            if mutation == "scenario": data["scenarios"].pop()
            elif mutation == "duplicate_scenario": data["scenarios"].append(copy.deepcopy(data["scenarios"][0]))
            elif mutation == "query": measured(data)["records"].pop(4)
            else: measured(data)["records"].append(copy.deepcopy(measured(data)["records"][4]))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): gates.evaluate(data)

    def test_missing_exact_nanoseconds_or_full_corpus_are_not_evidence(self):
        for value in (0, -1, True, 1.5, None):
            data = matrix()
            measured(data)["records"][2]["wall_ns"] = value
            with self.subTest(value=value), self.assertRaises(ValueError): gates.evaluate(data)
        for size in (14_999_999_999, True, 15_000_000_000.0):
            data = matrix()
            measured(data)["records"][1]["bytes"] = size
            with self.subTest(size=size), self.assertRaises(ValueError): gates.evaluate(data)

    def test_smoke_repetitions_cannot_replace_the_full_sample(self):
        data = matrix()
        measured(data)["records"][0]["size"] = "1gib"
        with self.assertRaises(ValueError): gates.evaluate(data)


if __name__ == "__main__": unittest.main()
