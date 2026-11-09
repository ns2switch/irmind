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
        rows.append({"metric": "PARQUET_WORST_PATH", "time_budget": False,
                     "truncated": False, "error": False})
    return rows


def matrix():
    return {"run_url": "synthetic test", "artifacts": [
        {"name": f"common-schema-{scenario}",
         "stages": {"reference": sample(scenario), "candidate": sample(scenario)}}
        for scenario in sorted(gates.SCENARIOS)]}


class ActivationGates(unittest.TestCase):
    def test_both_relative_query_boundaries_are_strict(self):
        for reference, accepted, rejected in (
            (4_000_000_000, 4_400_000_000, 4_400_000_001),
            (1_000_000_000, 1_250_000_000, 1_250_000_001),
        ):
            data = matrix()
            stages = data["artifacts"][0]["stages"]
            ref = next(r for r in stages["reference"] if r["metric"] == "PARQUET_QUERY_EXACT")
            query = next(r for r in stages["candidate"] if r["metric"] == "PARQUET_QUERY_EXACT")
            ref["p95_ns"], query["p95_ns"] = reference, accepted
            self.assertTrue(gates.evaluate(data)["eligible"])
            query["p95_ns"] = rejected
            self.assertFalse(gates.evaluate(data)["eligible"])

    def test_large_percentage_with_small_absolute_delta_is_allowed(self):
        data = matrix()
        stages = data["artifacts"][0]["stages"]
        for stage, latency in (("reference", 10_000_000), ("candidate", 200_000_000)):
            next(r for r in stages[stage] if r["metric"] == "PARQUET_QUERY_EXACT")["p95_ns"] = latency
        self.assertTrue(gates.evaluate(data)["eligible"])

    def test_absolute_target_is_required_even_when_reference_misses_it(self):
        data = matrix()
        stages = data["artifacts"][0]["stages"]
        stages["reference"] = sample("cloud-v2", 1000 * gates.SECOND)
        stages["candidate"] = sample("cloud-v2", 950 * gates.SECOND)
        self.assertFalse(gates.evaluate(data)["eligible"])

    def test_stress_relative_ingestion_is_reported_but_not_a_gate(self):
        data = matrix()
        scenario = "endpoint-v2-64"
        stages = next(a["stages"] for a in data["artifacts"] if a["name"].endswith(scenario))
        stages["candidate"] = sample(scenario, 1349 * gates.SECOND)
        result = gates.evaluate(data)
        row = next(r for r in result["scenarios"] if r["scenario"] == scenario)
        self.assertTrue(result["eligible"])
        self.assertFalse(row["relative_ingest"])
        self.assertFalse(row["relative_ingest_required"])
        stages["candidate"][2]["wall_ns"] = 1350 * gates.SECOND
        self.assertFalse(gates.evaluate(data)["eligible"])

    def test_chronological_relative_ingestion_remains_a_gate(self):
        data = matrix()
        scenario = "endpoint-v2-64-chronological"
        stages = next(a["stages"] for a in data["artifacts"] if a["name"].endswith(scenario))
        stages["reference"] = sample(scenario, 700 * gates.SECOND)
        stages["candidate"] = sample(scenario, 771 * gates.SECOND)
        self.assertFalse(gates.evaluate(data)["eligible"])

    def test_two_stage_run_uses_its_default_v2_baseline(self):
        data = matrix()
        for artifact in data["artifacts"]:
            artifact["stages"]["baseline"] = artifact["stages"].pop("reference")
        self.assertTrue(gates.evaluate(data)["eligible"])

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
        self.assertFalse(gates.evaluate(data)["eligible"])

    def test_deliberate_path_timeout_requires_matching_partial_success(self):
        data = matrix()
        stages = data["artifacts"][0]["stages"]
        for rows in stages.values():
            rows[-1].update(time_budget=True, truncated=True)
        self.assertTrue(gates.evaluate(data)["eligible"])
        stages["reference"][-1].update(time_budget=False, truncated=False)
        self.assertFalse(gates.evaluate(data)["eligible"])
        stages["reference"][-1].update(time_budget=True, truncated=True, error=True)
        self.assertFalse(gates.evaluate(data)["eligible"])
        stages["reference"][-1]["error"] = False
        stages["candidate"][-1]["error"] = True
        self.assertFalse(gates.evaluate(data)["eligible"])

    def test_missing_or_contradictory_partial_marker_is_invalid_evidence(self):
        for mutation in ("missing", "false", "wrong_type"):
            data = matrix()
            worst = data["artifacts"][0]["stages"]["candidate"][-1]
            worst["time_budget"] = True
            if mutation == "missing":
                del worst["truncated"]
            else:
                worst["truncated"] = False if mutation == "false" else "true"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gates.evaluate(data)

    def test_historical_successful_worst_path_metric_has_no_error_field(self):
        data = matrix()
        for rows in data["artifacts"][0]["stages"].values():
            del rows[-1]["error"]
            rows[-1].update(time_budget=True, truncated=True)
        self.assertTrue(gates.evaluate(data)["eligible"])

    def test_query_deadline_is_never_waived(self):
        data = matrix()
        for stage in data["artifacts"][0]["stages"].values():
            for row in stage:
                if row["metric"] == "PARQUET_QUERY_EXACT":
                    row["p95_ns"] = 10 * gates.SECOND
        self.assertFalse(gates.evaluate(data)["eligible"])


if __name__ == "__main__":
    unittest.main()
