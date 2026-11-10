#!/usr/bin/env python3
"""Keep public benchmark records bounded and independent of unstructured logs."""
import unittest
from unittest.mock import patch

import collect_graph_metrics as collector


class MetricCollection(unittest.TestCase):
    def test_public_records_keep_only_allowlisted_fields(self):
        records = collector.parse_log(b"unstructured output\nPARQUET_QUERY scenario=cloud scope=all name=entity p95_seconds=1.25 errors=0 ignored=value\nPARQUET_COLD_QUERY seconds=0.5 error=false")
        self.assertEqual(records, [
            {"metric": "PARQUET_QUERY", "scenario": "cloud", "scope": "all", "name": "entity", "p95_seconds": 1.25, "errors": 0},
            {"metric": "PARQUET_COLD_QUERY", "seconds": 0.5, "error": False},
        ])

    def test_nonblocking_ingestion_goal_and_explicit_path_status_are_preserved(self):
        rows = collector.parse_log(b"PARQUET_INGEST_LIMIT seconds=1350 met=false required=false\nPARQUET_WORST_PATH seconds=10.01 truncated=true time_budget=true error=false")
        self.assertIs(rows[0]["met"], False)
        self.assertIs(rows[0]["required"], False)
        self.assertIs(rows[1]["error"], False)
        self.assertIs(rows[1]["truncated"], True)

    def test_exact_nanoseconds_do_not_pass_through_floating_point(self):
        records = collector.parse_log(b"PARQUET_INGEST_EXACT wall_ns=900000000001\nPARQUET_QUERY_EXACT scenario=cloud scope=all name=entity p50_ns=1000000001 p95_ns=1100000001 errors=0")
        self.assertEqual(records[0]["wall_ns"], 900000000001)
        self.assertEqual(records[1]["p95_ns"], 1100000001)
        self.assertIs(type(records[1]["p95_ns"]), int)

    def test_invalid_identifiers_and_durations_are_rejected(self):
        for line in [b"PARQUET_QUERY scenario=../invalid", b"PARQUET_QUERY p95_seconds=nan", b"PARQUET_QUERY p95_seconds=-1", b"PARQUET_QUERY errors=-1", b"PARQUET_COLD_QUERY error=unknown"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                collector.parse_log(line)

    def test_duplicate_and_oversized_metrics_are_rejected(self):
        with self.assertRaises(ValueError):
            collector.parse_log(b"PARQUET_INGEST_EXACT wall_ns=1 wall_ns=2")
        with patch.object(collector, "MAX_LOG", 2), self.assertRaises(ValueError):
            collector.parse_log(b"abc")


if __name__ == "__main__":
    unittest.main()
