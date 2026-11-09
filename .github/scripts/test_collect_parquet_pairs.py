#!/usr/bin/env python3
"""Keep public benchmark records bounded and independent of unstructured logs."""
import io
import json
import unittest
import zipfile
from unittest.mock import MagicMock, patch

import collect_parquet_pairs as collector


class MetricCollection(unittest.TestCase):
    def test_public_records_keep_only_allowlisted_fields(self):
        records = collector.parse_log(b"unstructured output\nPARQUET_QUERY scenario=cloud-v2 scope=all name=entity p95_seconds=1.25 errors=0 ignored=value\nPARQUET_COLD_QUERY seconds=0.5 error=false")
        self.assertEqual(records, [
            {"metric": "PARQUET_QUERY", "scenario": "cloud-v2", "scope": "all", "name": "entity", "p95_seconds": 1.25, "errors": 0},
            {"metric": "PARQUET_COLD_QUERY", "seconds": 0.5, "error": False},
        ])

    def test_exact_nanoseconds_do_not_pass_through_floating_point(self):
        records = collector.parse_log(b"PARQUET_INGEST_EXACT wall_ns=900000000001\nPARQUET_QUERY_EXACT scenario=cloud-v2 scope=all name=entity p50_ns=1000000001 p95_ns=1100000001 errors=0")
        self.assertEqual(records[0]["wall_ns"], 900000000001)
        self.assertEqual(records[1]["p95_ns"], 1100000001)
        self.assertIs(type(records[1]["p95_ns"]), int)

    def test_invalid_identifiers_and_durations_are_rejected(self):
        for line in [b"PARQUET_QUERY scenario=../invalid", b"PARQUET_QUERY p95_seconds=nan", b"PARQUET_QUERY p95_seconds=-1", b"PARQUET_QUERY errors=-1", b"PARQUET_COLD_QUERY error=unknown"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                collector.parse_log(line)

    def test_raw_download_stops_at_the_byte_limit(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.stdout.read.return_value = b"123"
        process.poll.return_value = None
        with patch.object(collector, "MAX_ARCHIVE", 2), patch.object(collector.subprocess, "Popen", return_value=process), self.assertRaisesRegex(RuntimeError, "limit exceeded"):
            collector.download("actions/artifacts/1/zip")
        process.stdout.read.assert_called_once_with(3)
        process.kill.assert_called()

    def test_archive_member_and_expanded_size_are_bounded(self):
        for name, payload in [("../unexpected", b"x"), ("benchmark-pair-baseline.txt", b"x" * 33)]:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr(name, payload)
            metadata = json.dumps({"artifacts": [{"id": 1, "name": "parquet-pair-cloud-v2", "expired": False, "size_in_bytes": len(archive.getvalue())}]}).encode()
            with self.subTest(name=name), patch.object(collector, "MAX_LOG", 32), patch.object(collector, "fetch", side_effect=[metadata, archive.getvalue()]), self.assertRaises(ValueError):
                collector.collect(1)


if __name__ == "__main__":
    unittest.main()
