#!/usr/bin/env python3
"""Proposed Sigma v2 table and retained-text vectors. Uses only the standard library."""

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).parent
FORMAT = "irmind-kubernetes-sigma-projection-v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def commitment(raw):
    return {
        "bytes_hex": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def text(value):
    return struct.pack(">I", len(value)) + value


def common(parser, action):
    return {
        "context": {},
        "event": {"action": action, "category": ["api"], "kind": "event",
                  "outcome": "unknown", "type": ["access"]},
        "observations": [],
        "origin": {
            "offset": 0,
            "parser": parser,
            "parser_version": parser.removeprefix("parser-") + "-source-v1",
            "record": 0,
            "source": "01" * 32,
        },
        "schema": "irmind-common-event-v1",
        "timestamp": None,
    }


def projection(label, parser, action, input_record, original, unavailable=None, xff=None):
    envelope = {
        "common": common(parser, action),
        "format": FORMAT,
        "original": original,
        "unavailable": unavailable or {},
    }
    expected = {
        "case": label,
        "source": input_record,
        "retained": envelope,
        **commitment(canonical(envelope)),
    }
    if xff is not None:
        expected["request"] = {"X-Forwarded-For": xff}
    if unavailable:
        expected["exact_field_rule_result"] = "partial"
    return expected


def partial_run_vectors():
    # A rule matches a healthy row and is indeterminate for two other rows.
    # A second source supplies a separate unavailable field to another rule.
    def sha(raw):
        return hashlib.sha256(raw).digest()

    def u64(value):
        return struct.pack(">Q", value)

    def entries(*items):
        return u64(len(items)) + b"".join(items)

    def ref(sequence, name):
        return u64(sequence) + sha(name)

    ip = text(b"synthetic-ip-rule") + sha(b"synthetic IP rule")
    status = text(b"synthetic-status-rule") + sha(b"synthetic status rule")
    kubernetes = ref(2, b"synthetic Kubernetes manifest") + sha(b"synthetic Kubernetes original")
    gke = ref(4, b"synthetic GKE manifest") + sha(b"synthetic GKE original")
    row = kubernetes + u64(9) + ref(3, b"synthetic Kubernetes artifact") + sha(b"synthetic Parquet") + u64(5)
    prefix = (b"irmind-sigma-run-results-v3\0"
              + entries(ip + bytes(2), status + bytes(2))
              + entries(ip + row + bytes(1)))
    rule_counts = entries(ip + u64(2), status + u64(1))
    matrix = entries(u64(3), u64(6)) + u64(2) + bytes([1, 4])
    tail = rule_counts + matrix
    results = prefix + entries(kubernetes + u64(2), gke + u64(1)) + tail

    return {
        "results": commitment(results),
        "invalid_results": {
            "duplicate_source": commitment(prefix + entries(kubernetes + u64(2), kubernetes + u64(1)) + tail),
            "zero_source_rows": commitment(prefix + entries(kubernetes + u64(0), gke + u64(1)) + tail),
        },
        "expected_coverage": {
            "one_valid_match": True,
            "distinct_unavailable_rows_by_source": {"kubernetes": 2, "gke": 1},
            "indeterminate_rows_by_rule": {"synthetic-ip-rule": 2, "synthetic-status-rule": 1},
            "run_status": "exact_fields_unavailable",
            "report_limitations": "include_partial_sigma_run",
        },
    }


def main():
    addresses = ["203.0.113.8", "2001:0db8::1", "192.0.2.9"]
    kubernetes = "parser-kubernetes"
    gke = "parser-gcp-audit"
    gke_action = "io.k8s.core.v1.secrets.get"
    xff_addresses = [f"192.0.2.{n}" for n in range(1, 34)]
    table = ROOT.joinpath("sigma_exact_source_fields.toml").read_bytes()
    proof = b"irmind-sigma-field-table-v1\0" + b"".join(
        map(text, [b"irmind-sigma-source-coverage", b"v2", table])
    )
    vectors = {
        "field_table_wire_v1": commitment(proof),
        "retained_text": [
            projection("native", kubernetes, "get",
                       {"sourceIPs": addresses, "requestObject": {"ignored": True}},
                       {"sourceIPs": addresses}),
            projection("wrapped_eks_or_aks", kubernetes, "get",
                       {"audit_event": {"sourceIPs": addresses, "responseObject": {"ignored": True}}},
                       {"audit_event": {"sourceIPs": addresses}}),
            projection("explicit_empty_list", kubernetes, "get", {"sourceIPs": []}, {"sourceIPs": []}),
            projection("missing_list", kubernetes, "get", {}, {}),
            projection("gke_status", gke, gke_action,
                       {"protoPayload": {"status": {"code": 7, "message": "not retained"}}},
                       {"protoPayload": {"status": {"code": 7}}}),
            projection("gke_missing_status", gke, gke_action, {"protoPayload": {}}, {}),
            projection("xff_33_ips", kubernetes, "get", {"sourceIPs": xff_addresses},
                       {}, {"sourceIPs": "overflow"}, ", ".join(xff_addresses)),
            projection("invalid_first_ip", kubernetes, "get",
                       {"sourceIPs": ["not-an-ip", "203.0.113.8"]},
                       {}, {"sourceIPs": "invalid_ip"}),
            projection("duplicate_ip", kubernetes, "get",
                       {"sourceIPs": ["203.0.113.8", "203.0.113.8"]},
                       {}, {"sourceIPs": "duplicate"}),
            projection("wrapped_duplicate_ipv6_spelling", kubernetes, "get",
                       {"audit_event": {"sourceIPs": ["2001:0db8::1", "2001:db8::1"]}},
                       {}, {"audit_event.sourceIPs": "duplicate"}),
            projection("non_string_ip", kubernetes, "get",
                       {"sourceIPs": ["203.0.113.8", 4]},
                       {}, {"sourceIPs": "unexpected_type"}),
            projection("non_array_ips", kubernetes, "get",
                       {"sourceIPs": "203.0.113.8"}, {}, {"sourceIPs": "unexpected_type"}),
            projection("gke_string_status", gke, gke_action,
                       {"protoPayload": {"status": {"code": "7"}}},
                       {}, {"protoPayload.status.code": "unexpected_type"}),
            projection("gke_null_status", gke, gke_action,
                       {"protoPayload": {"status": {"code": None}}},
                       {}, {"protoPayload.status.code": "unexpected_type"}),
            projection("gke_unassigned_status", gke, gke_action,
                       {"protoPayload": {"status": {"code": 17}}},
                       {}, {"protoPayload.status.code": "overflow"}),
            projection("gke_integer_width_overflow", gke, gke_action,
                       {"protoPayload": {"status": {"code": 2147483648}}},
                       {}, {"protoPayload.status.code": "overflow"}),
            projection("gke_negative_status", gke, gke_action,
                       {"protoPayload": {"status": {"code": -1}}},
                       {}, {"protoPayload.status.code": "overflow"}),
        ],
        "partial_run_wire": partial_run_vectors(),
        "defender_bindings": [
            {
                "case": "complete_paths",
                "source": {
                    "FolderPath": r"C:\Synthetic\Worker.EXE",
                    "FileName": "worker.exe",
                    "InitiatingProcessFolderPath": r"C:\Synthetic\Launcher.exe",
                    "InitiatingProcessFileName": "Launcher.exe",
                },
                "expected": {
                    "Image": r"C:\Synthetic\Worker.EXE",
                    "ParentImage": r"C:\Synthetic\Launcher.exe",
                },
            },
            {
                "case": "directory_only_or_filename_mismatch",
                "source": {
                    "FolderPath": r"C:\Synthetic",
                    "FileName": "worker.exe",
                    "InitiatingProcessFolderPath": r"C:\Synthetic\NotLauncher.exe",
                    "InitiatingProcessFileName": "Launcher.exe",
                },
                "expected": {},
            },
        ],
        "evtx_bindings": [
            {"source": {"EventID": "4625", "LogonType": "3"}, "expected": {"EventID": 4625, "LogonType": 3}},
            {"source": {"EventID": "65536", "LogonType": "256"}, "reject": True},
        ],
        "m365_pairs": {
            "source": {"Parameters": [{"Name": "SyntheticFirst", "Value": "1"},
                                      {"Name": "SyntheticSecond", "Value": "2"}]},
            "matches": {"Name": "SyntheticFirst", "Value": "1"},
            "does_not_match": {"Name": "SyntheticFirst", "Value": "2"},
        },
    }
    print(json.dumps(vectors, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
