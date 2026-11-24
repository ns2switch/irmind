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


def projection(label, parser, action, input_record, original):
    envelope = {"common": common(parser, action), "format": FORMAT, "original": original}
    return {
        "case": label,
        "source": input_record,
        "common": envelope["common"],
        "retained": envelope,
        **commitment(canonical(envelope)),
    }


def main():
    addresses = ["203.0.113.8", "2001:0db8::1", "192.0.2.9"]
    kubernetes = "parser-kubernetes"
    gke = "parser-gcp-audit"
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
            projection("gke_status", gke, "io.k8s.core.v1.secrets.get",
                       {"protoPayload": {"status": {"code": 7, "message": "not retained"}}},
                       {"protoPayload": {"status": {"code": 7}}}),
            projection("gke_missing_status", gke, "io.k8s.core.v1.secrets.get", {"protoPayload": {}}, {}),
        ],
        "projection_rejections": [
            {"case": "invalid_ip", "source": {"sourceIPs": ["203.0.113.8", "not-an-ip"]}},
            {"case": "duplicate_ip", "source": {"sourceIPs": ["203.0.113.8", "203.0.113.8"]}},
            {"case": "duplicate_ipv6_spelling", "source": {"sourceIPs": ["2001:0db8::1", "2001:db8::1"]}},
            {"case": "too_many_ips", "source": {"sourceIPs": [f"192.0.2.{n}" for n in range(1, 34)]}},
            {"case": "string_status", "source": {"protoPayload": {"status": {"code": "7"}}}},
        ],
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
