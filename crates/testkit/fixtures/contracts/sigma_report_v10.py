#!/usr/bin/env python3
"""Independent proposed V10 wire examples using only Python's standard library."""
import hashlib
import json
import struct

def sha(data):
    return hashlib.sha256(data).digest()

def tag(name):
    return name.encode("ascii") + bytes(1)

def text(value):
    value = value.encode("utf-8")
    return struct.pack(">I", len(value)) + value

def u64(value):
    return struct.pack(">Q", value)

def optional_hash(value):
    return bytes(1) if value is None else bytes([1]) + value

def commitment(domain, objects):
    descriptors = sorted(bytes([kind]) + sha(data) + u64(len(data)) for kind, data in objects)
    return sha(tag(domain) + u64(len(descriptors)) + b"".join(descriptors))

def vector(data):
    return {"bytes_hex": data.hex(), "size": len(data), "sha256": sha(data).hex()}

def generate():
    case = "00000000-0000-4000-8000-000000000010"
    checkpoint = text(case) + u64(7) + sha(b"synthetic-audit-entry")
    pack = b"synthetic-pack-manifest"
    rule = b"synthetic-rule-body"
    admission_proofs = commitment("irmind-sigma-proof-set-v1", [(0, pack), (1, rule)])
    admission = (
        tag("irmind-sigma-pack-admission-v1") + sha(pack) + admission_proofs
        + bytes([1]) + text("example-synthetic-v1") + optional_hash(sha(b"synthetic-archive"))
        + text("MIT OR Apache-2.0")
    )

    def run(status, used, matches, result):
        table, scope, rules = b"example-field-table", b"example-scope", b"example-compiled-rules"
        proofs = commitment("irmind-sigma-proof-set-v1", [(2, table), (3, scope), (4, rules), (5, result)])
        return (
            tag("irmind-sigma-run-v1") + checkpoint
            + sha(b"synthetic-signed-admission-operation") + sha(b"synthetic-active-artifact-inventory")
            + sha(scope) + struct.pack(">qq", 1795392000000000, 1795395600000000)
            + sha(rules) + sha(table) + text("irmind-sigma-evaluator-v1")
            + u64(1500) + u64(used) + bytes([status]) + u64(matches) + sha(result) + proofs
        )

    citations = b"synthetic-citation-manifest"
    analyst = b"synthetic-analyst-authored-sections"
    coverage = b"synthetic-mandatory-coverage-manifest"
    report = b"# Informe de ejemplo\n"
    report_proofs = commitment("irmind-report-proof-set-v1", [
        (0, citations), (1, analyst), (2, coverage), (3, report),
    ])
    publication = (
        tag("irmind-report-published-v1") + checkpoint + sha(citations)
        + optional_hash(None) + optional_hash(sha(analyst)) + sha(coverage)
        + bytes([1]) + text("irmind-report-renderer-v1") + bytes([0])
        + u64(len(report)) + sha(report) + report_proofs
    )

    header = {
        "version": 10,
        "case_id": case,
        "title": "Synthetic V10 layout",
        "severity": "low",
        "scope": "synthetic case",
        "seal": {
            "seq": 7,
            "hash": list(sha(b"synthetic-audit-entry")),
            "sig": list(range(64)),
            "public_key": list(range(32)),
            "analyst_key_fingerprint": sha(bytes(range(32))).hex(),
        },
    }
    header_json = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return {
        "sigma_pack_admission_v1": vector(admission),
        "sigma_run_v1_complete": vector(run(0, 1125, 2, b"synthetic-complete-results")),
        "sigma_run_v1_work_limit": vector(run(2, 1500, 1, b"synthetic-limited-results")),
        "report_published_v1": vector(publication),
        "export_v10_header_frame": vector(tag("IRMIND-EXPORT-V10") + u64(len(header_json)) + header_json),
        "export_v10_empty_sigma_and_report_counts": vector(u64(0) + u64(0)),
    }

if __name__ == "__main__":
    print(json.dumps(generate(), indent=2, sort_keys=True))
