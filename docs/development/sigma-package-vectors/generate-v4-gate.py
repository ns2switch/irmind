#!/usr/bin/env python3
"""Generate the proposed gated V4 pair without the Rust encoder."""
import json
import runpy
import struct
from pathlib import Path

wire = runpy.run_path(str(Path(__file__).with_name("generate.py")))
sha, text, u64, vector = (wire[key] for key in ("sha", "text", "u64", "vector"))
marker = "irmind-sigma-evaluator-v4-case-admission-v1"
case_id = "00000000-0000-4000-8000-000000000010"
previous = sha(b"synthetic package case before admission")
scope, inventory, manifest, global_admission, compiled, table, result, proof_set = (
    sha(label.encode()) for label in (
        "scope", "inventory", "manifest", "global admission", "compiled", "decimal table",
        "V3 result for the decimal projection", "proof set",
    )
)
times = struct.pack(">qq", 10, 20)
reservation = u64(1000)
before = text(case_id) + u64(9) + previous
# This fixture uses direct import, so the installation digest is absent.
claim = (
    b"irmind-sigma-case-run-admission-v1\0" + before + b"\0"
    + global_admission + manifest + inventory + scope + times + table + compiled
    + text(marker) + reservation
)
entry, challenge = wire["signed_case_admission"](claim, case_id, previous)
admission = json.loads(entry)
after = text(case_id) + u64(admission["seq"]) + bytes(admission["hash"])
run_prefix = (
    b"irmind-sigma-run-v1\0" + after + global_admission + inventory + scope + times
    + compiled + table
)
run_tail = reservation + u64(7) + b"\0" + u64(0) + result + proof_set
print(json.dumps({
    "admission": vector(claim),
    "signed_admission": vector(entry),
    "admission_challenge": vector(challenge),
    "following_run": vector(run_prefix + text(marker) + run_tail),
    "invalid_following_run_without_gate_identity": vector(
        run_prefix + text("irmind-sigma-evaluator-v4") + run_tail
    ),
}, indent=2))
