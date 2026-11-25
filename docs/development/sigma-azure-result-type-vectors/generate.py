#!/usr/bin/env python3
"""Independent proposed decimal projection and receipt vectors."""
import json
import re
import runpy
from pathlib import Path

root = Path(__file__).resolve().parents[3]
module = runpy.run_path(str(root / "crates/testkit/fixtures/contracts/sigma_source_class_compilation.py"))
scenario = module["scenario"]
model = scenario.__globals__
model["CLASSES"] = [(
    "entra-signin-table", "azure", "signinlogs", "parser-entra", "entra-source-v1",
    "mapping-entra-signin-table", "entra-v1-synthetic",
    module["field"]("ResultType", "integer", ["ResultType"])[:-1]
    + ', projection = "azure_signin_result_type_decimal_v1" }',
)]
# Replace the shared generator's synthetic discriminator with the exact proposed discriminator.
model["TABLE"] = module["make_table"](model["CLASSES"])
old = b'{ path = ["dataset"], equals = "entra-signin-table" }'
new = b'{ path = ["Type"], equals = "SigninLogs" }'
table = model["TABLE"]
header, start, toml = table.partition(b"[[variants]]")
assert start and toml.count(old) == 1
model["TABLE"] = header[:-4] + module["text"]((start + toml).replace(old, new).decode())
model["RULES"] = {"ip-range": module["make_rule"]("ip-range", "ResultType: 50053", "selection", "azure", "signinlogs")}
wire = module["wire"]
text = module["text"]


def project(row):
    value = row.get("ResultType")
    if value is None:
        return b"\x01"
    if not isinstance(value, str):
        return b"\x02"
    if len(value.encode()) > 6:
        return b"\x04"
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,5})", value):
        return b"\x03"
    return b"\x00" + module["u64"](int(value))


def make_case(gap):
    item = scenario([0], {"ip-range": [1]}, {"ip-range": (0, None)},
                    5 if gap else 0, hits=() if gap else [("ip-range", 0, 1)], row_gap=gap)
    v3 = bytes.fromhex(item["receipt"]["bytes_hex"])
    assert v3.count(text("irmind-sigma-evaluator-v3")) == 1
    v4 = v3.replace(text("irmind-sigma-evaluator-v3"), text("irmind-sigma-evaluator-v4"))
    item["receipt"] = wire(v4)
    return item


hit, gap = make_case(False), make_case(True)
cases = [{}, {"ResultType": None}] + [
    {"ResultType": value} for value in
    ("0", "50053", "999999", "1000000", 50053, False, [], {}, "", "00",
     "+42", "-1", " 42", "٤٢", "1e2", "1.0", "Failure")
]
print(json.dumps({
    "table": wire(model["TABLE"]),
    "rule": model["RULES"]["ip-range"],
    "projections": [{"row": row, "expected": project(row).hex()} for row in cases],
    "hit": hit,
    "indeterminate": gap,
    "invalid_evaluator_downgrade": wire(bytes.fromhex(gap["receipt"]["bytes_hex"]).replace(
        text("irmind-sigma-evaluator-v4"), text("irmind-sigma-evaluator-v3"))),
    "invalid_results_swap": {"receipt": gap["receipt"], "results": hit["results"]},
}, indent=2, ensure_ascii=False))
