#!/usr/bin/env python3
"""Independent synthetic Sigma V3 proof vectors. Uses only the standard library."""

import hashlib
import json
import struct


def sha(body):
    return hashlib.sha256(body).digest()


def wire(body):
    return {"bytes_hex": body.hex(), "sha256": sha(body).hex()}


def u64(value):
    return struct.pack(">Q", value)


def text(value):
    body = value.encode("utf-8")
    return struct.pack(">I", len(body)) + body


def items(entries):
    return u64(len(entries)) + b"".join(entries)


def audit_reference(sequence, label):
    return u64(sequence) + sha(label.encode())


def make_table(classes):
    variants = []
    for name, product, service, parser, decoder, mapping, recipe, field in classes:
        variants.append(
            "[[variants]]\n"
            f'product = "{product}"\n'
            f'service = "{service}"\n'
            f'parser_id = "{parser}"\n'
            f'parser_version = "{decoder}"\n'
            f'mapping_id = "{mapping}"\n'
            f'mapping_version = "{recipe}"\n'
            f'dataset = "{name}"\n'
            f'events = [{{ path = ["dataset"], equals = "{name}" }}]\n'
            f"fields = [{field}]\n"
        )
    return (
        b"irmind-sigma-field-table-v1\0"
        + text("irmind-synthetic-class-coverage")
        + text("v1")
        + text("\n".join(variants))
    )


def field(name, kind, path):
    return (
        f'{{ name = "{name}", path = {json.dumps(path)}, value_type = "{kind}", '
        'null_policy = "absent" }'
    )


# AKS deliberately has a synthetic text binding to exercise a type conflict.
# This fixture is a wire example, not an update to any enrolled field table.
CLASSES = [
    (
        "native", "kubernetes", "audit", "parser-kubernetes", "kubernetes-source-v1",
        "mapping-kubernetes", "kubernetes-audit-tables-v2",
        field("sourceIPs", "ip_list", ["original", "sourceIPs"]),
    ),
    (
        "cloudtrail", "aws", "cloudtrail", "parser-json", "json-stream-v3",
        "mapping-cloudtrail", "synthetic-cloudtrail-v1",
        field("eventName", "text", ["eventName"]),
    ),
    (
        "eks", "kubernetes", "audit", "parser-eks-audit", "eks-audit-source-v1",
        "mapping-eks-audit", "kubernetes-audit-tables-v2",
        field("sourceIPs", "ip_list", ["original", "audit_event", "sourceIPs"]),
    ),
    (
        "gke", "kubernetes", "audit", "parser-gcp-audit", "gcp-audit-source-v1",
        "mapping-gke-audit", "gke-paths-v2-synthetic",
        field("protoPayload.status.code", "integer", ["original", "protoPayload", "status", "code"]),
    ),
    (
        "aks", "kubernetes", "audit", "parser-aks-audit", "aks-audit-source-v1",
        "mapping-aks-audit", "kubernetes-audit-tables-v2",
        field("sourceIPs", "text", ["original", "audit_event", "sourceIPs"]),
    ),
]
TABLE = make_table(CLASSES)


def make_rule(rule_id, selection, condition, product="kubernetes", service="audit"):
    return (
        f"title: Synthetic {rule_id}\n"
        f"id: {rule_id}\n"
        "logsource:\n"
        f"  product: {product}\n"
        f"  service: {service}\n"
        "detection:\n"
        "  selection:\n"
        f"    {selection}\n"
        f"  condition: {condition}\n"
    )


RULES = {
    "ip-range": make_rule("ip-range", "sourceIPs|cidr: '192.0.2.0/24'", "selection"),
    "unknown-selection": make_rule("unknown-selection", "OtherField: true", "not missing"),
    "other-logsource": make_rule(
        "other-logsource", "CommandLine: synthetic", "selection", "windows", "sysmon",
    ),
    "inactive-source": make_rule(
        "inactive-source", "eventName: Synthetic", "selection", "aws", "cloudtrail",
    ),
}


def rule_key(rule_id):
    return text(rule_id) + sha(RULES[rule_id].encode())


def source_reference(class_ordinal):
    label = CLASSES[class_ordinal][0]
    return audit_reference(2 * class_ordinal + 1, f"synthetic {label} manifest") + sha(
        f"synthetic {label} original".encode()
    )


def row_reference(class_ordinal, record):
    label = CLASSES[class_ordinal][0]
    return (
        source_reference(class_ordinal)
        + u64(record)
        + audit_reference(2 * class_ordinal + 2, f"synthetic {label} artifact")
        + sha(f"synthetic {label} Parquet".encode())
        + u64(record + 5)
    )


def matrix(classes, rule_order, decisions):
    packed = bytearray()
    for rule_id in rule_order:
        cells = decisions[rule_id]
        if len(cells) != len(classes):
            raise ValueError("Each rule needs one decision per class")
        for start in range(0, len(cells), 4):
            packed.append(sum(cell << (2 * position)
                              for position, cell in enumerate(cells[start:start + 4])))
    return items([u64(ordinal) for ordinal in classes]) + u64(len(rule_order)) + packed


def scenario(classes, decisions, coverage, status, hits=(), row_gap=False, matrix_body=None):
    ordered = sorted(decisions)
    scope = b"irmind-sigma-source-scope-v1\0" + items(
        [source_reference(ordinal) for ordinal in classes]
    )
    compiled = b"irmind-sigma-compiled-rules-v1\0" + items([
        rule_key(rule_id) + items([
            u64(ordinal) for ordinal, cell in zip(classes, decisions[rule_id], strict=True)
            if cell == 1
        ])
        for rule_id in ordered
    ])
    results = (
        b"irmind-sigma-run-results-v3\0"
        + items([
            rule_key(rule_id) + bytes([coverage[rule_id][0]])
            + (b"\x00" if coverage[rule_id][1] is None else b"\x01" + text(coverage[rule_id][1]))
            for rule_id in ordered
        ])
        + items([
            rule_key(rule_id) + row_reference(ordinal, record) + b"\x00"
            for rule_id, ordinal, record in hits
        ])
        + items([source_reference(0) + u64(1)] if row_gap else [])
        + items([rule_key("ip-range") + u64(1)] if row_gap else [])
        + (matrix(classes, ordered, decisions) if matrix_body is None else matrix_body)
    )
    descriptors = items([
        bytes([kind]) + sha(body) + u64(len(body))
        for kind, body in [(2, TABLE), (3, scope), (4, compiled), (5, results)]
    ])
    proof_set = sha(b"irmind-sigma-proof-set-v1\0" + descriptors)
    return {
        "status_code": status,
        "scope": wire(scope),
        "compiled_rules": wire(compiled),
        "results": wire(results),
        "proof_set_sha256": proof_set.hex(),
    }


def vectors():
    short = [0, 2]
    wide = [0, 2, 3, 4]
    all_eligible = {"ip-range": [1, 1]}
    mixed = {"ip-range": [1, 1, 2, 3]}
    eligible = {"ip-range": (0, None)}
    one_hit = [("ip-range", 0, 9)]
    absent = {
        "inactive-source": (3, "No signed event artifact matches the rule's reviewed source classes"),
        "other-logsource": (1, "No reviewed variant matches the rule logsource"),
        "unknown-selection": (4, "Rule rejected before source-class compilation"),
    }
    excluded = {key: [0] * len(wide) for key in absent}
    no_classes = {"inactive-source": []}
    none_eligible = {"ip-range": [2, 3]}
    unavailable = {"ip-range": (2, "A matching source class lacks an exact binding for a rule field")}
    matrix_short = matrix(short, ["ip-range"], all_eligible)
    matrix_wide = matrix(wide, ["ip-range"], mixed)
    matrix_drops_rule = matrix(wide, [], {})
    matrix_swaps_eligibility = matrix(wide, ["ip-range"], {"ip-range": [1, 2, 1, 3]})
    wrong_ordinals = matrix([0, 2, 2, 4], ["ip-range"], mixed)
    outside_table = matrix([0, 2, 3, 5], ["ip-range"], mixed)
    wrong_scope = matrix([0, 1, 3, 4], ["ip-range"], mixed)
    return {
        "field_table": wire(TABLE),
        "synthetic_rules": RULES,
        "synthetic_rows": {
            "matching_native": {"dataset": "native", "original": {"sourceIPs": ["192.0.2.9"]}},
            "matching_eks": {
                "dataset": "eks", "original": {"audit_event": {"sourceIPs": ["192.0.2.8"]}}
            },
            "retained_indeterminate_native": {
                "dataset": "native",
                "sourceIPs_original": [f"192.0.2.{n}" for n in range(1, 34)],
                "unavailable": {"sourceIPs": "overflow"},
            },
        },
        "valid": {
            "complete": scenario(short, all_eligible, eligible, 0, one_hit + [("ip-range", 2, 10)]),
            "coverage_limited": scenario(wide, mixed, eligible, 6, one_hit, row_gap=True),
            "exact_rows_only": scenario(short, all_eligible, eligible, 5, one_hit, row_gap=True),
            "cancelled_with_both_gaps": scenario(wide, mixed, eligible, 4, one_hit, row_gap=True),
            "out_of_scope_and_bad_condition": scenario(wide, excluded, absent, 6),
            "no_classes": scenario([], no_classes, {"inactive-source": absent["inactive-source"]}, 6),
            "missing_and_type_no_eligible": scenario([3, 4], none_eligible, unavailable, 6),
        },
        "reject": {
            "complete_with_pair_gaps": scenario(wide, mixed, eligible, 0, one_hit),
            "nonzero_padding": scenario(
                short, all_eligible, eligible, 0, matrix_body=matrix_short[:-1] + b"\x45"
            ),
            "duplicate_class": scenario(wide, mixed, eligible, 6, matrix_body=wrong_ordinals),
            "class_outside_table": scenario(wide, mixed, eligible, 6, matrix_body=outside_table),
            "class_outside_scope": scenario(wide, mixed, eligible, 6, matrix_body=wrong_scope),
            "wrong_rule_count": scenario(wide, mixed, eligible, 6, matrix_body=matrix_drops_rule),
            "truncated_matrix": scenario(wide, mixed, eligible, 6, matrix_body=matrix_wide[:-1]),
            "trailing_byte": scenario(wide, mixed, eligible, 6, matrix_body=matrix_wide + b"\x00"),
            "compiled_and_matrix_disagree": scenario(
                wide, mixed, eligible, 6, matrix_body=matrix_swaps_eligibility
            ),
            "match_in_missing_binding_class": scenario(wide, mixed, eligible, 6, [("ip-range", 3, 9)]),
        },
    }


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2, sort_keys=True))
