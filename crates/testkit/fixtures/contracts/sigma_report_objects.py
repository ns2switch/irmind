#!/usr/bin/env python3
"""Independent active Sigma and report proof-object vectors, using the standard library."""
import hashlib
import json
import struct


def sha(value):
    return hashlib.sha256(value).digest()


def tag(value):
    return value.encode("ascii") + b"\0"


def u64(value):
    return struct.pack(">Q", value)


def text(value):
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def entries(*values):
    return u64(len(values)) + b"".join(values)


def ref(n, value):
    return u64(n) + sha(value)


def descriptor(kind, body):
    return bytes([kind]) + sha(body) + u64(len(body))


def vector(data):
    return {"bytes_hex": data.hex(), "size": len(data), "sha256": sha(data).hex()}


def report_coverage_prefix():
    return (
        tag("irmind-report-coverage-v2") + entries() + entries()
        + entries(ref(4, b"synthetic-query-limit"))
        + entries(ref(11, b"synthetic-partial-sigma-run"))
    )


def generate():
    rule = (
        b"title: Synthetic process creation\n"
        b"logsource: {category: process_creation, product: windows}\n"
        b"detection: {selection: {Image: test.exe}, condition: selection}\n"
    )
    rule_hash = sha(rule)
    rule_id = text(f"sha256:{rule_hash.hex()}")
    rule_key = rule_id + rule_hash
    source = ref(2, b"synthetic-source-manifest") + sha(b"synthetic evidence")
    artifact = ref(3, b"synthetic-artifact-entry") + sha(b"synthetic parquet")
    row = source + u64(9) + artifact + u64(5)
    confirmation = ref(14, b"synthetic-finding-confirmation")
    field_table = (
        '[[variants]]\nproduct = "windows"\ncategory = "process_creation"\n'
        'parser_id = "parser-evtx"\nparser_version = "fixture-v1"\n'
        'mapping_id = "mapping-evtx"\nmapping_version = "fixture-v1"\n'
        'channel = "Microsoft-Windows-Sysmon/Operational"\n'
        '[[variants.events]]\ncolumn = "event.code"\nequals = "1"\n'
        '[[variants.fields]]\nname = "Image"\ncolumn = "process.executable"\n'
        'value_type = "text"\nnull_policy = "absent"\n'
    )
    pack = tag("irmind-sigma-pack-manifest-v1") + entries(
        text("process.yml") + rule_key[: -len(rule_hash)]
        + b"\x00\x01" + text("Fixture Author") + rule_hash + u64(len(rule))
    )
    table = tag("irmind-sigma-field-table-v1") + text("fixture") + text("1") + text(field_table)
    scope = tag("irmind-sigma-source-scope-v1") + entries(source)
    compiled = tag("irmind-sigma-compiled-rules-v1") + entries(rule_key + entries(u64(0)))
    citations_tag = tag("irmind-report-citations-v1")
    citation = text("00000000-0000-4000-8000-000000000006") + confirmation
    cited = citations_tag + entries(citation + entries(b"\x00" + row))
    analyst = tag("irmind-report-analyst-sections-v1") + b"".join(map(
        text, ["Alcance sintético", "", "Caso de prueba", "Revisar fuentes"]
    ))
    coverage = report_coverage_prefix() + entries()
    rendered = b"# Synthetic report\n"
    objects = {
        "sigma_pack_manifest": pack, "sigma_raw_rule": rule, "sigma_field_table": table,
        "sigma_source_scope": scope, "sigma_compiled_rules": compiled,
        "report_citations": cited, "report_analyst_sections": analyst,
        "report_coverage": coverage, "report_rendered": rendered,
    }
    pack_descriptor, rule_descriptor = descriptor(0, pack), descriptor(1, rule)
    negative = {
        "reject_body_trailing_byte": pack + b"\0",
        "reject_duplicate_descriptor": entries(pack_descriptor, pack_descriptor),
        "reject_missing_pack_proof": entries(rule_descriptor),
        "reject_reordered_proofs": entries(rule_descriptor, pack_descriptor),
        "reject_unresolved_row": citations_tag + entries(citation + entries(
            b"\x00" + source + u64(9) + artifact + u64(6)
        )),
        "reject_uncited_finding": citations_tag + entries(citation + entries()),
    }
    return {name: vector(body) for name, body in (objects | negative).items()}


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2, sort_keys=True))
