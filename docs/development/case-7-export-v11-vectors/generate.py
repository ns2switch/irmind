#!/usr/bin/env python3
"""Independent case-7/V11 codec vectors. Requires Python 3 and OpenSSL 3."""

import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path


CASE = "00000000-0000-4000-8000-000000000070"
TITLE = "Synthetic case 7 format witness"
EVALUATOR = "irmind-sigma-evaluator-v5"
ZERO = bytes(32)
AT = 1800000000
SECTION_COUNTS = bytes(11 * 8)
RUN = b"irmind-sigma-run-v2\0"


def sha(data):
    return hashlib.sha256(data).digest()


def u64(value):
    return struct.pack(">Q", value)


def frame(data):
    return u64(len(data)) + data


def text(value):
    return frame(value.encode("utf-8"))


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def vector(data):
    return {"hex": data.hex(), "sha256": sha(data).hex(), "length": len(data)}


def openssl(*args):
    return subprocess.run(
        ["openssl", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


class SyntheticAnalyst:
    def __init__(self, directory):
        self.private = directory / "analyst.pk8"
        self.public = directory / "analyst.spki"
        self.message = directory / "message"
        self.signature = directory / "signature"
        # Deterministic test key. This seed is public and must only be used here.
        seed = sha(b"IRMind synthetic case-7 V11 review vectors")
        self.private.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
        spki = openssl(
            "pkey", "-inform", "DER", "-in", str(self.private), "-pubout", "-outform", "DER"
        )
        prefix = bytes.fromhex("302a300506032b6570032100")
        assert spki.startswith(prefix) and len(spki) == len(prefix) + 32
        self.public.write_bytes(spki)
        self.key = spki[len(prefix):]

    def sign(self, message):
        self.message.write_bytes(message)
        sig = openssl(
            "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(self.private),
            "-in", str(self.message),
        )
        assert len(sig) == 64
        self.signature.write_bytes(sig)
        openssl(
            "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
            "-inkey", str(self.public), "-in", str(self.message), "-sigfile", str(self.signature),
        )
        return sig

    def entry(self, kind, payload, predecessor=None):
        seq = 1 if predecessor is None else predecessor["seq"] + 1
        prev = ZERO if predecessor is None else bytes(predecessor["hash"])
        at = AT + seq
        challenge = (
            b"irmind-audit-v2\0" + u64(seq) + text(CASE) + u64(at)
            + text("analyst") + text("analyst") + text(kind) + text(payload)
            + b"\0" + prev + frame(self.key)
        )
        digest = sha(challenge)
        return dict(
            seq=seq, case_id=CASE, at=at, actor="analyst", origin="analyst",
            kind=kind, payload=payload, evidence=None, prev=list(prev), hash=list(digest),
            sig=list(self.sign(digest)), public_key=list(self.key),
        )

    def global_admission(self, body):
        payload = body.hex()
        challenge = (
            b"irmind-operation-v1\0" + text("global") + u64(1) + u64(AT)
            + text("analyst") + text(payload) + ZERO + frame(self.key)
        )
        digest = sha(challenge)
        return dict(
            case_id="global", seq=1, at=AT, actor="analyst", operation=payload,
            prev=list(ZERO), hash=list(digest), sig=list(self.sign(digest)),
            public_key=list(self.key),
        )

    def sealed_empty(self, root):
        sealed = self.entry("CaseSealed", "", root)
        digest = bytes(sealed["hash"])
        challenge = b"irmind-seal-v1\0" + text(CASE) + u64(2) + digest + text("")
        seal = dict(
            seq=2, hash=list(digest), sig=list(self.sign(challenge)), public_key=list(self.key),
            analyst_key_fingerprint=sha(self.key).hex(),
        )
        header = dict(version=11, case_id=CASE, title=TITLE, severity="medium", scope="local", seal=seal)
        body = u64(2) + frame(json_bytes(root)) + frame(json_bytes(sealed)) + SECTION_COUNTS
        return header, body


def case_payload(version):
    return json_bytes(dict(
        version=version, title=TITLE, severity="medium", scope="local",
        budget=dict(model_tokens=2_000_000, tool_calls=1_000, cloud_bytes=536_870_912_000),
        source_queries=dict(
            enabled=False, analytics_allowed=False, scan_bytes=None,
            retained_rows=0, retained_bytes=0,
        ),
    )).decode("utf-8")


def checkpoint(entry):
    return text(CASE) + u64(entry["seq"]) + bytes(entry["hash"])


def magic(version):
    return f"IRMIND-EXPORT-V{version}".encode("ascii") + b"\0"


def archive(header, body):
    return magic(11) + frame(json_bytes(header)) + body


def archive_vectors(analyst, root):
    header, sections = analyst.sealed_empty(root)
    old = analyst.entry("CaseCreated", case_payload(6))
    mixed_header, mixed_sections = analyst.sealed_empty(old)
    valid = archive(header, sections)
    return {
        "case_created_payload": vector(case_payload(7).encode("utf-8")),
        "case_created_signed_entry": vector(json_bytes(root)),
        "v11_magic_and_header_frame": vector(magic(11) + frame(json_bytes(header))),
        "v11_empty_signed_case": vector(valid),
        "reject_legacy_case_markers": {
            str(version): vector(json_bytes(
                old if version == 6 else analyst.entry("CaseCreated", case_payload(version))
            ))
            for version in range(1, 7)
        },
        "reject_legacy_magic_only": {str(version): vector(magic(version)) for version in range(1, 11)},
        "reject_signed_case_6_in_v11": vector(archive(mixed_header, mixed_sections)),
        "reject_header_version_mismatch": vector(archive(dict(header, version=10), sections)),
        "reject_missing_report_count": vector(valid[:-8]),
        "reject_trailing_byte": vector(valid + b"\0"),
        "reject_noncanonical_magic": vector(b"IRMIND-EXPORT-V011\0"),
        "reject_truncated_magic": vector(magic(11)[:-1]),
        "reject_duplicate_signed_marker": vector(json_bytes(analyst.entry(
            "CaseCreated", case_payload(7).replace('"version":7', '"version":6,"version":7', 1)
        ))),
        "future_archive_marker": vector(magic(12)),
    }


def sigma_vectors(analyst, root):
    rule = text("synthetic-rule") + sha(b"synthetic YAML rule bytes")
    unavailable_detail = "No signed event artifact matches the rule's reviewed source classes"
    scan = u64(1) + rule + b"\x03\x01" + text(unavailable_detail) + u64(0)
    count_scan = scan + u64(0) + u64(0)
    results = b"irmind-sigma-run-results-v3\0" + count_scan + u64(0) + u64(1)
    selected_sources = b"irmind-sigma-source-scope-v1\0" + u64(0)
    compiled_rules = b"irmind-sigma-compiled-rules-v1\0" + u64(1) + rule + u64(0)
    selected, compiled, result = map(sha, (selected_sources, compiled_rules, results))
    table = sha(b"synthetic field table reference")
    inventory = sha(b"synthetic inventory reference")
    manifest = sha(b"synthetic pack manifest reference")
    installation = sha(b"synthetic installation reference")
    proofs = sha(b"synthetic proof set reference")
    times = struct.pack(">qq", 10, 20)
    reserve = u64(1000)

    def pack_admission(pinned):
        body = (
            b"irmind-sigma-pack-admission-v1\0" + manifest + proofs
            + bytes([pinned]) + text("synthetic pack") + bytes([pinned])
            + (sha(b"synthetic pinned release archive") if pinned else b"") + text("MIT")
        )
        return analyst.global_admission(body)

    local = pack_admission(False)
    pinned = pack_admission(True)
    local_hash, pinned_hash = bytes(local["hash"]), bytes(pinned["hash"])

    def case_admission(op, installation_field):
        body = (
            b"irmind-sigma-case-run-admission-v1\0" + checkpoint(root)
            + installation_field + op + manifest + inventory + selected + times
            + table + compiled + text(EVALUATOR) + reserve
        )
        return analyst.entry("sigma-case-run-admission-v1", body.hex(), root)

    admitted = case_admission(pinned_hash, b"\x01" + installation)
    no_installation = case_admission(pinned_hash, b"\0")

    def run(
        after, op, mode, *, tag=RUN, evaluator=EVALUATOR,
        compiled_digest=compiled, declared_checkpoint=None, result_digest=result,
    ):
        anchor = after if declared_checkpoint is None else declared_checkpoint
        body = (
            tag + checkpoint(anchor) + op + inventory + selected + times
            + compiled_digest + table + text(evaluator) + mode
            + reserve + u64(7) + b"\x06" + u64(0) + result_digest + proofs
        )
        kind = "sigma-run-v2" if tag == RUN else "sigma-run-v1"
        return analyst.entry(kind, body.hex(), after)

    admitted_local = case_admission(local_hash, b"\x01" + installation)
    direct = run(root, local_hash, b"\0")
    installed = run(admitted, pinned_hash, b"\x01")
    return {
        "result_v3_no_sources": vector(results),
        "reject_standalone_results_v1": vector(b"irmind-sigma-run-results-v1\0" + scan),
        "reject_standalone_results_v2": vector(b"irmind-sigma-run-results-v2\0" + count_scan),
        "selected_sources": vector(selected_sources),
        "compiled_rules": vector(compiled_rules),
        "local_global_admission": vector(json_bytes(local)),
        "pinned_global_admission": vector(json_bytes(pinned)),
        "installed_case_admission": vector(json_bytes(admitted)),
        "installed_local_case_admission": vector(json_bytes(admitted_local)),
        "installed_local_run_v2_entry": vector(json_bytes(run(admitted_local, local_hash, b"\x01"))),
        "direct_run_v2_body": vector(bytes.fromhex(direct["payload"])),
        "direct_run_v2_entry": vector(json_bytes(direct)),
        "installed_run_v2_body": vector(bytes.fromhex(installed["payload"])),
        "installed_run_v2_entry": vector(json_bytes(installed)),
        "reject_unknown_mode": vector(json_bytes(run(root, local_hash, b"\x02"))),
        "reject_installed_mode_without_admission": vector(json_bytes(run(root, pinned_hash, b"\x01"))),
        "reject_direct_mode_with_admission": vector(json_bytes(
            run(admitted_local, local_hash, b"\0")
        )),
        "case_admission_without_installation": vector(json_bytes(no_installation)),
        "reject_installed_mode_without_installation_binding": vector(json_bytes(
            run(no_installation, pinned_hash, b"\x01")
        )),
        "reject_installed_mode_compiled_rule_mismatch": vector(json_bytes(
            run(admitted, pinned_hash, b"\x01", compiled_digest=sha(b"different compiled rule set"))
        )),
        "reject_detached_checkpoint": vector(json_bytes(
            run(admitted, pinned_hash, b"\x01", declared_checkpoint=root)
        )),
        "reject_direct_mode_with_pinned_origin": vector(json_bytes(run(root, pinned_hash, b"\0"))),
        "reject_v1_receipt_even_with_v5_evaluator": vector(json_bytes(
            run(root, local_hash, b"", tag=b"irmind-sigma-run-v1\0")
        )),
        "reject_missing_mode": vector(json_bytes(run(root, local_hash, b""))),
        "reject_retired_evaluator_ids": {
            suffix: vector(json_bytes(run(root, local_hash, b"\0", evaluator="irmind-sigma-evaluator-" + suffix)))
            for suffix in ("v1", "v2", "v3", "v4", "v3-case-admission-v1", "v4-case-admission-v1")
        },
    }


def main():
    with tempfile.TemporaryDirectory(prefix="irmind-case-7-vectors-") as tmp:
        analyst = SyntheticAnalyst(Path(tmp))
        root = analyst.entry("CaseCreated", case_payload(7))
        vectors = {
            "case_and_export": archive_vectors(analyst, root),
            "sigma": sigma_vectors(analyst, root),
            "report": {
                "coverage_v2_empty": vector(b"irmind-report-coverage-v2\0" + bytes(5 * 8)),
                "reject_coverage_v1_empty": vector(b"irmind-report-coverage-v1\0" + bytes(4 * 8)),
            },
        }
    print(json.dumps(vectors, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
