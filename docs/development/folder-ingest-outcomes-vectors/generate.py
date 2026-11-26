#!/usr/bin/env python3
"""Independent byte and Ed25519 vectors for local ingestion outcome receipts."""
import json
import runpy
from pathlib import Path

support = runpy.run_path(str(Path(__file__).parents[1] / "sigma-package-vectors" / "generate.py"))
sha, text, u64, vector = (support[key] for key in ("sha", "text", "u64", "vector"))
tag = b"irmind-ingest-file-outcome-v1\0"
source = "collection/registro-ñ.jsonl"
content = b"synthetic case input\n"
digest = sha(content)


def identity(data):
    return b"\0" + u64(len(data)) + sha(data)


def outcome(path, body, disposition, reason):
    return tag + b"\0" + text(path) + body + bytes((disposition, reason))


def integrity(expected, verdict):
    companion = expected.hex().encode("ascii") + b"  registro-\xc3\xb1.jsonl\n"
    return (tag + b"\x01" + text(source) + identity(content)
            + text(source + ".sha256") + u64(len(companion)) + sha(companion)
            + expected + bytes((verdict,)))


def signed(body):
    kind = "ingest-file-outcome-v1"
    payload = body.hex()
    case_id = "00000000-0000-4000-8000-000000000074"
    label = "synthetic folder ingestion analyst"
    key, _ = support["signature"](b"key derivation", label)
    previous = sha(b"synthetic case checkpoint")

    def sized(raw):
        return u64(len(raw)) + raw

    challenge = (b"irmind-audit-v2\0" + u64(7) + sized(case_id.encode()) + u64(1795708800)
                 + sized(b"analyst") + sized(b"analyst") + sized(kind.encode())
                 + sized(payload.encode()) + b"\0" + previous + sized(key))
    hashed = sha(challenge)
    _, signature = support["signature"](hashed, label)
    support["assert_verification"](key, hashed, signature, True)
    support["assert_verification"](key, sha(challenge + b"\0"), signature, False)
    envelope = dict(seq=7, case_id=case_id, at=1795708800, actor="analyst", origin="analyst",
                    kind=kind, payload=payload, evidence=None, prev=list(previous), hash=list(hashed),
                    sig=list(signature), public_key=list(key))
    return support["json_bytes"](envelope), challenge


skipped = outcome(source, identity(content), 0, 0)
entry, challenge = signed(skipped)
vectors = {
    "skipped_unicode": skipped,
    "failed_missing_pipeline": outcome(source, identity(content), 1, 6),
    "failed_unreadable": outcome(source, b"\x02", 1, 10),
    "matching_checksum": integrity(digest, 0),
    "checksum_mismatch": integrity(sha(b"synthetic altered content"), 1),
    "signed_skip": entry,
    "signed_skip_challenge": challenge,
    "reject_traversal": outcome("../outside.jsonl", identity(content), 0, 0),
    "reject_unknown_reason": outcome(source, identity(content), 0, 255),
    "reject_trailing_bytes": skipped + b"\0",
    "reject_missing_fingerprint_for_skip": outcome(source, b"\x02", 0, 0),
    "reject_mismatched_verified_claim": integrity(sha(b"synthetic altered content"), 0),
    "reject_equal_mismatch_claim": integrity(digest, 1),
}
print(json.dumps({name: vector(body) for name, body in vectors.items()}, indent=2))
