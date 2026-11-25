#!/usr/bin/env python3
"""Independent wire vectors for the proposed Sigma package contract."""

import hashlib
import json
import struct


def sha(body):
    return hashlib.sha256(body).digest()


def synthetic(label):
    return sha(label.encode("ascii"))


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def u64(value):
    return struct.pack(">Q", value)


def text(value):
    raw = value.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def vector(body):
    return {"bytes_hex": body.hex(), "sha256": sha(body).hex()}


def examples():
    name = "synthetic"
    version = "1.0.0"
    license_id = "MIT"
    rule = (
        b"title: Synthetic CloudTrail rule\nid: synthetic\n"
        b"logsource: {product: aws, service: cloudtrail}\n"
        b"detection: {selection: {eventName: Synthetic}, condition: selection}\n"
    )
    manifest = (
        b"irmind-sigma-pack-manifest-v1\0" + u64(1) + text("rule.yml")
        + text("synthetic") + bytes(2) + sha(rule) + u64(len(rule))
    )
    metadata = json_bytes(dict(
        format_version=1, name=name, version=version, license=license_id,
        attribution="Synthetic example",
    ))
    package = (
        b"irmind-sigma-package-v1\0" + u64(len(metadata)) + metadata
        + u64(len(manifest)) + manifest + rule
    )
    # Public RFC 8032 test key. No signature or trusted key is installed here.
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    index = json_bytes(dict(
        format_version=1, catalog="example/synthetic-sigma", key_id=sha(public_key).hex(),
        release_tag="v1.0.0", release_commit=synthetic("commit").hex()[:40], release_sequence=1,
        entries=[dict(
            name=name, version=version, minimum_irmind_version="0.7.3", license=license_id,
            manifest_sha256=sha(manifest).hex(), source=dict(
                kind="catalog-asset", asset="synthetic.sigma", bytes=len(package),
                sha256=sha(package).hex(),
            ), coverage=[["aws", "cloudtrail", None]],
        )],
    ))
    index_preimage = b"irmind-sigma-catalog-index-v1\0" + u64(len(index)) + index
    installation = (
        b"irmind-sigma-package-installation-v1\0" + text(name) + text(version)
        + b"\x01\x00" + sha(metadata) + sha(manifest) + sha(package)
        + text(license_id) + b"\x00\x00"
    )
    deactivation = (
        b"irmind-sigma-package-installation-v1\0" + text(name) + text(version)
        + b"\x00\x01" + synthetic("previous signed installation") + sha(metadata)
        + sha(manifest) + sha(package) + text(license_id) + b"\x00\x00"
    )
    case_admission = (
        b"irmind-sigma-case-run-admission-v1\0"
        + text("00000000-0000-4000-8000-000000000010") + u64(9) + synthetic("checkpoint")
        + b"\x01" + synthetic("signed installation") + synthetic("signed pack admission")
        + sha(manifest) + synthetic("inventory") + synthetic("sources")
        + struct.pack(">qq", 10, 20) + synthetic("table") + synthetic("compiled")
        + text("irmind-sigma-evaluator-v3-case-admission-v1") + u64(1000)
    )
    return {
        "package": vector(package),
        "index": vector(index),
        "index_signature_preimage": vector(index_preimage),
        "local_installation": vector(installation),
        "local_deactivation": vector(deactivation),
        "case_admission": vector(case_admission),
        "invalid_trailing_package_byte": vector(package + b"\x00"),
    }


if __name__ == "__main__":
    print(json.dumps(examples(), indent=2, sort_keys=True))
