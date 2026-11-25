#!/usr/bin/env python3
"""Independent wire vectors for the proposed Sigma package contract."""

import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path


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


def signature(message, key_label):
    """Sign and verify using an ephemeral synthetic Ed25519 key."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        key, public, data = (root / name for name in ("key.der", "public.der", "message"))
        # PKCS#8 for an Ed25519 seed. Labels are test constants.
        key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + synthetic(key_label))
        data.write_bytes(message)
        subprocess.run(
            ["openssl", "pkey", "-in", str(key), "-inform", "DER", "-pubout",
             "-outform", "DER", "-out", str(public)], check=True, capture_output=True,
        )
        sig = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
             "-inkey", str(key), "-in", str(data)], check=True, capture_output=True,
        ).stdout
        return public.read_bytes()[-32:], sig


def assert_verification(public_key, message, sig, expected):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        key, data, signed = (root / name for name in ("public.der", "message", "signature"))
        key.write_bytes(bytes.fromhex("302a300506032b6570032100") + public_key)
        data.write_bytes(message)
        signed.write_bytes(sig)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
             "-inkey", str(key), "-in", str(data), "-sigfile", str(signed)], capture_output=True,
        )
        assert (result.returncode == 0) == expected


def global_operation(body):
    payload = body.hex()
    key_label = "synthetic Sigma package analyst"
    key, _ = signature(b"synthetic key derivation", key_label)

    def sized(raw):
        return u64(len(raw)) + raw

    preimage = (
        b"irmind-operation-v1\0" + sized(b"global") + u64(1) + u64(1795392000)
        + sized(b"analyst") + sized(payload.encode("ascii")) + bytes(32) + sized(key)
    )
    digest = sha(preimage)
    _, sig = signature(digest, key_label)
    assert_verification(key, digest, sig, True)
    encoded = json_bytes(dict(
        case_id="global", seq=1, at=1795392000, actor="analyst", operation=payload,
        prev=list(bytes(32)), hash=list(digest), sig=list(sig), public_key=list(key),
    ))
    return encoded, preimage, digest


def proof_records(objects):
    descriptors = [
        (bytes([kind]) + sha(body) + u64(len(body)), body) for kind, body in objects
    ]
    count = u64(len(descriptors))
    body = count + b"".join(descriptor + content for descriptor, content in descriptors)
    commitment = sha(b"irmind-sigma-proof-set-v1\0" + count + b"".join(
        descriptor for descriptor, _ in descriptors
    ))
    return dict(wire=vector(body), proof_set_sha256=commitment.hex())


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
    key_label = "synthetic shared skills and Sigma publisher"
    public_key, _ = signature(b"synthetic key derivation", key_label)
    index = json_bytes(dict(
        format_version=1, catalog="ns2switch/irmind-skills", key_id=sha(public_key).hex(),
        release_tag="v1.0.0", release_commit=synthetic("commit").hex()[:40], release_sequence=1,
        entries=[dict(
            name=name, version=version, minimum_irmind_version="0.7.3", license=license_id,
            manifest_sha256=sha(manifest).hex(), source=dict(
                kind="catalog-asset", asset="synthetic.sigma", bytes=len(package),
                sha256=sha(package).hex(),
            ), coverage=[["aws", "cloudtrail", None]],
        )],
    ))
    sigma_domain = b"irmind-sigma-catalog-index-v1\0"
    skill_domain = b"irmind-skill-catalog-index-v1\0"
    index_preimage = sigma_domain + u64(len(index)) + index
    skills_index = json_bytes(dict(
        format_version=1, catalog="ns2switch/irmind-skills", key_id=sha(public_key).hex(),
        release_tag="v1.0.0", release_commit=synthetic("commit").hex()[:40],
        release_sequence=1, entries=[],
    ))
    skills_preimage = skill_domain + u64(len(skills_index)) + skills_index
    _, sigma_signature = signature(index_preimage, key_label)
    _, skill_signature = signature(skills_preimage, key_label)
    assert_verification(public_key, index_preimage, sigma_signature, True)
    assert_verification(public_key, skills_preimage, skill_signature, True)
    assert_verification(public_key, skill_domain + index_preimage[len(sigma_domain):], sigma_signature, False)
    assert_verification(public_key, sigma_domain + skills_preimage[len(skill_domain):], skill_signature, False)
    catalog_proof = b"irmind-sigma-catalog-proof-v1\0" + u64(len(index)) + index + sigma_signature
    catalog_installation = (
        b"irmind-sigma-package-installation-v1\0" + text(name) + text(version)
        + bytes([1, 0]) + sha(metadata) + sha(manifest) + sha(package)
        + text(license_id) + bytes([1, 1]) + sha(catalog_proof)
    )
    operation, operation_preimage, operation_digest = global_operation(catalog_installation)
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
        + b"\x01" + operation_digest + synthetic("signed pack admission")
        + sha(manifest) + synthetic("inventory") + synthetic("sources")
        + struct.pack(">qq", 10, 20) + synthetic("table") + synthetic("compiled")
        + text("irmind-sigma-evaluator-v3-case-admission-v1") + u64(1000)
    )
    return {
        "package": vector(package),
        "index": vector(index),
        "index_signature_preimage": vector(index_preimage),
        "publisher_public_key": public_key.hex(),
        "publisher_key_id": sha(public_key).hex(),
        "sigma_index_signature": sigma_signature.hex(),
        "skills_index": vector(skills_index),
        "skills_index_signature": skill_signature.hex(),
        "skills_signature_preimage": vector(skills_preimage),
        "negative_signature_domains": {
            "sigma_index_as_skill": vector(skill_domain + index_preimage[len(sigma_domain):]),
            "skills_index_as_sigma": vector(sigma_domain + skills_preimage[len(skill_domain):]),
        },
        "catalog_installation": vector(catalog_installation),
        "installation_operation_signing_preimage": vector(operation_preimage),
        "v10_object_6": vector(operation),
        "v10_object_7": vector(catalog_proof),
        "v10_object_8": vector(metadata),
        "v10_package_proof_records": proof_records([
            (0, manifest), (1, rule), (6, operation), (7, catalog_proof), (8, metadata),
        ]),
        "local_installation": vector(installation),
        "local_deactivation": vector(deactivation),
        "case_admission": vector(case_admission),
        "invalid_trailing_package_byte": vector(package + b"\x00"),
    }


if __name__ == "__main__":
    print(json.dumps(examples(), indent=2, sort_keys=True))
