#!/usr/bin/env python3
"""Refresh the synthetic V11 exports from the authenticated current seeds.

Development only; requires Python cryptography. Only the published synthetic
signing keys are accepted. Original signatures and seed digests are checked
before updating profiles, artifact bindings, receipts, inventory and signatures.
No evidence, mapping installation or Parquet bytes are changed.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'IRMIND-EXPORT-V11\0'
PROFILE = b'irmind-mapping-profile-v1\0'
KEY = Ed25519PrivateKey.from_private_bytes(bytes([43]) * 32)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sha(value):
    return hashlib.sha256(value).digest()


def number(value):
    return value.to_bytes(8, 'big')


def field(value):
    value = value.encode() if isinstance(value, str) else value
    return number(len(value)) + value


class Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, length):
        value = self.data[self.offset:self.offset + length]
        assert len(value) == length
        self.offset += length
        return value

    def number(self):
        return int.from_bytes(self.take(8), 'big')

    def field(self):
        size = self.number()
        assert size <= 1024 * 1024
        return self.take(size)


def canonical(entry):
    out = b'irmind-audit-v2\0' + number(entry['seq'])
    out += field(entry['case_id']) + number(entry['at'])
    out += b''.join(field(entry[key]) for key in ['actor', 'origin', 'kind', 'payload'])
    out += (b'\0' if entry['evidence'] is None else b'\1' + field(entry['evidence']))
    return out + bytes(entry['prev']) + field(bytes(entry['public_key']))


def replace_digest(data, old, new):
    assert len(old) == len(new) == 64
    return data.replace(old, new)


def rewrite_pipeline(entries):
    codes = (ROOT / 'crates/domain/src/common_event/goldens/codes-v1.tsv').read_bytes()
    new_contract = sha(b'irmind-common-contract-v1\0' + field(codes)).hex().encode()
    profiles, artifacts = {}, []
    old_contract = None
    for entry in entries:
        raw = bytes.fromhex(entry['payload']) if entry['kind'] != 'CaseCreated' else b''
        if entry['kind'] == 'MappingProfileV1' and raw.startswith(PROFILE):
            reader = Reader(raw[len(PROFILE):])
            contracts = [reader.field() for _ in range(6)]
            old_contract = contracts[-1]
            changed = replace_digest(raw, old_contract, new_contract)
            profiles[sha(raw).hex().encode()] = sha(changed).hex().encode()
            entry['payload'] = changed.hex()
        elif entry['kind'] == 'ParquetArtifactV3':
            assert old_contract is not None
            changed = replace_digest(raw, old_contract, new_contract)
            for old, new in profiles.items():
                changed = replace_digest(changed, old, new)
            entry['payload'] = changed.hex()
            artifacts.append(changed)
        elif entry['kind'] == 'MappingRunV1':
            assert len(artifacts) == 1, 'fixture recipe expects exactly one artifact'
            changed = raw
            for old, new in profiles.items():
                changed = replace_digest(changed, old, new)
            digest = sha(b'irmind-mapping-outputs-v1\0' + number(1) + field(artifacts[0]))
            entry['payload'] = (changed[:-64] + digest.hex().encode()).hex()


def inventory(entries):
    items = []
    for entry in entries:
        raw = bytes.fromhex(entry['payload']) if entry['kind'] != 'CaseCreated' else b''
        if entry['kind'] == 'SourceManifestV2':
            outer = Reader(raw[len(b'irmind-source-manifest-v2\0'):])
            source = bytes.fromhex(outer.field().decode())
            key = Reader(source[len(b'irmind-source-manifest-v1\0'):]).field()
            kind = 1
        elif entry['kind'] == 'ParquetArtifactV3':
            core = Reader(raw[len(b'irmind-parquet-artifact-v3\0'):]).field()
            key = Reader(core[len(b'irmind-parquet-artifact-v2\0'):]).field()
            kind = 2
        else:
            continue
        digest = sha(b'irmind-seal-inventory-item-v2\0' + bytes([kind]) + field(key) + field(entry['payload']))
        items.append((kind, key, digest))
    assert len(items) == 2
    body = b'irmind-seal-inventory-items-v2\0' + number(len(items))
    body += b''.join(bytes([kind]) + field(key) + digest for kind, key, digest in sorted(items))
    return (b'irmind-seal-inventory-v2\0' + number(len(items)) + field(sha(body).hex())).hex()


def frame(value):
    return field(json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True))


def refresh(path):
    test = (ROOT / 'crates/infra/src/tests/mapped_export/seed.rs').read_text()
    match = re.search(re.escape(path.name) + r'"\),\s*"([0-9a-f]{64})"', test)
    assert match, 'fixture must have an explicit frozen digest'
    original = path.read_bytes()
    assert sha(original).hex() == match[1], 'original fixture digest does not match'
    source = Reader(original)
    assert source.take(len(MAGIC)) == MAGIC
    header = json.loads(source.field())
    assert header['version'] == 11
    entries = [json.loads(source.field()) for _ in range(source.number())]
    assert entries[0]['kind'] == 'CaseCreated' and json.loads(entries[0]['payload'])['version'] == 7

    previous = bytes(32)
    for entry in entries:
        assert bytes(entry['public_key']) == PUBLIC and bytes(entry['prev']) == previous
        previous = sha(canonical(entry))
        assert previous == bytes(entry['hash'])
        KEY.public_key().verify(bytes(entry['sig']), previous)
    last = entries[-1]
    seal = header['seal']
    assert last['kind'] == 'CaseSealed' and last['seq'] == seal['seq']
    assert bytes(seal['public_key']) == PUBLIC and bytes(seal['hash']) == previous
    challenge = b'irmind-seal-v1\0' + field(header['case_id']) + number(last['seq']) + previous + field(last['payload'])
    KEY.public_key().verify(bytes(seal['sig']), challenge)

    rewrite_pipeline(entries)
    last['payload'] = inventory(entries[:-1])
    return resign(header, entries, source.data[source.offset:]), match[1]


def resign(header, entries, remainder):
    previous = bytes(32)
    for entry in entries:
        entry['prev'] = list(previous)
        previous = sha(canonical(entry))
        entry['hash'], entry['sig'] = list(previous), list(KEY.sign(previous))
    final = entries[-1]
    challenge = b'irmind-seal-v1\0' + field(header['case_id']) + number(final['seq']) + previous + field(final['payload'])
    assert bytes(header['seal']['public_key']) == PUBLIC
    header['seal'].update(hash=list(previous), sig=list(KEY.sign(challenge)))
    ordered_header = {key: header[key] for key in (
        'version', 'case_id', 'title', 'severity', 'scope', 'seal',
    )}
    ordered_header['seal'] = {key: header['seal'][key] for key in (
        'seq', 'hash', 'sig', 'public_key', 'analyst_key_fingerprint',
    )}
    prefix = field(
        json.dumps(ordered_header, ensure_ascii=False, separators=(',', ':')),
    )
    return MAGIC + prefix + number(len(entries)) + b''.join(map(frame, entries)) + remainder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    test_path = ROOT / 'crates/infra/src/tests/mapped_export/seed.rs'
    test = test_path.read_text()
    for suffix in ('mapped', 'installed'):
        path = ROOT / f'fuzz/seeds/export/valid-v11-{suffix}.irmind'
        body, old = refresh(path)
        digest = sha(body).hex()
        print(path.name, digest)
        if args.write:
            path.write_bytes(body)
            test = test.replace(old, digest)
    if args.write:
        test_path.write_text(test)


if __name__ == '__main__':
    main()
