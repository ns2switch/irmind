#!/usr/bin/env python3
"""Independent reference encoder for new mapping/layout fixtures only."""
import argparse
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'crates/domain/src/custody_manifest/mapping/goldens'
SOURCE = 'irmind-source-record-v1'
TARGET = 'irmind-common-event-v1'
POLICY = 'ascii-dns-lowercase-strip-root-v1'
MAPPER = ('mapping-example', '1', TARGET, 'c' * 64)
BUILDER = 'parquet-builder-common-event-v1'
LAYOUT = 'parquet-layout-common-event-v1'
DESCRIPTOR = (
    'irmind-source-record-v1;utf8-byte-sorted-unique-object-keys;array-order;'
    'null=0,bool=1,number-lexeme=2,text=3,bytes=4,array=5,object=6;'
    'record-bytes=4194304,nodes=4096,depth=32,number-bytes=128;'
    'source-sha256,ordinal,optional-real-offset,decoder,source-reference,'
    'source-kind,acquisition,optional-indexed-time,format,discriminators,'
    'typed-fields,partial,members,optional-raw;length-prefix-u64-be'
).encode()


def u64(n):
    return struct.pack('>Q', n)


def field(value):
    if isinstance(value, str):
        value = value.encode()
    return u64(len(value)) + value


def fields(*values):
    return b''.join(field(v) for v in values)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def contracts():
    codes = (ROOT / 'crates/domain/src/common_event/goldens/codes-v1.tsv').read_bytes()
    source = sha(b'irmind-source-contract-v1\0' + field(DESCRIPTOR))
    target = sha(b'irmind-common-contract-v1\0' + field(codes))
    return source, target


def source_set(letter, path, context=None):
    snapshot_time = (f"source-time-v1;year={context[0]:04};offset={context[1]};rollover={int(context[2])};basis={context[3]}" if context else "normalized-utc")
    wire_time = (b"\1" + u64(context[0]) + struct.pack(">q", context[1]) + bytes([int(context[2])]) + field(context[3]) if context else b"\0")
    original = (b'irmind-source-manifest-v1\0' + field(path) + u64(4200)
                + b'\0\0\0' + field(letter * 64) + b'\0')
    manifest = (b'irmind-source-manifest-v2\0' + fields(original.hex(), 'parser-json', 'json-source-v1')
                + bytes([90, 0, 1]) + field(snapshot_time) + u64(1) + b'\0')
    return (b'irmind-source-record-set-v1\0' + fields(letter * 64, sha(manifest), path)
            + b'\0\0' + fields('parser-json', 'json-source-v1') + wire_time + fields(SOURCE, contracts()[0])
            + u64(1) + fields('json', 'source-json-v1') + u64(2) + u64(1) + field('b' * 64))


def snapshot():
    return (b'irmind-mapping-snapshot-v1\0' + fields(*MAPPER)
            + field('{"contract":"synthetic","selectors":[]}'))


def profile(letter, source):
    return (b'irmind-mapping-profile-v1\0'
            + fields(SOURCE, TARGET, 'irmind-mapping-selection-v1', POLICY, *contracts())
            + u64(1) + fields(letter * 64, sha(source)) + u64(2)
            + u64(1) + fields(*MAPPER, sha(snapshot())))


def catalog():
    return sha(b'irmind-mapping-catalog-v1\0' + u64(1) + fields(*MAPPER, sha(snapshot())))


def partition():
    return (fields('2026-01-02', 'scope-partitions-v1', 'nfkc-unicode-18.0.0-ascii-v1')
            + u64(4096) + b'\0' + u64(0))


def binding(letter, source, prof):
    return (fields(letter * 64, sha(source), sha(prof), catalog()) + u64(2)
            + fields('parser-json', 'json-source-v1') + b'\1' + fields(*MAPPER))


def artifact(path, file_hash, sources, bindings, rows, parents=None):
    builder = LAYOUT if parents else BUILDER
    core = (b'irmind-parquet-artifact-v2\0' + field(path) + u64(150 if parents else 100)
            + fields(file_hash, 'parser-json', 'json-source-v1', 'irmind-events-v4')
            + partition() + u64(len(sources)) + fields(*sources)
            + fields('utc-microseconds-residual-ns-v1', 'instant-source-offset-record-v1', builder) + u64(0))
    out = (b'irmind-parquet-artifact-v3\0' + field(core)
           + fields('irmind-artifact-pipeline-v1', 'layout' if parents else 'mapped', SOURCE, TARGET, POLICY, *contracts())
           + u64(len(bindings)) + b''.join(bindings) + u64(rows))
    if parents:
        out += field(builder) + u64(len(parents)) + b''.join(fields(p, sha(a)) for p, a in parents)
    return out


def commitment(tag, values):
    data = tag + u64(len(values)) + b''.join(field(v) for v in values)
    return u64(len(values)) + field(sha(data))


def fixtures():
    a = source_set('a', 'logs/synthetic.json')
    d = source_set('d', 'logs/second.json')
    pa, pd = profile('a', a), profile('d', d)
    ba, bd = binding('a', a, pa), binding('d', d, pd)
    path_a, path_b, path_c = ['date=2026-01-02/part-' + x + '.parquet' for x in 'abc']
    first = artifact(path_a, 'e' * 64, ['a' * 64], [ba], 2)
    second = artifact(path_b, 'f' * 64, ['d' * 64], [bd], 2)
    parent_commitment = commitment(b'irmind-layout-parents-v1\0', [first, second])
    seed = (b'irmind-layout-path-v1\0' + field(LAYOUT) + parent_commitment
            + field('irmind-events-v4') + partition() + u64(0))
    path_c = 'date=2026-01-02/layout-' + sha(seed) + '.parquet'
    child = artifact(path_c, '1' * 64, ['a' * 64, 'd' * 64], [ba, bd], 4,
                     [(path_a, first), (path_b, second)])
    layout = (b'irmind-parquet-layout-v1\0' + field(LAYOUT)
              + commitment(b'irmind-layout-parents-v1\0', [first, second])
              + commitment(b'irmind-layout-replacements-v1\0', [child])
              + commitment(b'irmind-layout-bindings-v1\0', [ba, bd])
              + field('irmind-events-v4') + partition() + u64(4))
    run = (b'irmind-mapping-run-v1\0' + fields(sha(pa), catalog()) + u64(1)
           + field('a' * 64) + b'\1' + fields(*MAPPER) + u64(2) + u64(0) * 3
           + commitment(b'irmind-mapping-outputs-v1\0', [first]))
    return {'source-set-v1': a, 'source-set-time-v1': source_set('a', 'logs/synthetic.json', (2026, -210, True, 'command')), 'snapshot-v1': snapshot(), 'profile-v1': pa,
            'mapped-v3': first, 'layout-v3': child, 'layout-receipt-v1': layout, 'mapping-run-v1': run}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='write only the new mapping/layout fixtures')
    args = parser.parse_args()
    for name, value in fixtures().items():
        path = DEST / (name + '.hex')
        text = value.hex() + '\n'
        if args.write:
            path.write_text(text)
        elif path.read_text() != text:
            raise SystemExit('mapping fixture differs: ' + name)
    print('Checked 8 independent mapping/layout wire fixtures')


if __name__ == '__main__':
    main()
