#!/usr/bin/env python3
"""Aggregate Heaptrack allocation-call stacks without publishing raw traces or paths."""
import argparse
import json
from collections import Counter
from pathlib import Path

# The deepest recognized production frame owns each allocation; never count twice.
PHASES = (
    ("commitment_finalization", ("source_mapping::stream::commitment::finish",)),
    ("common_validation_serialization", ("common_event::check_common_record", "common_event::codec::encode_common_event", "common_event::codec::Wire")),
    ("writer_projection", ("writer::common::row", "RecordRow::from_mapping")),
    ("mapping", ("irmind_mapping_tables::map::", "irmind_mapping_tables::TableMapping::project", "mapping_ecs::", "mapping_ocsf::", "mapping_cloudtrail::", "mapping_journald_compat::")),
    ("source_validation_commitment", ("SourceRecordAccumulator", "source_mapping::stream::validation", "source_mapping::stream::commitment::spool_tuple")),
    ("decode", ("parser_ecs::source_decode", "parser_ocsf::source_decode", "parser_json::source_decode", "parser_linux::source_frames", "parser_evtx::source_decode", "parser_evtx::codec")),
    ("parquet_write", ("parquet_store::writer::", "parquet::arrow::arrow_writer", "parquet::column::writer")),
    ("partition_sort", ("parquet_store::partitioning::", "parquet_store::spool::")),
    ("hash_read", ("ParquetStore::hash_reader", "HashingReader")),
    ("signed_custody", ("irmind_infra::signing::", "irmind_infra::sqlite::audit", "irmind_app::signed_entry")),
)

def phase(stack):
    for frame in reversed(stack.split(';')):
        if 'SourceRecordAccumulator' in frame and '::finish' in frame:
            return 'commitment_finalization'
        for name, patterns in PHASES:
            if any(pattern in frame for pattern in patterns):
                # Mapping construction outside ingestion is not mapping work.
                if name == 'mapping' and not any(word in frame for word in ('::map', '::project')):
                    continue
                return name
    return 'outside_or_unattributed'

def aggregate(text):
    counts = Counter({name: 0 for name, _ in PHASES})
    counts['outside_or_unattributed'] = 0
    total = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        stack, raw = line.rsplit(' ', 1)
        count = int(raw)
        if count < 0:
            raise ValueError('negative allocation count')
        counts[phase(stack)] += count
        total += count
    if not total:
        raise ValueError('empty allocation profile')
    assert sum(counts.values()) == total
    if counts['outside_or_unattributed'] == total:
        raise ValueError('no production allocation stacks could be attributed')
    for required in ('mapping', 'writer_projection', 'common_validation_serialization', 'source_validation_commitment', 'commitment_finalization'):
        if not counts[required]:
            raise ValueError('missing production allocation symbols for ' + required)
    return {'allocation_calls': dict(counts), 'total_allocation_calls': total,
            'attributed_calls': total - counts['outside_or_unattributed'],
            'method': 'Heaptrack calls to allocation functions; exclusive deepest recognized stack frame. Other calls remain explicit. Timing comes from separate uninstrumented runs.'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stacks', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--source', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--heaptrack-version', required=True)
    args = parser.parse_args()
    result = aggregate(args.stacks.read_text())
    result.update(source=args.source, revision=args.revision, heaptrack_version=args.heaptrack_version)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')

if __name__ == '__main__':
    main()
