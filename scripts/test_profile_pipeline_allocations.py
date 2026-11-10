#!/usr/bin/env python3
import unittest
from profile_pipeline_allocations import aggregate, phase

class AllocationAttribution(unittest.TestCase):
    def test_deepest_phase_and_totals(self):
        result = aggregate('ingest;SourceRecordAccumulator::accept;irmind_mapping_tables::map::project;malloc 9\ningest;SourceRecordAccumulator::accept;source_mapping::stream::commitment::spool_tuple;malloc 4\nSourceRecordAccumulator::finish;malloc 2\ncommon_event::check_common_record;malloc 5\nwriter::common::row;malloc 6\nbootstrap;malloc 3\n')
        self.assertEqual(result['allocation_calls']['mapping'], 9)
        self.assertEqual(result['allocation_calls']['source_validation_commitment'], 4)
        self.assertEqual(result['allocation_calls']['outside_or_unattributed'], 3)
        self.assertEqual(result['total_allocation_calls'], 29)
    def test_real_rust_trait_frames_and_inherent_table_methods(self):
        self.assertEqual(phase('<irmind_mod_mapping_ecs::EcsMapping as irmind_app::SourceMapper>::map;malloc'), 'mapping')
        self.assertEqual(phase('irmind_mapping_tables::TableMapping::project;malloc'), 'mapping')
    def test_missing_phase_symbols_are_not_reported_as_zero_work(self):
        with self.assertRaises(ValueError):
            aggregate('irmind_mapping_tables::TableMapping::project;malloc 10')
    def test_zero_and_invalid_are_not_valid_profiles(self):
        for text in ('', 'malloc -1'):
            with self.assertRaises(ValueError): aggregate(text)
    def test_buffer_finalization_is_not_decoder_work(self):
        self.assertEqual(phase('SourceRecordAccumulator::finish;source_mapping::stream::commitment::finish;malloc'), 'commitment_finalization')

if __name__ == '__main__': unittest.main()
