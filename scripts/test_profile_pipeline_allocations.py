#!/usr/bin/env python3
import unittest
from profile_pipeline_allocations import aggregate, phase

class AllocationAttribution(unittest.TestCase):
    def test_deepest_phase_and_totals(self):
        result = aggregate('ingest;SourceRecordAccumulator::accept;irmind_mapping_tables::map::project;malloc 9\ningest;SourceRecordAccumulator::accept;source_mapping::stream::commitment::spool_tuple;malloc 4\nbootstrap;malloc 3\n')
        self.assertEqual(result['allocation_calls']['mapping'], 9)
        self.assertEqual(result['allocation_calls']['source_validation_commitment'], 4)
        self.assertEqual(result['allocation_calls']['outside_or_unattributed'], 3)
        self.assertEqual(result['total_allocation_calls'], 16)
    def test_zero_and_invalid_are_not_valid_profiles(self):
        for text in ('', 'malloc -1'):
            with self.assertRaises(ValueError): aggregate(text)
    def test_buffer_finalization_is_not_decoder_work(self):
        self.assertEqual(phase('SourceRecordAccumulator::finish;source_mapping::stream::commitment::finish;malloc'), 'commitment_finalization')

if __name__ == '__main__': unittest.main()
