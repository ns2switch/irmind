#!/usr/bin/env python3
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import hunteval_benchmark as b

HASH = 'a' * 64


class MetricsTests(unittest.TestCase):
    def test_exact_scores_keep_false_positives_and_do_not_count_query_echo(self):
        final = {'events': ['evt-0001', 'evt-9999'], 'entities': ['alice', 'invented'],
                 'techniques': ['T1078'], 'findings': [{'claim': 'Check this event',
                    'event_ids': ['evt-0001'], 'evidence_hashes': [HASH]}]}
        observed = {'final': json.dumps(final), 'tool_text': 'query=evt-9999 source=' + HASH + '#0 alice',
                    'known_hashes': {HASH}, 'source_hash': HASH}
        result = b.evaluate(observed, [{'event_id': 'evt-0001', 'principal': 'alice'}],
                            {'malicious_event_ids': ['evt-0001'], 'malicious_entity_ids': ['alice'],
                             'expected_attack_techniques': ['T1078']})
        self.assertEqual(result['events']['precision'], 0.5)
        self.assertEqual(result['entities']['precision'], 0.5)
        self.assertEqual(result['false_positive_event_ids'], ['evt-9999'])
        self.assertEqual(result['retrieved_events']['reported'], 1)
        self.assertEqual(result['event_supported_finding_proxy']['supported'], 1)
        self.assertIsNone(result['human_correct_findings'])

    def test_invalid_answer_and_unsupported_citations_are_not_success(self):
        with self.assertRaises(ValueError):
            b.final_object('There may be a compromise.')
        with self.assertRaises(ValueError):
            b.final_object(json.dumps({'events': [], 'entities': [], 'techniques': [], 'findings': [{}]}))

    def test_provider_keys_are_not_inherited_or_passed_as_arguments(self):
        import subprocess
        observed = subprocess.CompletedProcess([], 0, 'ok', '')
        with patch.dict(b.os.environ, {'PROVIDER_API_KEY': 'do-not-forward', 'IRMIND_MODEL': 'ambient'}), \
             patch.object(b.subprocess, 'run', return_value=observed) as call:
            b.invoke(Path('/synthetic/irmind'), Path('/synthetic/home'), 'unlock-phrase', 'case', 'list')
        self.assertNotIn('PROVIDER_API_KEY', call.call_args.kwargs['env'])
        self.assertNotIn('IRMIND_MODEL', call.call_args.kwargs['env'])
        self.assertNotIn('unlock-phrase', call.call_args.args[0])
        self.assertEqual(call.call_args.kwargs['input'], 'unlock-phrase\n')

    def test_every_model_run_finishes_before_private_answers_are_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); binary = root / 'irmind'; binary.write_bytes(b'synthetic')
            source = root / 'events.json'; source.write_text('[{"event_id":"evt-0001"}]')
            hidden = root / 'ground-truth.json'; hidden.write_text(json.dumps({
                'malicious_event_ids': [], 'malicious_entity_ids': [], 'expected_attack_techniques': []}))
            count = 0
            def invoke(_binary, _home, _password, *args):
                nonlocal count
                self.assertNotIn(str(hidden), args)
                self.assertFalse(any('ground-truth' in arg for arg in args))
                if args[0] == 'case':
                    return '00000000-0000-0000-0000-000000000001'
                if 'ask' in args:
                    count += 1
                return ''
            def verify_private(_root, _relative):
                self.assertEqual(count, 18)
            observed = dict(final=json.dumps(dict(events=[], entities=[], techniques=[], findings=[])),
                            tool_text='', known_hashes=set(), tool_calls=0, input_tokens=None,
                            output_tokens=None, estimated_cost_microusd=None, usage_complete=False,
                            retrieval_complete=True)
            models = [dict(label='fake', module='llm-deepseek', model='synthetic', home=root)]
            argv = ['benchmark', '--hunteval-root', str(root), '--models', 'unused', '--binary',
                    str(binary), '--output', str(root / 'report'), '--execute']
            with patch('sys.argv', argv), patch.object(b, 'models_from', return_value=models), \
                 patch.object(b, 'checked_files', return_value=(source, hidden)), \
                 patch.object(b, 'verify_checksum', side_effect=verify_private), \
                 patch.object(b, 'invoke', side_effect=invoke), \
                 patch.object(b, 'read_verified_case', return_value=observed.copy()), \
                 patch.object(b.getpass, 'getpass', return_value='synthetic-passphrase'), \
                 patch.object(b.subprocess, 'check_output', return_value='irmind synthetic'):
                b.main()
            report = json.loads((root / 'report/report.json').read_text())
            self.assertEqual(len(report['runs']), 18)
            self.assertEqual(report['status_counts'], {'scored_pending_human_review': 18})


if __name__ == '__main__':
    unittest.main()
