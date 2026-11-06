#!/usr/bin/env python3
import json
import unittest
from normalize_evtx_geiger import normalize, parse_errors


class Report(unittest.TestCase):
    def test_build_paths_and_package_sources_are_not_published(self):
        raw = {
            'packages': [{
                'package': {'id': {'name': 'synthetic', 'version': '1.0',
                                   'source': '/private/build-user/package'}},
                'unsafety': {'forbids_unsafe': True, 'used': {}, 'unused': {}},
            }],
            'packages_without_metrics': [],
            'used_but_not_scanned_files': ['/private/build-user/out/version.expr'],
        }
        result = normalize(raw)
        self.assertNotIn('build-user', json.dumps(result))
        self.assertEqual(result['unscanned_inputs'], ['version.expr'])
        self.assertEqual(result['packages'][0]['crate'], 'synthetic')

    def test_nonproduction_parse_gaps_are_reported_without_machine_paths(self):
        diagnostic = 'Failed to parse file: /private/build/.cargo/registry/src/index/example-1.0/src/lib.rs, Syn(Error("syntax"))'
        errors = parse_errors(diagnostic, set())
        self.assertEqual(errors[0]['package'], 'example-1.0')
        self.assertEqual(errors[0]['file'], 'src/lib.rs')
        self.assertNotIn('/private/', json.dumps(errors))
        with self.assertRaisesRegex(SystemExit, 'production dependency'):
            parse_errors(diagnostic, {'example-1.0'})


if __name__ == '__main__':
    unittest.main()
