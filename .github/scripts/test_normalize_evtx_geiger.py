#!/usr/bin/env python3
import json
import unittest
from normalize_evtx_geiger import normalize


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


if __name__ == '__main__':
    unittest.main()
