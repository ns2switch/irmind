#!/usr/bin/env python3
"""Regression checks for portable, fail-closed reviewed-source verification."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('check_date_dependencies.py')
SPEC = importlib.util.spec_from_file_location('check_date_dependencies', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DateSourceChecks(unittest.TestCase):
    def test_source_hashes_do_not_use_the_host_text_encoding(self):
        env = dict(os.environ, LC_ALL='C', PYTHONUTF8='0', PYTHONCOERCECLOCALE='0')
        result = subprocess.run([sys.executable, '-B', str(SCRIPT)], env=env,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))
        self.assertIn(b'57 unchanged unsafe-bearing sources verified', result.stdout)

    def test_a_changed_reviewed_source_hash_is_rejected(self):
        with patch.object(MODULE, 'digest', return_value='0' * 64):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SystemExit, 'reviewed source hash differs'):
                    MODULE.main()

    def test_unsafe_source_changes_are_still_rejected(self):
        read_text = Path.read_text
        target = MODULE.ROOT / 'vendor/arrow-array/src/array/boolean_array.rs'
        def changed(path, *args, **kwargs):
            source = read_text(path, *args, **kwargs)
            if path == target:
                source = source.replace('unsafe { self.values.value_unchecked(i) }',
                                        'unsafe { self.values.value_unchecked(0) }', 1)
            return source
        with patch.object(Path, 'read_text', new=changed):
            with self.assertRaisesRegex(SystemExit, 'upstream unsafe-bearing source changed'):
                MODULE.main()

    def test_reviewed_vendor_files_disable_checkout_conversion(self):
        paths = []
        for name in ('arrow-array', 'parquet'):
            manifest = MODULE.json.loads((MODULE.ROOT / 'vendor' / name / 'UPSTREAM.json').read_text(encoding='utf-8'))
            paths.extend(f'vendor/{name}/{p}' for p in manifest['reviewed_file_sha256'])
        result = subprocess.run(['git', 'check-attr', '-z', '--stdin', 'text'],
                                input=('\0'.join(paths) + '\0').encode(),
                                cwd=MODULE.ROOT, capture_output=True, check=True)
        fields = result.stdout.decode('utf-8').split('\0')
        self.assertEqual(len(fields), len(paths) * 3 + 1)
        for path, attribute, state in zip(fields[0:-1:3], fields[1:-1:3], fields[2:-1:3]):
            self.assertEqual((attribute, state), ('text', 'unset'), path)


if __name__ == '__main__':
    unittest.main()
