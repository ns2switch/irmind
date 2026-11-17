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


if __name__ == '__main__':
    unittest.main()
