#!/usr/bin/env python3
"""Offline tests for the closed native-signing gate; no certificate is loaded."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('sign_macos', Path(__file__).with_name('sign_macos.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class GateTests(unittest.TestCase):
    def test_both_architectures_have_closed_disk_image_names(self):
        self.assertEqual(signing.disk_image_name('aarch64'), 'IRMind-macos-aarch64.dmg')
        self.assertEqual(signing.disk_image_name('x86_64'), 'IRMind-macos-x86_64.dmg')
        for invalid in ('../escape', 'arm64', 'x86_64;id'):
            with self.assertRaises(ValueError):
                signing.disk_image_name(invalid)

    def environment(self):
        return dict.fromkeys(signing.FIELDS, 'synthetic') | {
            'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/tags/v0.5.1',
            'MACOS_NATIVE_SIGNING_ENABLED': 'true',
            'APPLE_SIGNING_IDENTITY': 'Developer ID Application: Synthetic (SYNTHETIC0)'}

    def test_requires_explicit_enable_tag_and_complete_secrets(self):
        signing.enabled_environment(self.environment())
        for field, value in [('GITHUB_EVENT_NAME', 'workflow_dispatch'),
                             ('GITHUB_REF', 'refs/heads/main'),
                             ('MACOS_NATIVE_SIGNING_ENABLED', ''),
                             ('APPLE_SIGNING_IDENTITY', 'Apple Development: Synthetic')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                signing.enabled_environment(self.environment() | {field: value})
        for field in signing.FIELDS:
            with self.subTest(missing=field), self.assertRaises(ValueError):
                signing.enabled_environment(self.environment() | {field: ''})

    def test_workflow_requires_protected_tag_job_and_blocks_failed_signing(self):
        workflow = Path(__file__).parents[1] / 'workflows/ci.yml'
        text = workflow.read_text()
        job = text.split('  native_macos:\n', 1)[1].split('  release:\n', 1)[0]
        for gate in ['false &&', "github.event_name == 'push'", "refs/tags/v", 'environment: release',
                     "vars.MACOS_NATIVE_SIGNING_ENABLED == 'true'", 'contents: read']:
            self.assertIn(gate, job)
        self.assertNotIn('id-token: write', job)
        self.assertIn("needs.native_macos.result == 'success' || needs.native_macos.result == 'skipped'", text)
        self.assertIn("subject-path: 'release/IRMind-macos-*.dmg'", text)
        self.assertIn('irmind-macos-native-x86_64', text)
        self.assertIn('irmind-macos-native-aarch64', text)


if __name__ == '__main__':
    unittest.main()
