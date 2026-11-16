#!/usr/bin/env python3
"""Exercise the offline mirror pin and its explicit, data-only synchronization."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from skills_inventory import inventory
from sync_core_skills import check, synchronize, validate_pin, validate_rows, REPOSITORY


class CoreMirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'irmind'
        self.root.mkdir()
        self.method = self.root / 'skills/example-method/SKILL.md'
        self.method.parent.mkdir(parents=True)
        self.method.write_bytes(b'Bounded synthetic methodology.\n')
        self.rows = [{'source': 'core/example-method/SKILL.md',
                      'path': 'skills/example-method/SKILL.md',
                      'sha256': hashlib.sha256(self.method.read_bytes()).hexdigest()}]
        generated = inventory(self.root / 'skills')
        self.pin = {'format_version': 1, 'repository': REPOSITORY, 'commit': 'a' * 40,
                    'packages': json.loads(generated['package-identities.json']), 'files': self.rows}
        for name, content in generated.items():
            (self.root / 'skills' / name).write_text(content)
        self.write_pin()

    def write_pin(self):
        (self.root / 'skills/upstream.json').write_text(json.dumps(self.pin))

    def test_check_is_offline_and_preserves_every_byte(self):
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch('subprocess.check_output', side_effect=AssertionError('unexpected external access')):
            self.assertEqual(check(self.root), self.pin)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_tampered_resource_fails(self):
        self.method.write_bytes(self.method.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            check(self.root)

    def test_added_uncommitted_resource_fails(self):
        (self.method.parent / 'extra.txt').write_text('unlisted')
        with self.assertRaisesRegex(ValueError, 'untracked or missing'):
            check(self.root)

    def test_canonical_package_commitment_is_checked_independently(self):
        self.pin['packages']['example-method'] = '0' * 64
        self.write_pin()
        with self.assertRaisesRegex(ValueError, 'canonical package'):
            check(self.root)

    def test_paths_cannot_modify_code_or_escape_the_mirror(self):
        for source, destination in [('core/../escape', 'skills/../escape'),
                                    ('episodes/example/data.rs', 'crates/app/src/lib.rs'),
                                    ('episodes/example/data.json', 'crates/testkit/fixtures/../../app/lib.json'),
                                    ('episodes/example/data.json', '/outside.json')]:
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                validate_rows([{'source': source, 'path': destination, 'sha256': '0' * 64}])

    def test_linked_resource_is_rejected(self):
        outside = Path(self.temp.name) / 'outside'
        outside.write_bytes(self.method.read_bytes())
        self.method.unlink()
        try:
            self.method.symlink_to(outside)
        except OSError:
            self.skipTest('symlink creation not permitted by the platform')
        with self.assertRaisesRegex(ValueError, 'linked'):
            check(self.root)

    def test_pin_requires_a_full_fixed_upstream_commit(self):
        for field, value in [('commit', 'main'), ('repository', 'https://example.invalid/other')]:
            pin = copy.deepcopy(self.pin)
            pin[field] = value
            with self.assertRaises(ValueError):
                validate_pin(pin)

    def test_sync_reads_git_objects_not_the_mutable_worktree(self):
        upstream = Path(self.temp.name) / 'upstream'
        upstream.mkdir()
        subprocess.run(['git', 'init', '-q', str(upstream)], check=True)
        resource = upstream / self.rows[0]['source']
        resource.parent.mkdir(parents=True)
        resource.write_bytes(self.method.read_bytes())
        (upstream / 'core/package-identities.json').write_text(json.dumps(self.pin['packages']))
        (upstream / 'source-map.json').write_text(json.dumps({'format_version': 1, 'files': self.rows}))
        subprocess.run(['git', '-C', str(upstream), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(upstream), '-c', 'user.name=Synthetic test',
                        '-c', 'user.email=synthetic@example.invalid', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'Synthetic mirror'], check=True)
        commit = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
        resource.write_bytes(b'not committed')
        self.assertEqual(synchronize(self.root, upstream, commit)['commit'], commit)
        self.assertEqual(self.method.read_bytes(), b'Bounded synthetic methodology.\n')
        with self.assertRaises(ValueError):
            synchronize(self.root, upstream, 'main')


if __name__ == '__main__':
    unittest.main()
