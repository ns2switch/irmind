"""Keep native macOS builds and their published verification material aligned."""
from pathlib import Path
import unittest

WORKFLOW = Path(__file__).parents[1] / 'workflows/ci.yml'


class MacOSReleaseTests(unittest.TestCase):
    def test_both_architectures_are_built_and_tested_natively(self):
        job = WORKFLOW.read_text().split('  macos:\n', 1)[1].split('  macos_verify_windows:', 1)[0]
        for entry in ('runner: macos-latest, target: aarch64-apple-darwin, arch: arm64',
                      'runner: macos-15-intel, target: x86_64-apple-darwin, arch: x86_64'):
            self.assertIn(entry, job)
        self.assertIn('cargo nextest run --workspace --all-features', job)
        self.assertIn('python3 helpers/evtx/test.py', job)
        self.assertIn('target/${{ matrix.target }}/release/irmind-evtx', job)
        self.assertIn('name: "irmind-macos-${{ matrix.arch }}"', job)

    def test_every_intel_binary_is_checksummed_signed_verified_and_attested(self):
        release = WORKFLOW.read_text().split('  release:\n', 1)[1].split('  verify_install_linux:', 1)[0]
        for name in ('irmind-macos-x86_64', 'irmind-evtx-macos-x86_64'):
            self.assertIn(f' release/{name}\n', release)
            checksum_line = next(line for line in release.splitlines() if '> SHA256SUMS)' in line)
            self.assertIn(name, checksum_line.split())
            loops = [line for line in release.splitlines() if 'for file in ' in line]
            self.assertEqual(len(loops), 2)
            self.assertTrue(all('release/' + name in line.split() for line in loops))
        self.assertIn("subject-path: 'release/irmind-*'", release)

    def test_clean_installation_runs_on_both_native_architectures(self):
        job = WORKFLOW.read_text().split('  verify_install_macos:\n', 1)[1].split('  verify_install_windows:', 1)[0]
        self.assertIn('runner: [macos-latest, macos-15-intel]', job)
        self.assertIn('attestations: read', job)
        self.assertIn('sh install.sh "$GITHUB_REF_NAME"', job)
        self.assertNotIn('contents: write', job)


if __name__ == '__main__':
    unittest.main()
