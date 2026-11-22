"""Keep native macOS builds and their published verification material aligned."""
from pathlib import Path
import unittest
import re

WORKFLOW = Path(__file__).parents[1] / 'workflows/ci.yml'
RELEASE = WORKFLOW.with_name('release.yml')


class MacOSReleaseTests(unittest.TestCase):
    def test_thin_lto_is_scoped_to_the_main_release_binary(self):
        workflow = WORKFLOW.read_text()
        optimized = ('CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 '
                     'cargo build --release -p irmind --locked')
        for name in ('linux', 'linux_arm64', 'windows', 'macos'):
            with self.subTest(job=name):
                job = re.split(r'\n  \w+:\n', workflow.split(f'  {name}:\n', 1)[1], 1)[0]
                self.assertIn('\n          ' + optimized + '\n'
                              '          cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked', job)
        for variable in ('CARGO_PROFILE_RELEASE_LTO', 'CARGO_PROFILE_RELEASE_CODEGEN_UNITS'):
            self.assertEqual(workflow.count(variable), workflow.count(optimized))

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
        release = WORKFLOW.read_text().split('  release:\n', 1)[1].split('  post_release:', 1)[0]
        for name in ('irmind-macos-x86_64', 'irmind-evtx-macos-x86_64'):
            self.assertIn(f' release/{name}\n', release)
            checksum_line = next(line for line in release.splitlines() if '> SHA256SUMS)' in line)
            self.assertIn(name, checksum_line.split())
            loops = [line for line in release.splitlines() if 'for file in ' in line]
            self.assertEqual(len(loops), 2)
            self.assertTrue(all('release/' + name in line.split() for line in loops))
        self.assertIn("subject-path: 'release/irmind-*'", release)

    def test_optional_native_signing_does_not_skip_post_release_installation(self):
        caller = WORKFLOW.read_text().split('  post_release:\n', 1)[1]
        self.assertIn('uses: ./.github/workflows/release.yml', caller)
        self.assertIn("needs.release.result == 'success'", caller)
        self.assertIn("github.event_name == 'push'", caller)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", caller)
        self.assertNotIn('needs.native_macos', caller)
        workflow = RELEASE.read_text()
        for name in ('verify_install_linux', 'verify_install_macos', 'verify_install_windows'):
            with self.subTest(job=name):
                job = workflow.split(f'  {name}:\n', 1)[1]
                condition = re.search(r'^    if: (.+)$', job, re.MULTILINE).group(1)
                self.assertIn('!cancelled()', condition)
                self.assertIn("github.event_name == 'push'", condition)
                self.assertIn("startsWith(github.ref, 'refs/tags/v')", condition)
                self.assertNotIn('needs.native_macos', condition)

    def test_clean_installation_runs_on_both_native_architectures(self):
        job = RELEASE.read_text().split('  verify_install_macos:\n', 1)[1].split('  verify_install_windows:', 1)[0]
        self.assertIn('runner: [macos-latest, macos-15-intel]', job)
        self.assertIn('attestations: read', job)
        self.assertIn('sh install.sh "$GITHUB_REF_NAME"', job)
        self.assertNotIn('contents: write', job)


if __name__ == '__main__':
    unittest.main()
