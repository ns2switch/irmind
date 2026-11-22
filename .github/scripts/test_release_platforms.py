"""Keep native macOS builds and their published verification material aligned."""
from pathlib import Path
import unittest
import re
from tempfile import TemporaryDirectory

from build_release_binaries import PLATFORMS, build_env, verify_rebuild

WORKFLOW = Path(__file__).parents[1] / 'workflows/ci.yml'
RELEASE = WORKFLOW.with_name('release.yml')
BINARIES = WORKFLOW.with_name('release-binaries.yml')


class MacOSReleaseTests(unittest.TestCase):
    def test_all_destinations_build_the_pair_before_signing(self):
        workflow = WORKFLOW.read_text()
        job = workflow.split('  release:\n', 1)[1].split('  post_release:', 1)[0]
        self.assertIn("needs.release_binaries.result == 'success'", job)
        self.assertIn("uses: ./.github/workflows/release-binaries.yml", workflow)
        binaries = BINARIES.read_text()
        self.assertIn('dist --verify', binaries)
        self.assertCountEqual(re.findall(r'destination: (\S+), runner:', binaries), PLATFORMS)
        self.assertIn('runner: macos-latest, artifact: irmind-macos-arm64', binaries)
        self.assertIn('runner: macos-15-intel, artifact: irmind-macos-x86_64', binaries)

    def test_linker_flags_match_the_release_platform(self):
        self.assertEqual(build_env('linux-x86_64')['RUSTFLAGS'], '-C link-arg=-fuse-ld=mold')
        self.assertEqual(build_env('windows-x86_64')['RUSTFLAGS'], '-C link-arg=/Brepro')
        for destination in ('macos-x86_64', 'macos-aarch64', 'linux-aarch64'):
            self.assertNotIn('RUSTFLAGS', build_env(destination))

    def test_altered_helper_fails_reproducibility(self):
        with TemporaryDirectory() as temp:
            first, second = Path(temp) / 'first', Path(temp) / 'second'
            for pair in (first, second):
                pair.mkdir()
                (pair / 'irmind').write_bytes(b'main')
                (pair / 'irmind-evtx').write_bytes(b'helper')
            verify_rebuild('linux-x86_64', first, second)
            (second / 'irmind-evtx').write_bytes(b'other helper')
            with self.assertRaisesRegex(SystemExit, 'linux-x86_64 irmind-evtx differs'):
                verify_rebuild('linux-x86_64', first, second)

    def test_both_architectures_are_tested_natively(self):
        job = WORKFLOW.read_text().split('  macos:\n', 1)[1].split('  macos_verify_windows:', 1)[0]
        self.assertIn('runner: macos-latest, target: aarch64-apple-darwin, arch: arm64', job)
        self.assertIn('runner: macos-15-intel, target: x86_64-apple-darwin, arch: x86_64', job)
        self.assertIn('cargo nextest run --workspace --all-features', job)
        self.assertIn('python3 helpers/evtx/test.py', job)

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
