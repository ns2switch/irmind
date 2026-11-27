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
        discovery, builds = binaries.split('  verify_release_reproducibility:', 1)
        self.assertCountEqual(re.findall(r'destination: (\S+), runner:', discovery), PLATFORMS)
        self.assertCountEqual(re.findall(r'destination: (\S+), runner:', builds), PLATFORMS)
        self.assertIn('needs: prepare_native_mapping_inputs', builds)
        self.assertIn('--mapping-inputs mapping-inputs/NATIVE-MAPPING-INPUTS.json', builds)
        self.assertIn('runner: macos-26, artifact: irmind-macos-arm64', binaries)
        self.assertIn('runner: macos-15-intel, artifact: irmind-macos-x86_64', binaries)

    def test_portable_sigma_case_is_required_on_tags_and_tagless_rehearsals(self):
        workflow = WORKFLOW.read_text()
        caller = workflow.split('  release_binaries:\n', 1)[1].split('  native_macos:', 1)[0]
        self.assertIn("needs.dco.outputs.release_build == 'true'", caller)
        self.assertNotIn('secrets:', caller)
        release = workflow.split('  release:\n', 1)[1].split('  post_release:', 1)[0]
        self.assertIn("needs.release_binaries.outputs.portable_sigma_verified == 'true'", release)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", release)
        self.assertIn('inputs.release_dry_run == true', release)
        binaries = BINARIES.read_text()
        self.assertIn('jobs.require_sigma_report_case.outputs.verified', binaries)
        producer, tail = binaries.split('  create_sigma_report_case:\n', 1)[1].split(
            '  verify_sigma_report_case:\n', 1)
        consumer, gate = tail.split('  require_sigma_report_case:\n', 1)
        self.assertIn('needs: verify_release_reproducibility', producer)
        self.assertIn('--test release_sigma_report -- --ignored', producer)
        self.assertIn('needs: [verify_release_reproducibility, create_sigma_report_case]', consumer)
        self.assertIn('verify_release_sigma_report.py', consumer)
        self.assertIn('needs: [create_sigma_report_case, verify_sigma_report_case]', gate)
        self.assertRegex(gate, r"(?m)^        run: echo 'verified=true'")
        for job in (producer, consumer, gate):
            self.assertNotRegex(job, r'(?m)^ +(?:if|continue-on-error|environment|secrets):')
            self.assertNotRegex(job, r'\b(?:secrets|inputs|vars)\.')

    def test_release_workflows_pin_their_runner_images(self):
        for workflow in (WORKFLOW, RELEASE, BINARIES):
            self.assertNotRegex(workflow.read_text(), r"(?:ubuntu|macos|windows)-latest")

    def test_build_environment_is_checksummed_signed_verified_and_attested(self):
        release = WORKFLOW.read_text().split('  release:\n', 1)[1].split('  post_release:', 1)[0]
        self.assertIn('assemble artifacts release/BUILD-ENVIRONMENT.json', release)
        checksum = next(line for line in release.splitlines() if '> SHA256SUMS)' in line)
        self.assertIn('BUILD-ENVIRONMENT.json', checksum.split())
        self.assertIn('NATIVE-MAPPING-INPUTS.json', checksum.split())
        signing_loops = [line for line in release.splitlines() if 'for file in ' in line]
        self.assertEqual(len(signing_loops), 2)
        self.assertTrue(all('release/NATIVE-MAPPING-INPUTS.json' in line.split() for line in signing_loops))
        self.assertTrue(all('release/BUILD-ENVIRONMENT.json' in line.split() for line in signing_loops))
        self.assertIn('subject-path: |\n            release/*SBOM.spdx.json\n            release/BUILD-ENVIRONMENT.json', release)
        self.assertIn('release/* --clobber', release)

    def test_release_downloads_every_required_artifact_before_packaging(self):
        release = WORKFLOW.read_text().split('  release:\n', 1)[1].split('  post_release:', 1)[0]
        downloads, _ = release.split('      - name: Stage binaries and install scripts', 1)
        required = re.findall(
            r'(?m)^      - uses: actions/download-artifact@[^\n]+\n'
            r'        with: \{name: ([^,]+), path: artifacts/([^}]+)\}$',
            downloads,
        )
        self.assertCountEqual(required, [
            ('irmind-linux', 'linux-x86_64'),
            ('irmind-linux-arm64', 'linux-aarch64'),
            ('irmind-macos-arm64', 'macos-aarch64'),
            ('irmind-macos-x86_64', 'macos-x86_64'),
            ('irmind-windows', 'windows-x86_64'),
            ('native-mapping-build-inputs', 'native-mapping-build-inputs'),
        ])

    def test_full_rehearsal_keeps_verified_assets_and_skips_release_writes(self):
        release = WORKFLOW.read_text().split('  release:\n', 1)[1].split('  post_release:', 1)[0]
        shared, publication = release.split('      - name: Publish the signed release', 1)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.release_dry_run == true", shared)
        self.assertLess(shared.index('cosign verify-blob'), shared.index('name: signed-release-dry-run'))
        self.assertNotIn('gh release ', shared)
        tag_gate = "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
        publish, edit_notes = publication.split('      - name: Add the public code signing policy', 1)
        self.assertIn(tag_gate, publish)
        self.assertIn('gh release create ', publish)
        self.assertIn(tag_gate, edit_notes)
        self.assertIn('gh release edit ', edit_notes)

    def test_windows_rehearsal_runs_with_the_verified_release_helper(self):
        build = BINARIES.read_text()
        witness = build.split('      - name: Measure the released Windows helper', 1)[1]
        witness = witness.split('      - uses:', 1)[0]
        self.assertIn("if: runner.os == 'Windows' && inputs.signing_rehearsal", witness)
        self.assertIn('cp dist/irmind-evtx.exe target/x86_64-pc-windows-msvc/release/', witness)
        self.assertIn('target/x86_64-pc-windows-msvc/release/examples/collection.exe', witness)

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
        self.assertIn('runner: macos-26, target: aarch64-apple-darwin, arch: arm64', job)
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
        self.assertIn('runner: [macos-26, macos-15-intel]', job)
        self.assertIn('attestations: read', job)
        self.assertIn('sh install.sh "$GITHUB_REF_NAME"', job)
        self.assertNotIn('contents: write', job)


if __name__ == '__main__':
    unittest.main()
