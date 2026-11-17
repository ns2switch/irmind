"""External export examples never exempt flags used by IRMind itself."""
import unittest
import check_docs

class CommandOwnership(unittest.TestCase):
    def test_complete_gcloud_export_uses_the_gcloud_cli(self):
        self.assertEqual(check_docs.irmind_flag_citations('gcloud logging read query --project=PROJECT --format=json > cloud.json'), set())

    def test_same_flag_in_irmind_still_requires_cli_support(self):
        self.assertIn('--format', check_docs.irmind_flag_citations('irmind --format=json'))
        self.assertIn('--made-up-flag', check_docs.irmind_flag_citations('irmind --made-up-flag'))

    def test_a_mixed_shell_line_does_not_hide_irmind_options(self):
        for suffix in [' && irmind --made-up-flag', '; irmind --made-up-flag', ' > $(irmind --made-up-flag)']:
            self.assertIn('--made-up-flag', check_docs.irmind_flag_citations('gcloud logging read query --format=json'+suffix))

    def test_external_example_cannot_exempt_a_later_irmind_line(self):
        text = 'gcloud logging read query --format=json\nirmind --made-up-flag'
        self.assertIn('--made-up-flag', check_docs.irmind_flag_citations(text))

    def test_catalog_environment_secret_example_uses_github_flags(self):
        line = 'gh secret set CATALOG_ED25519_SEED_HEX --repo ns2switch/irmind-skills --env release < catalog-seed.hex'
        self.assertEqual(check_docs.irmind_flag_citations(line), set())
        for suffix in [' && irmind --repo=unexpected', '; target/ci/irmind --env=unexpected']:
            self.assertTrue(check_docs.irmind_flag_citations(line + suffix))
        self.assertIn('--repo', check_docs.irmind_flag_citations('irmind --repo=unexpected'))
        self.assertIn('--env', check_docs.irmind_flag_citations('irmind --env=unexpected'))

class LaunchCommandOwners(unittest.TestCase):
    def test_external_lab_and_benchmark_flags_have_their_own_owner(self):
        text = "docker compose --env-file lab.env up\ncurl --cacert ca.crt https://localhost:9200\npython3 scripts/hunteval_benchmark.py --models local.json --execute\npython3 tools/real-validation/lab.py load --windows-utc-offset +00:00\n"
        self.assertEqual(check_docs.irmind_flag_citations(text), set())
        self.assertEqual(check_docs.irmind_flag_citations("gh secret set APPLE_API_KEY_ID --repo ns2switch/irmind --env release"), set())
        self.assertIn("--bad-irmind-option", check_docs.irmind_flag_citations(
            "docker compose up && irmind --bad-irmind-option"))

    def test_native_signing_flags_belong_to_the_inspection_tools(self):
        text = 'codesign --verify --strict --verbose=2 ./irmind\nspctl --assess --type execute --verbose=4 ./irmind\nxcrun stapler validate ./IRMind-macos-aarch64.dmg'
        self.assertEqual(check_docs.irmind_flag_citations(text), set())
        self.assertEqual(check_docs.COMMAND.findall(text), [])
        for extra in [' && irmind --made-up-flag', '; ./irmind --made-up-flag', ' $(irmind --made-up-flag)', ' `irmind --made-up-flag`']:
            self.assertIn('--made-up-flag', check_docs.irmind_flag_citations('codesign --verify ./irmind' + extra))
        self.assertIn('--made-up-flag', check_docs.irmind_flag_citations('xcrun irmind --made-up-flag'))


if __name__ == '__main__':
    unittest.main()
