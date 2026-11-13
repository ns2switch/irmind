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

if __name__ == '__main__':
    unittest.main()
