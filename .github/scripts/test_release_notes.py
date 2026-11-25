"""Release notes preserve existing content and expose the signing policy."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from release_notes import FOOTER, POLICY_URL, append_policy


class ReleaseNotesTests(unittest.TestCase):
    def test_manual_notes_and_unicode_are_preserved(self):
        notes = "# v0.5.3\n\nReviewer notes: Cañada · synthetic data.\n\n[Checksums](SHA256SUMS)\n"
        result = append_policy(notes)
        self.assertTrue(result.startswith(notes.rstrip() + "\n\n---\n\n"))
        self.assertIn(f"Code signing policy: {POLICY_URL}", result)
        self.assertTrue(result.endswith(FOOTER + "\n"))

    def test_old_sponsorship_credit_is_removed_without_changing_other_notes(self):
        old_credit = "Free code signing provided by " + "a former service, certificate by its foundation"
        notes = "Manual release notes.\n\n" + FOOTER + "\n\n" + old_credit + "\n"
        result = append_policy(notes)
        self.assertIn("Manual release notes.", result)
        self.assertNotIn(old_credit, result)
        self.assertEqual(result.count(FOOTER), 1)
        self.assertEqual(append_policy(result), result)

    def test_publication_retry_does_not_duplicate_or_replace_notes(self):
        first = append_policy("Generated notes\n")
        manual_edit = first + "\nAdditional maintainer note.\n"
        self.assertEqual(append_policy(first), first)
        self.assertEqual(append_policy(manual_edit), manual_edit)
        self.assertEqual(manual_edit.count(FOOTER), 1)

    def test_empty_release_gets_policy(self):
        self.assertEqual(append_policy("\n"), FOOTER + "\n")

    def test_cli_updates_an_existing_utf8_file_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            notes = Path(directory) / "notes.md"
            notes.write_text("Release · existing notes\n", encoding="utf-8")
            command = [sys.executable, str(Path(__file__).with_name("release_notes.py")), str(notes)]
            subprocess.run(command, check=True)
            first = notes.read_bytes()
            subprocess.run(command, check=True)
            self.assertEqual(first, notes.read_bytes())
            self.assertIn(b"existing notes", first)

    def test_workflow_updates_notes_after_create_or_upload(self):
        workflow = (Path(__file__).parents[1] / "workflows/ci.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Add the public code signing policy to release notes\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        self.assertIn("if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')", step)
        self.assertIn('gh release view "$GITHUB_REF_NAME" --json body --jq .body', step)
        self.assertIn("python3 .github/scripts/release_notes.py", step)
        self.assertIn('gh release edit "$GITHUB_REF_NAME" --notes-file', step)
        self.assertLess(workflow.index('gh release create "$GITHUB_REF_NAME"'),
                        workflow.index("      - name: Add the public code signing policy"))
        self.assertNotIn("uses: signpath/", workflow.lower())


if __name__ == "__main__":
    unittest.main()
