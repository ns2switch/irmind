from pathlib import Path
import unittest

from release_version import release_kind
from select_homebrew_release import eligible


class HomebrewDispatchTests(unittest.TestCase):
    def test_publication_classifies_stable_and_preview_tags(self):
        self.assertEqual(release_kind("v0.7.4"), "stable")
        for tag in ("v0.8.0-alpha.1", "v0.8.0-beta", "v0.8.0-rc.2"):
            with self.subTest(tag=tag):
                self.assertEqual(release_kind(tag), "prerelease")
        for tag in ("v0.8.0-preview", "v0.8.0-rcx", "v00.8.0", "v0.8.0\n", "main"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_kind(tag)

    def test_publication_excludes_prereleases_from_latest(self):
        workflow = (Path(__file__).parents[1] / "workflows/ci.yml").read_text()
        publish = workflow.split("- name: Publish the signed release", 1)[1].split("- name:", 1)[0]
        self.assertIn('python3 -B .github/scripts/release_version.py "$GITHUB_REF_NAME"', publish)
        self.assertIn('if [ "$release_kind" = prerelease ]; then', publish)
        self.assertIn('release_flags=(--prerelease --latest=false)', publish)
        self.assertIn('--verify-tag "${release_flags[@]}"', publish)

    def test_only_an_exact_published_stable_tag_is_eligible(self):
        self.assertTrue(eligible("v0.8.0", {
            "tagName": "v0.8.0", "isDraft": False, "isPrerelease": False,
        }))
        for tag in ("v0.8.0-alpha.1", "v0.8.0-beta", "v0.8.0-rc.2",
                    "v0.8.0-preview", "v00.8.0", "v0.8.0\n", "main"):
            with self.subTest(tag=tag):
                self.assertFalse(eligible(tag, {
                    "tagName": tag, "isDraft": False, "isPrerelease": False,
                }))

    def test_refuses_preliminary_draft_missing_or_mismatched_metadata(self):
        tag = "v0.8.0"
        for release in (
            {"tagName": tag, "isDraft": False, "isPrerelease": True},
            {"tagName": tag, "isDraft": True, "isPrerelease": False},
            {"tagName": tag, "isDraft": False},
            {"tagName": tag, "isDraft": False, "isPrerelease": 0},
            {"tagName": "v0.8.1", "isDraft": False, "isPrerelease": False},
            [],
            None,
        ):
            with self.subTest(release=release):
                self.assertFalse(eligible(tag, release))

    def test_dispatch_is_tag_only_protected_and_after_verified_installers(self):
        workflow = (Path(__file__).parents[1] / "workflows/ci.yml").read_text()
        job = workflow.split("  update_homebrew:\n", 1)[1].split("\n  release_profile:", 1)[0]
        for required in (
            "environment: release",
            "github.event_name == 'push'",
            "startsWith(github.ref, 'refs/tags/v')",
            "secrets.HOMEBREW_TAP_TOKEN",
            "needs: [release, post_release]",
            "needs.post_release.result == 'success'",
            "needs.release.outputs.homebrew_eligible == 'true'",
            "if: steps.homebrew.outputs.eligible == 'true'",
            "gh workflow run update.yml --repo ns2switch/homebrew-irmind --ref main",
        ):
            self.assertIn(required, job)
        self.assertIn("homebrew_eligible: ${{ steps.homebrew.outputs.eligible }}", workflow)
        self.assertEqual(workflow.count("select_homebrew_release.py"), 2)
        self.assertNotIn("contents: write", job)
        self.assertNotIn("repository_dispatch", job)


if __name__ == "__main__":
    unittest.main()
