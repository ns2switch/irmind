"""Fast tests for CI event selection."""

import unittest
from select_ci_scope import platform_path, select_scope


class ScopeTests(unittest.TestCase):
    def test_platform_paths(self):
        for path in (
            "crates/fs/src/lib.rs", "crates/modules/keystore-file/src/lib.rs",
            "crates/infra/src/windows_security.rs", "crates/tui/src/case.rs",
            "crates/modules/storage-object/src/lib.rs",
            ".github/workflows/ci.yml",
        ):
            self.assertTrue(platform_path(path), path)
        for path in ("crates/app/src/lib.rs", "docs/platforms.md"):
            self.assertFalse(platform_path(path), path)

    def test_ordinary_pull_request_only_runs_linux(self):
        scope = select_scope("pull_request", "refs/pull/7/merge",
                             ["crates/app/src/lib.rs"], set(), True)
        self.assertEqual(scope, dict(run_ci=True, platforms=False,
                                     cross_verify=False, release_build=False))

    def test_platform_or_label_pull_request_runs_matrix_without_release(self):
        for changed, labels in ((["crates/tui/src/lib.rs"], set()),
                                ([], {"full-ci"})):
            scope = select_scope("pull_request", "refs/pull/7/merge",
                                 changed, labels, True)
            self.assertTrue(scope["platforms"])
            self.assertFalse(scope["cross_verify"])
            self.assertFalse(scope["release_build"])

    def test_main_push_is_linux_only(self):
        scope = select_scope("push", "refs/heads/main", [], set(), True)
        self.assertTrue(scope["run_ci"])
        self.assertFalse(scope["platforms"])
        self.assertFalse(scope["release_build"])

    def test_nightly_requires_recent_main_commit(self):
        self.assertFalse(select_scope("schedule", "refs/heads/main", [],
                                      set(), False)["run_ci"])
        docs = select_scope("schedule", "refs/heads/main", ["docs/a.md"],
                            set(), True)
        self.assertTrue(docs["platforms"])
        self.assertTrue(docs["cross_verify"])
        self.assertFalse(docs["release_build"])
        code = select_scope("schedule", "refs/heads/main", ["crates/app/a.rs"],
                            set(), True)
        self.assertTrue(code["release_build"])

    def test_tag_builds_and_verifies(self):
        scope = select_scope("push", "refs/tags/v0.1.0", [], set(), False)
        self.assertEqual(scope, dict(run_ci=True, platforms=True,
                                     cross_verify=True, release_build=True))

    def test_manual_release_dry_run_builds_and_verifies_without_a_tag(self):
        scope = select_scope("workflow_dispatch", "refs/heads/release-test", [],
                             set(), False, release_dry_run=True)
        self.assertEqual(scope, dict(run_ci=True, platforms=True,
                                     cross_verify=True, release_build=True))
        self.assertFalse(select_scope("workflow_dispatch", "refs/heads/release-test",
                                      [], set(), False)["release_build"])

    def test_dry_run_rejects_non_branch_and_non_manual_events(self):
        for event, ref in (("push", "refs/heads/main"),
                           ("workflow_dispatch", "refs/tags/v0.1.0")):
            with self.assertRaises(ValueError):
                select_scope(event, ref, [], set(), False,
                             release_dry_run=True)


if __name__ == "__main__":
    unittest.main()
