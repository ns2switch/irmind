"""Regressions for event selection and the protected CI checks."""

import unittest
from unittest.mock import patch

from select_ci_scope import (
    docs_binary_run, docs_path, has_full_release_build, nightly_release_changed, platform_path, select_scope,
)


class ScopeTests(unittest.TestCase):
    def pr(self, changed, labels=(), **kwargs):
        return select_scope("pull_request", "refs/pull/7/merge", changed, set(labels), True, **kwargs)

    def test_platform_paths(self):
        for path in (
            "crates/fs/src/lib.rs", "crates/modules/keystore-file/src/lib.rs",
            "crates/bin/src/keystore.rs", "crates/infra/src/windows_security.rs",
            "crates/modules/storage-object/src/lib.rs", "crates/modules/query-athena/src/lib.rs",
            "crates/app/src/source_queries/page.rs", "crates/infra/src/parquet_store/query_capture.rs",
            "crates/tui/src/case/runtime/input.rs", "crates/tui/src/home/runtime.rs",
            "crates/tui/src/case/picker.rs", "crates/tui/src/case/commands/export.rs",
            "crates/process-containment/src/lib.rs", "helpers/evtx/src/lib.rs",
            ".github/workflows/ci.yml",
        ):
            self.assertTrue(platform_path(path), path)
        for path in (
            "crates/app/src/lib.rs", "docs/platforms.md", "crates/tui/src/case/render/cards.rs",
            "crates/tui/src/home/render/help.rs",
        ):
            self.assertFalse(platform_path(path), path)

    def test_ordinary_rust_and_tui_prs_run_linux(self):
        for path in ("crates/app/src/lib.rs", "crates/tui/src/case/render/cards.rs"):
            self.assertEqual(self.pr([path]), dict(
                run_ci=True, docs_only=False, platforms=False, cross_verify=False, release_build=False,
            ))

    def test_irrelevant_label_never_runs_even_on_native_or_full_ci_pr(self):
        for event in ("labeled", "unlabeled"):
            for path in ("crates/fs/src/lib.rs", "README.md"):
                scope = self.pr([path], ["full-ci"], action=event, label="enhancement")
                self.assertFalse(any(scope.values()))

    def test_adding_and_removing_full_ci_reevaluates_the_pr(self):
        path = "crates/tui/src/case/render/cards.rs"
        self.assertTrue(self.pr([path], ["full-ci"], action="labeled", label="full-ci")["platforms"])
        removed = self.pr([path], action="unlabeled", label="full-ci")
        self.assertTrue(removed["run_ci"])
        self.assertFalse(removed["platforms"])
        self.assertFalse(self.pr([path], ["full-ci"], draft=True)["platforms"])
        self.assertTrue(self.pr([path], ["full-ci"], action="ready_for_review")["platforms"])
        self.assertTrue(self.pr(["crates/fs/src/lib.rs"], draft=True)["platforms"])

    def test_docs_only_runs_required_documentation_check(self):
        doc_only = self.pr(["README.es.md", "CHANGELOG.md", "docs/demo/screen.png"], ["full-ci"])
        self.assertEqual(doc_only, dict(
            run_ci=True, docs_only=True, platforms=False, cross_verify=False, release_build=False,
        ))
        self.assertFalse(self.pr([])["docs_only"])

    def test_documentation_mixed_with_test_or_code_inputs_runs_code_checks(self):
        for path in (
            "docs/examples/parsers/access-csv.toml", "docs/development/source-query-format-vectors/a.json",
            "docs/development/vectors/native-mapping-manifest-v2.json", "docs/demo/generate.py",
            "skills/core/windows-triage/SKILL.md", "crates/app/README.md",
            "crates/tui/src/case/render/panels.rs", ".github/workflows/ci.yml",
        ):
            self.assertFalse(docs_path(path), path)
            self.assertFalse(self.pr(["README.md", path])["docs_only"], path)

    def test_main_push_is_linux_only(self):
        scope = select_scope("push", "refs/heads/main", [], set(), True)
        self.assertTrue(scope["run_ci"])
        self.assertFalse(scope["platforms"])
        self.assertFalse(scope["release_build"])

    def test_nightly_keeps_native_tests_and_limits_release_builds(self):
        def nightly(recent, **kwargs):
            return select_scope("schedule", "refs/heads/main", [], set(), recent, **kwargs)
        self.assertFalse(nightly(False)["run_ci"])
        daily = nightly(True)
        self.assertTrue(daily["platforms"])
        self.assertTrue(daily["cross_verify"])
        self.assertFalse(daily["release_build"])
        self.assertTrue(nightly(False, weekly=True)["release_build"])
        self.assertTrue(nightly(False, release_changed=True)["release_build"])

    @patch("select_ci_scope.diff_names")
    @patch("select_ci_scope.run_data")
    @patch("select_ci_scope.main_runs")
    def test_release_anchor_uses_last_success_with_all_five_destinations(self, runs, jobs, changed):
        runs.return_value = [{"id": 2, "head_sha": "b" * 40}, {"id": 1, "head_sha": "a" * 40}]
        jobs.side_effect = [[], [
            {"name": f"release_binaries / verify_release_reproducibility ({target}, runner)", "conclusion": "success"}
            for target in ("linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64", "windows-x86_64")
        ]]
        changed.return_value = ["vendor/parquet/src/lib.rs"]
        self.assertTrue(nightly_release_changed(False))
        changed.assert_called_once_with(f"{'a' * 40}..HEAD")

    def test_retried_release_build_accepts_successes_from_both_attempts(self):
        jobs = [
            {"name": f"release_binaries / verify_release_reproducibility ({target}, runner)",
             "conclusion": "success", "run_attempt": 1}
            for target in ("linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64")
        ]
        windows = "release_binaries / verify_release_reproducibility (windows-x86_64, runner)"
        jobs.append({"name": windows, "conclusion": "failure", "run_attempt": 1})
        self.assertFalse(has_full_release_build(jobs))
        jobs.append({"name": windows, "conclusion": "success", "run_attempt": 2})
        self.assertTrue(has_full_release_build(jobs))

    @patch("select_ci_scope.diff_names")
    @patch("select_ci_scope.run_data")
    @patch("select_ci_scope.main_runs")
    def test_docs_binary_is_compatible_and_unexpired(self, runs, artifacts, changed):
        runs.return_value = [
            {"id": 3, "head_sha": "c" * 40}, {"id": 2, "head_sha": "b" * 40},
            {"id": 1, "head_sha": "a" * 40},
        ]
        changed.side_effect = [["crates/bin/src/main.rs"], [], ["README.md"]]
        artifacts.side_effect = [
            [{"name": "docs-cli", "expired": True}],
            [{"name": "docs-cli", "expired": False}],
        ]
        self.assertEqual(docs_binary_run(), 1)

    def test_tag_builds_and_verifies(self):
        scope = select_scope("push", "refs/tags/v0.1.0", [], set(), False)
        self.assertEqual(scope, dict(
            run_ci=True, docs_only=False, platforms=True, cross_verify=True, release_build=True,
        ))

    def test_manual_release_dry_run_builds_and_verifies_without_a_tag(self):
        scope = select_scope("workflow_dispatch", "refs/heads/release-test", [], set(), False,
                             release_dry_run=True)
        self.assertEqual(scope, dict(
            run_ci=True, docs_only=False, platforms=True, cross_verify=True, release_build=True,
        ))
        self.assertFalse(select_scope("workflow_dispatch", "refs/heads/release-test",
                                      [], set(), False)["release_build"])

    def test_dry_run_rejects_non_branch_and_non_manual_events(self):
        for event, ref in (("push", "refs/heads/main"),
                           ("workflow_dispatch", "refs/tags/v0.1.0")):
            with self.assertRaises(ValueError):
                select_scope(event, ref, [], set(), False, release_dry_run=True)


if __name__ == "__main__":
    unittest.main()
