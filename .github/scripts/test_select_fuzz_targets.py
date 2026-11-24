"""Regressions for the daily and required pull-request fuzz plans."""

import unittest

from select_fuzz_targets import ROOT, daily_targets, pr_targets, targets


class FuzzScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.targets = targets(ROOT)

    def test_documentation_selects_no_fuzzer(self):
        self.assertEqual(daily_targets(ROOT, self.targets, ["docs/parsers.md"]), [])

    def test_decoder_or_shared_mapping_selects_users(self):
        fdr = ["crates/modules/parser-fdr/src/lib.rs"]
        self.assertEqual(daily_targets(ROOT, self.targets, fdr), ["fuzz:parser_fdr"])
        mapping = ["crates/modules/mapping-cloud-flow/src/lib.rs"]
        self.assertCountEqual(daily_targets(ROOT, self.targets, mapping), [
            "fuzz:parser_azure_flow", "fuzz:parser_gcp_flow", "fuzz:parser_vpc_flow",
        ])

    def test_evtx_inputs_and_global_inputs(self):
        path = "helpers/evtx/fuzz/seeds/security.evtx"
        self.assertEqual(daily_targets(ROOT, self.targets, [path]), ["helpers/evtx/fuzz:evtx_decode"])
        self.assertEqual(daily_targets(ROOT, self.targets, ["Cargo.lock"]), list(self.targets))

    def test_patched_dependencies_select_their_consumers(self):
        paths = ["vendor/parquet/src/lib.rs"]
        self.assertIn("fuzz:export", daily_targets(ROOT, self.targets, paths))

    def test_new_decoder_must_have_a_harness(self):
        path = "crates/modules/parser-fdr/Cargo.toml"
        self.assertEqual(pr_targets(ROOT, self.targets, [path]), ["fuzz:parser_fdr"])
        with self.assertRaisesRegex(ValueError, "needs an admitted AddressSanitizer"):
            pr_targets(ROOT, {}, [path])
        self.assertEqual(pr_targets(ROOT, self.targets, ["fuzz/fuzz_targets/parser_fdr.rs"]),
                         ["fuzz:parser_fdr"])

    def test_isolated_workspaces_do_not_confuse_target_names(self):
        self.assertEqual(self.targets["helpers/evtx/fuzz:evtx_protocol"],
                         "helpers/evtx/fuzz/fuzz_targets/evtx_protocol.rs")
        self.assertIn("fuzz:source_mapping", self.targets)


if __name__ == "__main__":
    unittest.main()
