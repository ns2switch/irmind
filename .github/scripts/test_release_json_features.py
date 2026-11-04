#!/usr/bin/env python3
"""Exercise the release gate without downloading or compiling dependencies."""

import subprocess
import unittest
from unittest.mock import patch

import check_release_json_features as gate


class ReleaseFeatureGate(unittest.TestCase):
    def test_current_normal_build_graph_is_clean(self):
        tree = 'serde_json v1.0.154\nserde_json feature "std"\n'
        self.assertFalse(gate.forbidden_feature(tree))

    def test_preserve_order_is_rejected_even_when_cargo_deduplicates_it(self):
        for suffix in ["", " (*)"]:
            tree = 'serde_json v1.0.154\nserde_json feature "preserve_order"' + suffix
            self.assertTrue(gate.forbidden_feature(tree))
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=tree)):
                with self.assertRaisesRegex(SystemExit, "Release blocked"):
                    gate.main()

    def test_build_command_excludes_development_edges_and_pins_the_target(self):
        with patch.dict(gate.os.environ, {"CARGO_BUILD_TARGET": "x86_64-pc-windows-msvc"}):
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="")) as run:
                gate.main()
        args = run.call_args.args[0]
        self.assertIn("--locked", args)
        self.assertEqual(args[args.index("-p") + 1], "irmind")
        self.assertEqual(args[args.index("-e") + 1], "normal,build,features")
        self.assertEqual(args[args.index("--target") + 1], "x86_64-pc-windows-msvc")


if __name__ == "__main__":
    unittest.main()
