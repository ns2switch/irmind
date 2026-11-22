"""Require a complete, commit-bound build environment before release signing."""

from pathlib import Path
import tempfile
import unittest

from release_build_environment import FILENAME, NATIVE_FIELDS, PLATFORMS, assemble, write_json


class BuildEnvironmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name)
        self.commit = "f" * 40
        self.reports = {}
        for destination, (system, _, _) in PLATFORMS.items():
            self.reports[destination] = {
                "destination": destination,
                "source_commit": self.commit,
                "runner_label": "pinned-runner",
                "image_os": "runner-image",
                "image_version": "123.1",
                "rustc": "1.95.0",
                "cargo": "1.95.0",
                "native": dict.fromkeys(NATIVE_FIELDS[system], "1.0"),
            }
            (self.artifacts / destination).mkdir()
            self.write_report(destination)

    def write_report(self, destination):
        write_json(self.artifacts / destination / FILENAME, self.reports[destination])

    def test_all_five_platform_reports_are_included(self):
        report = assemble(self.artifacts, self.commit)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["source_commit"], self.commit)
        self.assertEqual(report["targets"], self.reports)

    def test_missing_target_blocks_assembly(self):
        (self.artifacts / "linux-aarch64" / FILENAME).unlink()
        with self.assertRaises(FileNotFoundError):
            assemble(self.artifacts, self.commit)

    def test_report_for_another_commit_or_target_is_rejected(self):
        for key, value in (("source_commit", "0" * 40), ("destination", "macos-aarch64")):
            with self.subTest(key=key):
                report = self.reports["macos-x86_64"]
                original, report[key] = report[key], value
                self.write_report("macos-x86_64")
                with self.assertRaisesRegex(ValueError, "wrong commit or target"):
                    assemble(self.artifacts, self.commit)
                report[key] = original
                self.write_report("macos-x86_64")

    def test_missing_native_version_blocks_assembly(self):
        self.reports["windows-x86_64"]["native"]["linker"] = ""
        self.write_report("windows-x86_64")
        with self.assertRaisesRegex(ValueError, "missing required tool versions"):
            assemble(self.artifacts, self.commit)


if __name__ == "__main__":
    unittest.main()
