"""Exercise the worker-sweep shell harness without building or benchmarking Rust."""
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "benchmark_workers.sh"


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("git"), "Linux shell harness")
class WorkerHarnessTest(unittest.TestCase):
    def test_reference_checkout_and_executable_have_distinct_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / "commands"
            commands.mkdir()
            cargo = commands / "cargo"
            cargo.write_text(
                f"#!{sys.executable}\n"
                "import json,os,pathlib,sys\n"
                "assert '--release' in sys.argv and '--locked' in sys.argv\n"
                "target=pathlib.Path(os.environ['CARGO_TARGET_DIR'])\n"
                "target.mkdir(parents=True,exist_ok=True)\n"
                "binary=target/'synthetic-test'\n"
                "binary.write_text('#!/bin/sh\\nprintf SYNTHETIC_HARNESS_EXECUTION\\n')\n"
                "binary.chmod(0o700)\n"
                "print(json.dumps({'reason':'compiler-artifact','target':{'name':'irmind_infra'},'executable':str(binary)}))\n"
            )
            cargo.chmod(0o700)
            run = lambda *args: subprocess.run(args, cwd=root, check=True, capture_output=True, text=True)
            run("git", "init", "--initial-branch=main")
            (root / "fixture.txt").write_text("synthetic harness only\n")
            run("git", "add", "fixture.txt")
            run("git", "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid",
                "commit", "-m", "Synthetic harness fixture")
            revision = run("git", "rev-parse", "HEAD").stdout.strip()
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                       BASE_REF=revision, WORKER_WORKLOAD="cloud-files")
            env.pop("CARGO_TARGET_DIR", None)
            env.pop("OS", None)
            # Stub only the external RSS sampler: this is not a performance run.
            timer = commands / "time"
            timer.write_text('#!/bin/sh\nshift\nshift\nexec "$@"\n')
            timer.chmod(0o700)
            script = root / "worker-harness.sh"
            script.write_text(SCRIPT.read_text().replace("/usr/bin/time", shlex.quote(str(timer))))
            result = subprocess.run(["bash", str(script)], cwd=root, env=env, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertGreaterEqual(result.stdout.count("SYNTHETIC_HARNESS_EXECUTION"), 12)
            self.assertFalse(list(root.glob("w.*")))
            worktrees = run("git", "worktree", "list", "--porcelain").stdout
            self.assertEqual(worktrees.count("worktree "), 1)
            self.assertTrue(list(root.glob("worker-sweep-reference-*.txt")))
            self.assertTrue(list(root.glob("worker-sweep-candidate-*.txt")))


if __name__ == "__main__":
    unittest.main()
