"""Inspect workspace, Cargo registry and target paths across native macOS builds."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from diagnose_native_release import inspect
from reproduce_release_profile import mapping_identities, output


def paths_in(data, paths):
    return {name: any(str(prefix).encode() in data for prefix in {path, path.resolve()})
            for name, path in paths.items()}


def snapshot(file, paths):
    result = inspect(file)
    result["literal_paths"] = paths_in(file.read_bytes(), paths)
    symbols = subprocess.check_output(["/usr/bin/nm", "-pa", file])
    oso = [line for line in symbols.splitlines() if re.search(rb"\bOSO\b", line)]
    result["oso_count"] = len(oso)
    result["oso_paths"] = paths_in(b"\n".join(oso), paths)
    debug_map = subprocess.run(["xcrun", "dsymutil", "--dump-debug-map", file], capture_output=True)
    result["debug_map_status"] = debug_map.returncode
    result["debug_map_paths"] = paths_in(debug_map.stdout, paths)
    return result


def probe(target, mode):
    repo = Path.cwd()
    commit = output(["git", "rev-parse", "HEAD"])
    builds = []
    with tempfile.TemporaryDirectory(prefix="mac-uuid-", dir=os.environ["RUNNER_TEMP"]) as base:
        for name in ("a", "longer-checkout-b"):
            root = Path(base).resolve() / name
            root.mkdir()
            paths = {key: root / key for key in ("workspace", "cargo_home", "target")}
            if mode == "fixed":
                paths["cargo_home"] = Path(base).resolve() / "shared-cargo-home"
                paths["target"] = Path(base).resolve() / "shared-target"
            subprocess.run(["git", "worktree", "add", "--detach", paths["workspace"], commit], check=True, cwd=repo)
            try:
                flags = []
                for key in (paths if mode != "workspace" else ("workspace",)):
                    for prefix in sorted({paths[key], paths[key].resolve()}):
                        flags.append(f"--remap-path-prefix={prefix}=/canonical/{key}")
                env = os.environ | {
                    "CARGO_HOME": str(paths["cargo_home"]),
                    "CARGO_TARGET_DIR": str(paths["target"]),
                    "CARGO_BUILD_TARGET": target,
                    "CARGO_PROFILE_RELEASE_STRIP": "none",
                    "CARGO_INCREMENTAL": "0",
                    "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
                }
                subprocess.run(["cargo", "build", "--release", "--locked", "-p", "irmind"],
                               cwd=paths["workspace"], env=env, check=True)
                release = paths["target"] / target / "release"
                file = release / "irmind"
                before = snapshot(file, paths)
                stripped = root / "stripped"
                shutil.copy2(file, stripped)
                subprocess.run(["/usr/bin/strip", "-S", "-x", stripped], check=True)
                after = snapshot(stripped, paths)
                builds.append({"before_strip": before, "after_strip": after,
                               "mappings": mapping_identities(release / "build")})
            finally:
                subprocess.run(["git", "worktree", "remove", "--force", paths["workspace"]], check=True, cwd=repo)
                if mode == "fixed" and paths["target"].exists():
                    shutil.rmtree(paths["target"])
                shutil.rmtree(root)
    left, right = builds
    summary = {
        "matches": {kind: {field: left[kind][field] == right[kind][field]
                           for field in ("sha256", "all_metadata_masked_sha256", "sections")}
                    for kind in ("before_strip", "after_strip")},
        "uuids": [[build[kind]["metadata"]["macho_uuid"] for kind in ("before_strip", "after_strip")]
                  for build in builds],
        "equal_mappings": left["mappings"] == right["mappings"],
    }
    print(json.dumps(summary, indent=2))
    Path(f"macos-uuid-{target}-{mode}.json").write_text(
        json.dumps({"commit": commit, "builds": builds, "summary": summary}, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("mode", choices=("workspace", "all", "fixed"))
    args = parser.parse_args()
    probe(args.target, args.mode)
