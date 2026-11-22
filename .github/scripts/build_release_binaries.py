"""Build the two release executables from clean checkouts of HEAD."""

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

from reproduce_release_profile import mapping_identities


PLATFORMS = {
    "linux-x86_64": ("linux", "x86_64", ""),
    "linux-aarch64": ("linux", "aarch64", ""),
    "macos-aarch64": ("darwin", "arm64", "aarch64-apple-darwin"),
    "macos-x86_64": ("darwin", "x86_64", "x86_64-apple-darwin"),
    "windows-x86_64": ("win32", "AMD64", "x86_64-pc-windows-msvc"),
}


@contextmanager
def staged_tree(checkout, commit, name):
    # Cargo includes the absolute path of the helper's containment crate in
    # its build identity. macOS ld also derives LC_UUID from absolute inputs.
    root = (Path("C:/") if os.name == "nt" else Path("/tmp")).resolve()
    stage = root / name
    stage.mkdir(mode=0o700)
    try:
        archive = stage / "source.tar"
        subprocess.run(["git", "-C", checkout, "archive", "--format=tar", "-o", archive, commit],
                       check=True)
        source = stage / "source"
        source.mkdir()
        with tarfile.open(archive) as tar:
            for entry in tar:
                relative = PurePosixPath(entry.name)
                if (relative.is_absolute() or ".." in relative.parts
                        or "\\" in entry.name or ":" in entry.name):
                    raise ValueError("Invalid path in the committed release tree")
                destination = source.joinpath(*relative.parts)
                if entry.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(entry) as input_file, destination.open("xb") as output:
                        shutil.copyfileobj(input_file, output)
                    if os.name != "nt":
                        destination.chmod(entry.mode & 0o777)
                else:
                    raise ValueError("The release tree must contain only files and directories")
        archive.unlink()
        yield source
    finally:
        shutil.rmtree(stage)


def build_env(destination):
    system, _, target = PLATFORMS[destination]
    env = os.environ | {
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_RELEASE_STRIP": "symbols",
    }
    for name in ("CARGO_BUILD_TARGET", "CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS",
                 "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS"):
        env.pop(name, None)
    if target:
        env["CARGO_BUILD_TARGET"] = target
    if destination == "linux-x86_64":
        env["RUSTFLAGS"] = "-C link-arg=-fuse-ld=mold"
    if system == "win32":
        env["RUSTFLAGS"] = "-C link-arg=/Brepro"
    return env


def cargo_build(source, target_dir, env, platform_component, name, flags):
    subprocess.run(["cargo", "build", "--release", "--locked", *flags],
                   cwd=source, env=env | {"CARGO_TARGET_DIR": str(target_dir)}, check=True)
    return target_dir / platform_component / "release" / name


def build_binaries(checkout, commit, destination, output, check_features, compare_windows):
    system, _, target = PLATFORMS[destination]
    env = build_env(destination)
    if check_features:
        subprocess.run([sys.executable, ".github/scripts/check_release_json_features.py"],
                       cwd=checkout, env=env, check=True)
    main_name = "irmind.exe" if system == "win32" else "irmind"
    helper_name = "irmind-evtx.exe" if system == "win32" else "irmind-evtx"
    if system == "darwin":
        with staged_tree(checkout, commit, "irmind-macos-release-v1") as source:
            cargo_home = source.parent / "cargo-home"
            target_dir = source.parent / "target"
            remaps = {
                source: "/canonical/workspace",
                cargo_home: "/canonical/cargo_home",
                target_dir: "/canonical/target",
            }
            main_env = env | {
                "CARGO_HOME": str(cargo_home),
                "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(
                    f"--remap-path-prefix={path}={alias}" for path, alias in remaps.items()
                ),
            }
            binary = cargo_build(source, target_dir, main_env, target, main_name, ["-p", "irmind"])
            shutil.copy2(binary, output / main_name)
    else:
        main_env = env | {
            "CARGO_PROFILE_RELEASE_LTO": "thin",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        }
        binary = cargo_build(checkout, checkout / "target", main_env, target, main_name, ["-p", "irmind"])
        shutil.copy2(binary, output / main_name)
        if compare_windows:
            baseline = cargo_build(checkout, checkout / "baseline-target", env, target,
                                   main_name, ["-p", "irmind"])
            optimized_mappings = mapping_identities(binary.parent / "build")
            if optimized_mappings != mapping_identities(baseline.parent / "build"):
                raise SystemExit("Windows ThinLTO changed native mapping identities")
            print(f"Windows ThinLTO preserves all {len(optimized_mappings)} native mapping identities")

    with staged_tree(checkout, commit, "irmind-evtx-release-v1") as source:
        binary = cargo_build(source, source.parent / "target", env, target, helper_name, [
            "--manifest-path", "helpers/evtx/Cargo.toml", "--bin", "irmind-evtx",
        ])
        shutil.copy2(binary, output / helper_name)


def checksums(directory):
    with_digests = {}
    for path in sorted(directory.iterdir()):
        with path.open("rb") as binary:
            with_digests[path.name] = hashlib.file_digest(binary, "sha256").hexdigest()
    return with_digests


def verify_rebuild(destination, first, second):
    expected, reproduced = checksums(first), checksums(second)
    for filename, digest in expected.items():
        if reproduced.get(filename) != digest:
            raise SystemExit(f"{destination} {filename} differs: "
                             f"{digest} vs {reproduced.get(filename)}")
        print(f"{destination} {filename}: reproduced SHA-256 {digest}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", choices=PLATFORMS)
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify", action="store_true", help="require matching SHA-256 from two clean builds")
    parser.add_argument("--compare-windows-mappings", action="store_true")
    args = parser.parse_args()
    system, architecture, _ = PLATFORMS[args.destination]
    if sys.platform != system or platform.machine().lower() != architecture.lower():
        parser.error(f"{args.destination} requires a native {system} {architecture} host")
    if args.compare_windows_mappings and system != "win32":
        parser.error("--compare-windows-mappings is only valid on Windows")
    repo = Path.cwd().resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    output = args.output.resolve()
    if output.exists():
        parser.error(f"output already exists: {args.output}")
    env_checkout = "true" if system == "win32" else "false"
    worktree = ["git", "-c", "core.longpaths=true", "-c", f"core.autocrlf={env_checkout}", "worktree"]
    with tempfile.TemporaryDirectory(prefix="ir-rel-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        directory = Path(temporary).resolve()
        first = directory / "first"
        builds = ("a", "different-b") if args.verify else ("a",)
        for index, name in enumerate(builds):
            checkout = directory / name
            binaries = first if index == 0 else directory / "second"
            binaries.mkdir()
            subprocess.run([*worktree, "add", "--detach", checkout, commit], cwd=repo, check=True)
            try:
                build_binaries(checkout, commit, args.destination, binaries, index == 0,
                               index == 0 and args.compare_windows_mappings)
            finally:
                subprocess.run([*worktree, "remove", "--force", checkout], cwd=repo, check=True)
            if index != 0:
                verify_rebuild(args.destination, first, binaries)
        shutil.copytree(first, output)


if __name__ == "__main__":
    main()
