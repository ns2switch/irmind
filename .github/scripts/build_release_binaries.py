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
from time import monotonic

from reproduce_release_profile import mapping_identities
from native_mapping.build_inputs import prepare as prepare_mapping_inputs, write_json
from native_mapping.observe import canonical_json as canonical_observation, cargo_metadata, normalize


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


def observed_main(checkout, commit, source, target_dir, env, destination, name):
    _, _, target = PLATFORMS[destination]
    started = monotonic()
    with tempfile.TemporaryDirectory(prefix="ir-map-input-") as temporary:
        spool = Path(temporary)
        compiler = spool / ("observe.exe" if os.name == "nt" else "observe")
        subprocess.run([
            "rustc", "--edition=2024",
            checkout / ".github/scripts/native_mapping/rustc_observer.rs", "-o", compiler,
        ], cwd=source, env=env, check=True)
        records = spool / "records"
        records.mkdir()
        env = env | {
            "RUSTC_WRAPPER": str(compiler),
            "IRMIND_NATIVE_MAPPING_OBSERVATIONS": str(records),
        }
        binary = cargo_build(source, target_dir, env, target, name, ["-p", "irmind"])
        compiled = monotonic()
        packages = cargo_metadata(source, env | {"CARGO_TARGET_DIR": str(target_dir)})
        observation = normalize(records, packages, checkout, commit, source, destination, env)
    print(f"{destination}: observed release build {compiled - started:.3f} s; "
          f"closure collection {monotonic() - compiled:.3f} s")
    directory = env.get("IRMIND_NATIVE_MAPPING_MANIFEST_DIR")
    if directory:
        expected = {
            file.stem: hashlib.sha256(file.read_bytes()).hexdigest()
            for file in Path(directory).glob("irmind-mod-mapping-*.bin")
        }
        actual = {
            name: value for name, value in mapping_identities(binary.parent / "build").items()
            if name.startswith("irmind-mod-mapping-")
        }
        if actual != expected:
            raise SystemExit(f"Compiled native mapping identities differ on {destination}")
        print(f"{destination}: checked all {len(actual)} embedded native mapping commitments")
    return binary, observation


def build_binaries(checkout, commit, destination, output, check_features, compare_windows,
                   observe_only=False, expected_observation=None, manifest_directory=None):
    system, _, target = PLATFORMS[destination]
    env = build_env(destination)
    if check_features:
        subprocess.run([sys.executable, ".github/scripts/check_release_json_features.py"],
                       cwd=checkout, env=env, check=True)
    main_name = "irmind.exe" if system == "win32" else "irmind"
    helper_name = "irmind-evtx.exe" if system == "win32" else "irmind-evtx"
    env.pop("RUSTC_WRAPPER", None)
    env.pop("RUSTC_WORKSPACE_WRAPPER", None)
    env.pop("IRMIND_NATIVE_MAPPING_REQUIRE_V2", None)
    env.pop("IRMIND_NATIVE_MAPPING_MANIFEST_DIR", None)
    main_env = dict(env)
    if manifest_directory is not None:
        main_env.update(IRMIND_NATIVE_MAPPING_REQUIRE_V2="1",
                        IRMIND_NATIVE_MAPPING_MANIFEST_DIR=str(manifest_directory))

    def build_main(source, build_dir, settings):
        if observe_only or expected_observation is not None:
            binary, observation = observed_main(
                checkout, commit, source, build_dir, settings, destination, main_name,
            )
            if observe_only:
                write_json(output / "observation.json", observation)
            elif canonical_observation(observation) != canonical_observation(expected_observation):
                raise SystemExit(f"Observed native mapping inputs differ on {destination}")
            return binary
        return cargo_build(source, build_dir, settings, target, main_name, ["-p", "irmind"])

    if system == "darwin":
        with staged_tree(checkout, commit, "irmind-macos-release-v1") as source:
            cargo_home = source.parent / "cargo-home"
            target_dir = source.parent / "target"
            remaps = {
                source: "/canonical/workspace",
                cargo_home: "/canonical/cargo_home",
                target_dir: "/canonical/target",
            }
            main_env.update(
                CARGO_HOME=str(cargo_home),
                CARGO_ENCODED_RUSTFLAGS="\x1f".join(
                    f"--remap-path-prefix={path}={alias}" for path, alias in remaps.items()
                ),
            )
            binary = build_main(source, target_dir, main_env)
            if not observe_only:
                shutil.copy2(binary, output / main_name)
    else:
        release_env = main_env | {
            "CARGO_PROFILE_RELEASE_LTO": "thin",
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        }
        binary = build_main(checkout, checkout / "target", release_env)
        if not observe_only:
            shutil.copy2(binary, output / main_name)
        if compare_windows:
            baseline = build_main(checkout, checkout / "baseline-target", main_env)
            optimized_mappings = mapping_identities(binary.parent / "build")
            if optimized_mappings != mapping_identities(baseline.parent / "build"):
                raise SystemExit("Windows ThinLTO changed native mapping identities")
            print(f"Windows ThinLTO preserves all {len(optimized_mappings)} native mapping identities")

    if not observe_only:
        with staged_tree(checkout, commit, "irmind-evtx-release-v1") as source:
            binary = cargo_build(source, source.parent / "target", env, target, helper_name, [
                "--manifest-path", "helpers/evtx/Cargo.toml", "--bin", "irmind-evtx",
            ])
            shutil.copy2(binary, output / helper_name)


def checksums(directory):
    with_digests = {}
    for path in sorted(directory.iterdir()):
        digest = hashlib.sha256()
        with path.open("rb") as binary:
            while block := binary.read(1024 * 1024):
                digest.update(block)
        with_digests[path.name] = digest.hexdigest()
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
    parser.add_argument("--observe-only", action="store_true",
                        help="record production mapping inputs for this native target")
    parser.add_argument("--mapping-inputs", type=Path,
                        help="verified shared observations for the five release targets")
    args = parser.parse_args()
    if args.observe_only and (args.verify or args.mapping_inputs or args.compare_windows_mappings):
        parser.error("observation is a separate preflight build")
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
    env_checkout = "false"
    worktree = ["git", "-c", "core.longpaths=true", "-c", f"core.autocrlf={env_checkout}", "worktree"]
    with tempfile.TemporaryDirectory(prefix="ir-rel-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        directory = Path(temporary).resolve()
        manifest_directory, observation = None, None
        if args.mapping_inputs is not None:
            manifest_directory = directory / "native-mapping-manifests"
            manifest_directory.mkdir()
            observation = prepare_mapping_inputs(args.mapping_inputs, manifest_directory)[args.destination]
        first = directory / "first"
        builds = ("a", "different-b") if args.verify else ("a",)
        for index, name in enumerate(builds):
            checkout = directory / name
            binaries = first if index == 0 else directory / "second"
            binaries.mkdir()
            subprocess.run([*worktree, "add", "--detach", checkout, commit], cwd=repo, check=True)
            try:
                build_binaries(checkout, commit, args.destination, binaries, index == 0,
                               index == 0 and args.compare_windows_mappings,
                               args.observe_only, observation, manifest_directory)
            finally:
                subprocess.run([*worktree, "remove", "--force", checkout], cwd=repo, check=True)
            if index != 0:
                verify_rebuild(args.destination, first, binaries)
        shutil.copytree(first, output)


if __name__ == "__main__":
    main()
