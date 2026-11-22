"""Build the released EVTX helper independently of the checkout path."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile


def build(checkout, commit):
    # Outside the helper workspace, Cargo includes the absolute path of the
    # containment crate in its build identity. Keep the source and target
    # paths fixed on each shipping runner and stage only the committed tree.
    root = (Path("C:/") if os.name == "nt" else Path("/tmp")).resolve()
    stage = root / "irmind-evtx-release-v1"
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

        target = stage / "target"
        env = os.environ | {
            "CARGO_TARGET_DIR": str(target),
            "CARGO_INCREMENTAL": "0",
            "CARGO_PROFILE_RELEASE_STRIP": "symbols",
        }
        if os.name == "nt":
            flags = env.get("CARGO_ENCODED_RUSTFLAGS")
            if flags is None:
                flags = "\x1f".join(env.get("RUSTFLAGS", "").split())
            env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(filter(None, (flags, "-C", "link-arg=/Brepro")))
        subprocess.run(["cargo", "build", "--manifest-path", "helpers/evtx/Cargo.toml",
                        "--release", "--locked", "--bin", "irmind-evtx"],
                       cwd=source, env=env, check=True)
        filename = "irmind-evtx.exe" if os.name == "nt" else "irmind-evtx"
        return (target / env.get("CARGO_BUILD_TARGET", "") / "release" / filename).read_bytes()
    finally:
        shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    repo = Path.cwd()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    expected = build(repo, commit)
    with tempfile.TemporaryDirectory(prefix="evtx-repro-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        alternate = Path(temporary) / "second-checkout"
        worktree = ["git", "-c", "core.longpaths=true", "worktree"]
        subprocess.run([*worktree, "add", "--detach", alternate, commit], check=True)
        try:
            reproduced = build(alternate, commit)
        finally:
            subprocess.run([*worktree, "remove", "--force", alternate], check=True)
    if expected != reproduced:
        raise SystemExit("EVTX release binary differed across two clean checkouts")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(expected)
    if os.name != "nt":
        args.output.chmod(0o755)
    print(f"EVTX release SHA-256 reproduced across two checkouts: {hashlib.sha256(expected).hexdigest()}")


if __name__ == "__main__":
    main()
