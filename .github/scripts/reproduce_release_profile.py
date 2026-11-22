"""Compare the unsigned release CLI and native mapping manifests across build profiles."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


PLATFORMS = (
    "linux-x86_64", "linux-arm64", "macos-arm64", "macos-x86_64", "windows-x86_64",
)
PROFILES = ("default", "thin")


def output(command):
    return subprocess.check_output(command, text=True).strip()


def mapping_identities(build):
    identities = {}
    for manifest in sorted(build.glob("*/out/native-mapping-manifest.bin")):
        crate = manifest.parents[1].name.rsplit("-", 1)[0]
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        if identities.setdefault(crate, digest) != digest:
            raise ValueError(f"Conflicting native mapping manifests for {crate}")
    if not identities:
        raise ValueError("No native mapping manifests were built")
    return identities


def build_once(checkout, profile, target):
    env = dict(os.environ)
    env.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_RELEASE_STRIP="symbols")
    env.pop("CARGO_PROFILE_RELEASE_LTO", None)
    env.pop("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", None)
    env.pop("CARGO_BUILD_TARGET", None)
    if profile == "thin":
        env.update(CARGO_PROFILE_RELEASE_LTO="thin", CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1")
    if target:
        env["CARGO_BUILD_TARGET"] = target
    env["CARGO_TARGET_DIR"] = str(checkout / "out")

    start = time.monotonic()
    subprocess.run(["cargo", "build", "--release", "-p", "irmind", "--locked"],
                   cwd=checkout, env=env, check=True)
    seconds = round(time.monotonic() - start, 3)
    release = checkout / "out" / target / "release"
    binary = release / ("irmind.exe" if os.name == "nt" else "irmind")
    version = output([binary, "--version"])
    if not version.startswith("irmind "):
        raise ValueError("Unexpected version from the release executable")
    contents = binary.read_bytes()
    prefixes = (str(checkout), checkout.as_posix())
    return {
        "seconds": seconds,
        "bytes": len(contents),
        "sha256": hashlib.sha256(contents).hexdigest(),
        "version": version,
        "has_checkout_path": any(value.encode(encoding) in contents
                                 for value in prefixes for encoding in ("utf-8", "utf-16le")),
        "mappings": mapping_identities(release / "build"),
    }


def record(platform, profile, target):
    commit = output(["git", "rev-parse", "HEAD"])
    command = ["git", "-c", "core.longpaths=true", "worktree"]
    with tempfile.TemporaryDirectory(prefix="rp-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        results = []
        for name in ("a", "longer-second-source"):
            checkout = Path(temp) / name
            subprocess.run([*command, "add", "--detach", checkout, commit], check=True)
            try:
                results.append(build_once(checkout, profile, target))
            finally:
                subprocess.run([*command, "remove", "--force", checkout], check=True)
    receipt = {
        "commit": commit,
        "toolchain": output(["rustc", "-vV"]),
        "builds": results,
    }
    Path(f"release-repro-{platform}-{profile}.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def compare(directory):
    commit = output(["git", "rev-parse", "HEAD"])
    lines = [
        "| Target | Reproducible default | Reproducible ThinLTO | Equal mapping identities | Default / ThinLTO bytes | Default / ThinLTO mean s |",
        "| --- | --- | --- | --- | ---: | ---: |",
    ]
    for platform in PLATFORMS:
        baseline, thin = [
            json.loads((directory / f"release-repro-{platform}-{profile}.json").read_text(encoding="utf-8"))
            for profile in PROFILES
        ]
        if not (baseline["commit"] == thin["commit"] == commit
                and baseline["toolchain"] == thin["toolchain"]):
            raise ValueError(f"Build inputs differ for {platform}")
        default_a, default_b = baseline["builds"]
        thin_a, thin_b = thin["builds"]
        all_builds = (default_a, default_b, thin_a, thin_b)
        same_mappings = all(build["mappings"] == default_a["mappings"] for build in all_builds)
        if not all(build["version"] == default_a["version"] for build in all_builds):
            raise ValueError(f"Unexpected release executable version for {platform}")
        default_repro = default_a["sha256"] == default_b["sha256"]
        thin_repro = thin_a["sha256"] == thin_b["sha256"]
        default_time = (default_a["seconds"] + default_b["seconds"]) / 2
        thin_time = (thin_a["seconds"] + thin_b["seconds"]) / 2
        lines.append(f"| {platform} | {default_repro} | {thin_repro} | "
                     f"{same_mappings} ({len(default_a['mappings'])}) | "
                     f"{default_a['bytes']:,} / {thin_a['bytes']:,} | {default_time:.1f} / {thin_time:.1f} |")
    report = "\n".join(lines) + "\n"
    print(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=PLATFORMS)
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--target", default="")
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    if args.compare:
        compare(args.compare)
    elif args.platform and args.profile:
        record(args.platform, args.profile, args.target)
    else:
        parser.error("provide --compare or a platform and profile")


if __name__ == "__main__":
    main()
