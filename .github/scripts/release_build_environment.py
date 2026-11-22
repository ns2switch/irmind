"""Record native build tools and assemble the five signed release reports."""

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess

from build_release_binaries import PLATFORMS

FILENAME = "BUILD-ENVIRONMENT.json"
NATIVE_FIELDS = {
    "linux": ("os", "compiler", "linker"),
    "darwin": ("os", "xcode", "macos_sdk_version", "macos_sdk_build", "compiler", "linker"),
    "win32": ("os", "visual_studio", "msvc_toolset", "windows_sdk", "compiler", "linker"),
}


def version(*command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()


def native_versions(destination):
    system = PLATFORMS[destination][0]
    if system == "linux":
        linker = "mold" if destination == "linux-x86_64" else version("cc", "-print-prog-name=ld")
        return {
            "os": platform.release(),
            "compiler": version("cc", "--version").splitlines()[0],
            "linker": version(linker, "--version").splitlines()[0],
        }
    if system == "darwin":
        sdk = ("xcrun", "--sdk", "macosx")
        return {
            "os": version("sw_vers"),
            "xcode": version("xcodebuild", "-version"),
            "macos_sdk_version": version(*sdk, "--show-sdk-version"),
            "macos_sdk_build": version(*sdk, "--show-sdk-build-version"),
            "compiler": version(*sdk, "clang", "--version").splitlines()[0],
            "linker": version(*sdk, "ld", "-v").splitlines()[0],
        }
    return {
        "os": platform.version(),
        "visual_studio": os.environ["IRMIND_VISUAL_STUDIO_VERSION"],
        "msvc_toolset": os.environ["VCToolsVersion"],
        "windows_sdk": os.environ["WindowsSDKVersion"].rstrip("\\/"),
        "compiler": os.environ["IRMIND_CL_VERSION"],
        "linker": os.environ["IRMIND_LINK_VERSION"],
    }


def record(destination, runner, commit):
    return {
        "source_commit": commit,
        "destination": destination,
        "runner_label": runner,
        "image_os": os.environ["ImageOS"],
        "image_version": os.environ["ImageVersion"],
        "rustc": version("rustc", "-vV"),
        "cargo": version("cargo", "-vV"),
        "native": native_versions(destination),
    }


def validate(report, destination, commit):
    if report.get("source_commit") != commit or report.get("destination") != destination:
        raise ValueError(f"Build environment for {destination} has the wrong commit or target")
    fields = (report.get(key) for key in ("runner_label", "image_os", "image_version", "rustc", "cargo"))
    native = report.get("native", {})
    values = (*fields, *(native.get(key) for key in NATIVE_FIELDS[PLATFORMS[destination][0]]))
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError(f"Build environment for {destination} is missing required tool versions")


def assemble(artifacts, commit):
    targets = {}
    for destination in PLATFORMS:
        path = artifacts / destination / FILENAME
        report = json.loads(path.read_text(encoding="utf-8"))
        validate(report, destination, commit)
        targets[destination] = report
    return {"schema_version": 1, "source_commit": commit, "targets": targets}


def write_json(path, report):
    path.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    native = modes.add_parser("record")
    native.add_argument("destination", choices=PLATFORMS)
    native.add_argument("runner")
    native.add_argument("output", type=Path)
    aggregate = modes.add_parser("assemble")
    aggregate.add_argument("artifacts", type=Path)
    aggregate.add_argument("output", type=Path)
    args = parser.parse_args()
    commit = version("git", "rev-parse", "HEAD")
    if args.mode == "record":
        report = record(args.destination, args.runner, commit)
        validate(report, args.destination, commit)
    else:
        report = assemble(args.artifacts, commit)
    write_json(args.output, report)


if __name__ == "__main__":
    main()
