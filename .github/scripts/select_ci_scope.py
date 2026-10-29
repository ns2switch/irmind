"""Choose CI jobs from the event, changed paths, and the latest main commit."""

import json
import os
import subprocess
import time
import tomllib
from pathlib import Path


def platform_path(path: str) -> bool:
    parts = path.split("/")
    return (
        path.startswith("crates/fs/")
        or path.startswith("crates/modules/storage-object/")
        or (len(parts) >= 4 and parts[:2] == ["crates", "modules"]
            and parts[2].startswith("keystore-"))
        or (path.startswith("crates/infra/")
            and parts[-1].startswith("windows_security"))
        or path.startswith("crates/tui/")
        or path.startswith(".github/workflows/")
    )


def release_source(path: str) -> bool:
    return path.startswith("crates/") or path in {
        "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
    }


def select_scope(event: str, ref: str, changed: list[str], labels: set[str],
                 recent_commit: bool) -> dict[str, bool]:
    tag = event == "push" and ref.startswith("refs/tags/v")
    nightly = event == "schedule" and recent_commit
    return {
        "run_ci": event != "schedule" or recent_commit,
        "platforms": tag or nightly or event == "workflow_dispatch" or (
            event == "pull_request" and (
                "full-ci" in labels or any(map(platform_path, changed))
            )
        ),
        "cross_verify": tag or nightly,
        "release_build": tag or (nightly and any(map(release_source, changed))),
    }


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def changed_paths(event: str, payload: dict) -> list[str]:
    if event == "pull_request":
        base = payload["pull_request"]["base"]["sha"]
        head = payload["pull_request"]["head"]["sha"]
        raw = subprocess.check_output(
            ["git", "diff", "--name-only", "-z", f"{base}...{head}"]
        )
        return [path.decode("utf-8") for path in raw.split(b"\0") if path]
    if event == "schedule":
        return command("git", "log", "--since=24 hours ago", "--name-only",
                       "--format=").splitlines()
    return []


def main() -> None:
    event = os.environ["GITHUB_EVENT_NAME"]
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    changed = changed_paths(event, payload)
    labels = {
        label["name"] for label in payload.get("pull_request", {}).get("labels", [])
    }
    last_main_commit = int(command("git", "log", "-1", "--format=%ct"))
    recent_commit = 0 <= time.time() - last_main_commit < 86_400
    scope = select_scope(event, os.environ["GITHUB_REF"], changed, labels,
                         recent_commit)
    lock = tomllib.loads(Path("Cargo.lock").read_text())
    version = next(
        package["version"] for package in lock["package"]
        if package["name"] == "libduckdb-sys"
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii") as output:
        for key, enabled in scope.items():
            output.write(f"{key}={str(enabled).lower()}\n")
        output.write(f"duckdb_version={version}\n")
    if event == "schedule" and not scope["run_ci"]:
        print("Skipping nightly CI: main has no commit in the last 24 hours.")


if __name__ == "__main__":
    main()
