"""Select required CI work without filtering workflow triggers by path."""

from datetime import datetime, timezone
import json
import os
import re
import subprocess
import time
from pathlib import Path

WEEKLY_RELEASE = "17 3 * * 0"
LABEL_EVENTS = {"labeled", "unlabeled"}
NATIVE_PREFIXES = (
    ".github/workflows/",
    ".github/scripts/build_release",
    ".github/scripts/native_mapping/",
    ".github/scripts/release_build_environment.py",
    "crates/fs/",
    "crates/keystore-transfer/",
    "crates/process-containment/",
    "crates/modules/parser-evtx/",
    "crates/modules/keystore-",
    "crates/modules/query-",
    "crates/modules/storage-object/",
    "crates/app/src/keystore",
    "crates/app/src/source_queries/",
    "crates/bin/src/keystore",
    "crates/bin/src/cli/source_query",
    "crates/bin/src/source_query",
    "crates/bin/src/startup/storage",
    "crates/bin/tests/demo_pty",
    "crates/bin/tests/first_run_pty",
    "crates/bin/tests/support/demo_session",
    "crates/bin/tests/support/terminal_screen",
    "crates/infra/src/parquet_store/original_read",
    "crates/infra/src/parquet_store/query_capture",
    "crates/infra/src/sqlite/source_query",
    "crates/infra/src/tests/object_storage",
    "docs/development/source-query-format-vectors/",
    "helpers/evtx/",
)
TUI_NATIVE = {
    "Cargo.toml", "src/lib.rs", "src/case.rs", "src/home.rs",
    "src/case/commands/export.rs", "src/case/commands/objects.rs",
    "src/case/commands/parsers.rs", "src/case/commands/source_queries.rs",
    "src/home/new_case.rs", "src/home/resume.rs", "src/workflow/ingest.rs",
    "src/setup/wizard.rs", "src/skills/download.rs", "src/skills/state/forms.rs",
    "src/case/time_prompt.rs", "src/status_bar/editor.rs",
}


def platform_path(path: str) -> bool:
    if path.startswith(NATIVE_PREFIXES) or path in {"install.sh", "install.ps1"}:
        return True
    if path.startswith("crates/infra/") and Path(path).name.startswith("windows_security"):
        return True
    if not path.startswith("crates/tui/"):
        return False
    relative = path.removeprefix("crates/tui/")
    return relative in TUI_NATIVE or (
        path.endswith(".rs") and bool(
            {"input", "runtime", "terminal", "keyboard", "keymap", "picker", "path", "paths"}
            & set(Path(relative).with_suffix("").parts)
        )
    )


def docs_path(path: str) -> bool:
    parts = Path(path).parts
    if path.startswith("docs/"):
        # The manuals also contain inputs to parser and signed-format tests.
        return (
            not path.startswith(("docs/examples/", "docs/development/context-cost-data/"))
            and not any(part == "vectors" or part.endswith("-vectors") for part in parts)
            and Path(path).suffix not in {".py", ".sh", ".ps1", ".rs", ".toml", ".yml", ".yaml"}
        )
    return path.endswith(".md") and not path.startswith(("crates/", "helpers/", "skills/", "vendor/"))


def release_source(path: str) -> bool:
    return path.startswith((
        "crates/", "helpers/evtx/", "vendor/", "skills/core/",
        ".github/scripts/build_release", ".github/scripts/native_mapping/",
        ".github/workflows/release",
    )) or path in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "install.sh", "install.ps1"}


def select_scope(event: str, ref: str, changed: list[str], labels: set[str],
                 recent_commit: bool, release_dry_run: bool = False, *,
                 action: str = "", label: str = "", draft: bool = False,
                 weekly: bool = False, release_changed: bool = False) -> dict[str, bool]:
    if release_dry_run and (event != "workflow_dispatch" or not ref.startswith("refs/heads/")):
        raise ValueError("release dry run requires a manual workflow on a branch")
    pull_request = event == "pull_request"
    ignored = pull_request and action in LABEL_EVENTS and label != "full-ci"
    docs_only = pull_request and bool(changed) and all(map(docs_path, changed))
    tag = event == "push" and ref.startswith("refs/tags/v")
    nightly = event == "schedule" and (recent_commit or weekly or release_changed)
    return {
        "run_ci": not ignored and (event != "schedule" or nightly),
        "docs_only": not ignored and docs_only,
        "platforms": tag or nightly or event == "workflow_dispatch" or (
            not ignored and pull_request and not docs_only and (
                ("full-ci" in labels and not draft) or any(map(platform_path, changed))
            )
        ),
        "cross_verify": tag or nightly or release_dry_run,
        "release_build": tag or release_dry_run or (nightly and (weekly or release_changed)),
    }


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def diff_names(revision: str, *flags: str) -> list[str]:
    raw = subprocess.check_output(
        ["git", "diff", "--name-only", "--no-renames", "-z", *flags, revision]
    )
    return [path.decode("utf-8") for path in raw.split(b"\0") if path]


def main_runs(query: str) -> list[dict]:
    repo = os.environ["GITHUB_REPOSITORY"]
    return json.loads(command(
        "gh", "api", f"repos/{repo}/actions/workflows/ci.yml/runs?branch=main&{query}"
    ))["workflow_runs"]


def run_data(run: int, kind: str) -> list[dict]:
    repo = os.environ["GITHUB_REPOSITORY"]
    endpoint = f"repos/{repo}/actions/runs/{run}/{kind}?per_page=100"
    if kind == "jobs":
        endpoint += "&filter=all"
    entries = []
    page = 1
    while True:
        response = json.loads(command("gh", "api", f"{endpoint}&page={page}"))
        entries.extend(response[kind])
        if not response[kind] or len(entries) >= response["total_count"]:
            return entries
        page += 1


def has_full_release_build(jobs: list[dict]) -> bool:
    expected = {"linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64", "windows-x86_64"}
    outcomes = {}
    # Retrying failed jobs preserves the successes from earlier attempts.
    for job in sorted(jobs, key=lambda entry: entry.get("run_attempt", 1)):
        match = re.match(r"release_binaries / verify_release_reproducibility \(([^,]+),", job["name"])
        if match:
            outcomes[match[1]] = job["conclusion"]
    return outcomes == dict.fromkeys(expected, "success")


def nightly_release_changed(recent_commit: bool) -> bool:
    for run in main_runs("event=schedule&status=success&per_page=16"):
        sha = run["head_sha"]
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise ValueError("invalid nightly commit from GitHub")
        if has_full_release_build(run_data(run["id"], "jobs")):
            return any(map(release_source, diff_names(f"{sha}..HEAD")))
    # The weekly run seeds the history. Before that, use recent release inputs.
    return recent_commit and any(map(release_source, command(
        "git", "log", "--since-as-filter=24 hours ago", "--format=", "--name-only", "--no-renames",
    ).splitlines()))


def docs_binary_run() -> int | None:
    for run in main_runs("event=push&status=success&per_page=12"):
        sha = run["head_sha"]
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise ValueError("invalid documentation binary commit from GitHub")
        if any(map(release_source, diff_names(f"{sha}..HEAD"))):
            continue
        if any(item["name"] == "docs-cli" and not item["expired"]
               for item in run_data(run["id"], "artifacts")):
            return int(run["id"])
    return None


def main() -> None:
    event = os.environ["GITHUB_EVENT_NAME"]
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pull_request = payload.get("pull_request", {})
    action = payload.get("action", "")
    label = payload.get("label", {}).get("name", "")
    changed = []
    if event == "pull_request" and (action not in LABEL_EVENTS or label == "full-ci"):
        changed = diff_names(f"{pull_request['base']['sha']}...{pull_request['head']['sha']}")
    labels = {entry["name"] for entry in pull_request.get("labels", [])}
    last_main_commit = int(command("git", "log", "-1", "--format=%ct"))
    recent_commit = 0 <= time.time() - last_main_commit < 86_400
    weekly = event == "schedule" and payload.get("schedule") == WEEKLY_RELEASE
    inputs = payload.get("inputs") or {}
    release_dry_run = inputs.get("release_dry_run", "false") in (True, "true")
    if release_dry_run and inputs.get("profile_linux", "false") in (True, "true"):
        raise ValueError("release dry run and Linux-only profiling cannot run together")
    release_changed = False
    if event == "schedule" and not weekly:
        try:
            release_changed = nightly_release_changed(recent_commit)
        except subprocess.CalledProcessError:
            print("Could not check the last successful release build. Running the release matrix.")
            release_changed = True
    scope = select_scope(
        event, os.environ["GITHUB_REF"], changed, labels, recent_commit, release_dry_run,
        action=action, label=label, draft=pull_request.get("draft", False), weekly=weekly,
        release_changed=release_changed,
    )
    binary = None
    if scope["docs_only"]:
        try:
            binary = docs_binary_run()
        except subprocess.CalledProcessError:
            print("Could not locate the main CLI artifact. The documentation job checks the source.")
    iso = datetime.now(timezone.utc).isocalendar()
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii") as output:
        for key, enabled in scope.items():
            output.write(f"{key}={str(enabled).lower()}\n")
        output.write(f"docs_binary_run={binary or ''}\n")
        output.write(f"cache_epoch={iso.year}-w{iso.week:02d}\n")


if __name__ == "__main__":
    main()
