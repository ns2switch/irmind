"""Select registered fuzz targets by local crate dependencies and changed files."""

from functools import cache
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REGISTRIES = ("fuzz", "helpers/evtx/fuzz")
WEEKLY = "41 2 * * 0"
IDENTITY = set("""
parser_s3_access parser_elb parser_iis_w3c parser_windows_dns parser_route53
parser_github_audit parser_google_workspace parser_macos parser_fdr parser_defender
parser_email parser_m365 parser_okta parser_guardduty parser_vpc_flow parser_azure_flow
parser_gcp_flow query_page_athena query_page_bigquery query_page_azure_analytics
""".split())
GLOBAL_INPUTS = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".github/workflows/fuzz.yml",
    ".github/scripts/select_fuzz_targets.py", ".github/scripts/run_fuzz_targets.sh",
    ".github/scripts/install_cargo_fuzz.sh",
}


@cache
def read(path):
    with path.open("rb") as source:
        return tomllib.load(source)


def targets(root):
    registered = {}
    for registry in REGISTRIES:
        for target in read(root / registry / "Cargo.toml").get("bin", []):
            name, path = target["name"], target["path"]
            if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or path != f"fuzz_targets/{name}.rs":
                raise ValueError(f"invalid fuzz registration {registry}/{path}")
            registered[f"{registry}:{name}"] = f"{registry}/{path}"
    return registered


def dependency_paths(root, source):
    manifest = read(root / "Cargo.toml")
    workspace = manifest.get("workspace", {}).get("dependencies", {})
    patches = manifest.get("patch", {}).get("crates-io", {})
    manifests = sorted((root / "crates").glob("**/Cargo.toml")) + [root / "helpers/evtx/Cargo.toml"]
    manifests = {read(path)["package"]["name"].replace("-", "_"): path for path in manifests}
    roots = {manifests[name] for name in re.findall(r"\birmind_[a-z0-9_]+\b", source) if name in manifests}
    if re.search(r"\bevtx\b", source):
        roots.add(root / "helpers/evtx/Cargo.toml")
    reachable = set()
    while roots:
        path = roots.pop()
        if path in reachable:
            continue
        reachable.add(path)
        spec = read(path)
        for table in (spec, *spec.get("target", {}).values()):
            for category in ("dependencies", "build-dependencies"):
                for name, dep in table.get(category, {}).items():
                    parent = path.parent
                    if isinstance(dep, dict) and dep.get("workspace"):
                        dep = workspace.get(name, {})
                        parent = root
                    dep = dep if isinstance(dep, dict) else {}
                    if "path" not in dep:
                        dep = patches.get(dep.get("package", name), {})
                        parent = root
                    if "path" in dep:
                        child = (parent / dep["path"] / "Cargo.toml").resolve()
                        if child.is_relative_to(root) and child not in reachable:
                            roots.add(child)
    return {path.parent.relative_to(root).as_posix() + "/" for path in reachable}


def daily_targets(root, registered, changed):
    if set(changed) & GLOBAL_INPUTS:
        return list(registered)
    selected = []
    for key, filename in registered.items():
        registry, name = key.split(":")
        prefixes = dependency_paths(root, (root / filename).read_text())
        seeds = {"evtx_decode": f"{registry}/seeds/security.evtx",
                 "evtx_protocol": f"{registry}/seeds/protocol/"}
        prefixes.add(seeds.get(name, f"{registry}/seeds/{name}/"))
        shared = {f"{registry}/Cargo.lock", f"{registry}/Cargo.toml"}
        if any(path == filename or path in shared or path.startswith(tuple(prefixes))
               for path in changed):
            selected.append(key)
    return selected


def pr_targets(root, registered, added):
    result = [key for key, filename in registered.items() if filename in added]
    for path in added:
        if not re.fullmatch(r"crates/modules/parser-[^/]+/Cargo.toml", path):
            continue
        package = read(root / path)["package"]["name"].replace("-", "_")
        direct = [key for key, filename in registered.items()
                  if re.search(rf"\b{re.escape(package)}\b", (root / filename).read_text())]
        if not direct:
            raise ValueError(f"{path} needs an admitted AddressSanitizer fuzz target")
        result.extend(direct)
    return sorted(set(result))


def git_paths(*args):
    raw = subprocess.check_output(["git", *args, "-z"])
    return [path.decode() for path in raw.split(b"\0") if path]


def main():
    registered = targets(ROOT)
    event = os.environ["GITHUB_EVENT_NAME"]
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    output = {}
    if event == "pull_request":
        pr = payload["pull_request"]
        added = git_paths("diff", "--name-only", "--no-renames", "--diff-filter=A",
                          f"{pr['base']['sha']}...{pr['head']['sha']}")
        output["pr_targets"] = " ".join(pr_targets(ROOT, registered, added))
    elif event == "schedule" and payload.get("schedule") != WEEKLY:
        changed = git_paths("log", "--name-only", "--no-renames", "--format=",
                            "--since-as-filter=24 hours ago")
        output["daily_targets"] = " ".join(daily_targets(ROOT, registered, changed))
    else:
        output["core_targets"] = " ".join(
            key for key in registered if key.startswith("fuzz:") and key.split(":")[1] not in IDENTITY
        )
        identity = sorted(key for key in registered
                          if key.startswith("fuzz:") and key.split(":")[1] in IDENTITY)
        # Two runners share their compiler inputs across batches.
        output["identity_targets"] = json.dumps([
            {"batch": offset + 1, "targets": " ".join(identity[offset::2])}
            for offset in range(2) if identity[offset::2]
        ])
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii") as file:
        for key, value in output.items():
            file.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
