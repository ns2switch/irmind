"""Install signed branch artifacts with the Windows installer's verification."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib


LOCAL_DOWNLOAD = r'''function Download-Https([string]$Url, [string]$Destination, [long]$MaximumBytes) {
    $prefix = "https://github.com/$repo/releases/download/$Version/"
    if (-not $Url.StartsWith($prefix, [System.StringComparison]::Ordinal)) { Fail 'unexpected rehearsal URL' }
    $name = $Url.Substring($prefix.Length)
    if ($name -cnotmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$') { Fail 'unexpected rehearsal asset' }
    $file = Get-Item -LiteralPath (Join-Path $env:IRMIND_REHEARSAL_ASSETS $name)
    if ($file.Length -gt $MaximumBytes) { Fail 'rehearsal asset exceeds its size limit' }
    Copy-Item -LiteralPath $file.FullName -Destination $Destination
}'''


def main():
    source_ref = os.environ["GITHUB_REF"]
    if not source_ref.startswith("refs/heads/"):
        raise SystemExit("The install rehearsal requires a signed branch artifact")
    assets = Path(sys.argv[1]).resolve()
    repo = os.environ["GITHUB_REPOSITORY"]
    names = {"irmind.exe": "irmind-windows-x86_64.exe",
             "irmind-evtx.exe": "irmind-evtx-windows-x86_64.exe"}
    if not (shutil.which("cosign") and shutil.which("gh")):
        raise SystemExit("The install rehearsal requires Cosign and GitHub CLI")
    for name in names.values():
        subprocess.run(["gh", "attestation", "verify", assets / name, "-R", repo,
                        "--source-ref", source_ref, "--source-digest", os.environ["GITHUB_SHA"],
                        "--signer-workflow", f"{repo}/.github/workflows/ci.yml"], check=True)

    source = Path("install.ps1").read_text(encoding="utf-8")
    source, changed = re.subn(r"(?ms)^function Download-Https\(.*?^}", lambda _: LOCAL_DOWNLOAD, source)
    identity = "@refs/tags/$Version"
    if changed != 1 or source.count(identity) != 1:
        raise SystemExit("Unexpected installer structure")
    source = source.replace(identity, "@$env:GITHUB_REF")
    version = tomllib.loads(Path("crates/bin/Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    with tempfile.TemporaryDirectory(prefix="irmind-install-", dir=os.environ["USERPROFILE"]) as temp:
        root = Path(temp)
        script = root / "install-rehearsal.ps1"
        script.write_text(source, encoding="utf-8")
        installed = root / "bin"
        subprocess.run(["pwsh", "-NoProfile", "-File", script, "-Version", f"v{version}",
                        "-InstallDir", installed],
                       env=os.environ | {"IRMIND_REHEARSAL_ASSETS": str(assets)}, check=True)
        for name, asset in names.items():
            if (installed / name).read_bytes() != (assets / asset).read_bytes():
                raise SystemExit(f"The installed binary differs from its signed artifact: {name}")
        reported = subprocess.check_output([installed / "irmind.exe", "--version"], text=True).strip()
        if reported != f"irmind {version}":
            raise SystemExit(f"Unexpected installed version: {reported}")
    print(f"Signed Windows release rehearsal installed and ran {reported}")


if __name__ == "__main__":
    main()
