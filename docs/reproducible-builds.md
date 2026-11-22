[Español](es/reproducible-builds.md)

# Reproducible builds

Before signing a release, the [release build matrix](../.github/workflows/release-binaries.yml)
builds `irmind` and `irmind-evtx` from two clean checkouts of the same commit,
at different paths. It compares the full SHA-256 of each executable and blocks
publication on a mismatch. This check applies to tags whose workflow uses that
matrix. It covers the standalone executables before native platform signing.
Sigstore bundles and attestations are verified separately.

## Build inputs

Use the Rust toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml)
at the tag, currently 1.95.0, plus Git and Python 3.10 or newer. Match the
native runner image and compiler/linker versions recorded by that tag's workflow.
On macOS, use the recorded Xcode and macOS SDK. On Windows, use the recorded
Visual Studio C++ tools and Windows SDK, and run the commands in Git Bash.

| Target argument and release suffix | Native runner | Main executable |
| --- | --- | --- |
| `linux-x86_64` | Ubuntu 22.04 | ThinLTO, one codegen unit, mold 2.42.1 |
| `linux-aarch64` | Ubuntu 24.04 Arm64 | ThinLTO, one codegen unit, system linker |
| `macos-aarch64` | `macos-latest` on Apple Silicon | Native Apple linker |
| `macos-x86_64` | `macos-15-intel` on Intel | Native Apple linker |
| `windows-x86_64` | `windows-latest` on x64 | ThinLTO, one codegen unit, MSVC with `/Brepro` |

The [build script](../.github/scripts/build_release_binaries.py) passes
`--release --locked`, sets `CARGO_INCREMENTAL=0` and
`CARGO_PROFILE_RELEASE_STRIP=symbols`, and selects the target and linker flags.
Run it with the runner's standard Cargo and compiler environment, free of local
build overrides. The Windows worktree uses CRLF checkout rules for files such as
`Cargo.lock` that are governed by Git's automatic text conversion. These bytes
are part of the current native mapping identity.

For the macOS main executable, the script stages the committed tree in
`/private/tmp/irmind-macos-release-v1/source`, sets
`CARGO_HOME=/private/tmp/irmind-macos-release-v1/cargo-home` and
`CARGO_TARGET_DIR=/private/tmp/irmind-macos-release-v1/target`, and remaps
these three prefixes to `/canonical/workspace`, `/canonical/cargo_home` and
`/canonical/target` for Rust. The physical paths also keep the Apple linker's
build UUID stable.

EVTX uses its own lockfile and Cargo profile. Its committed tree and target are
staged in the `source` and `target` subdirectories of
`/tmp/irmind-evtx-release-v1` on Linux, `/private/tmp/irmind-evtx-release-v1`
on macOS and `C:\irmind-evtx-release-v1` on Windows. It uses the native
runner's Cargo home. The fixed staging directories must be free when the script
starts. The script removes the staging directories it creates.

## Build and compare with a release

From a clone of the public repository, set `tag` to the exact release tag and
`destination` to your target from the table. Use an absent output directory.
The build command below runs the same paired check as CI.

```bash
tag='<TAG>'
destination=macos-aarch64
git fetch --tags origin
git checkout --detach "$tag"
python .github/scripts/build_release_binaries.py "$destination" reproduced --verify

gh release download "$tag" -R ns2switch/irmind \
  -p SHA256SUMS -p SHA256SUMS.sigstore.json -D release-checksums
cosign verify-blob release-checksums/SHA256SUMS \
  --bundle release-checksums/SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use cosign 3.1.3 or newer and continue after successful verification. Compare
both local executables with their published release asset names:

```bash
python - "$destination" <<'PY'
import hashlib
from pathlib import Path
import sys

destination = sys.argv[1]
extension = ".exe" if destination.startswith("windows-") else ""
lines = Path("release-checksums/SHA256SUMS").read_text(encoding="ascii").splitlines()
for name in ("irmind", "irmind-evtx"):
    asset = f"{name}-{destination}{extension}"
    expected = [fields[0] for line in lines
                if len(fields := line.split()) == 2 and fields[1] == asset]
    digest = hashlib.sha256((Path("reproduced") / (name + extension)).read_bytes()).hexdigest()
    if expected != [digest]:
        sys.exit(f"{asset}: SHA-256 mismatch or checksum entry missing or duplicated")
    print(f"{asset}: {digest}")
PY
```

If optional Developer ID signing is activated for a tag, it changes the
downloadable macOS bytes after this build check. Use the
[platform verification guide](platforms.md#verify-a-release-before-installing)
to verify those assets and their provenance.
