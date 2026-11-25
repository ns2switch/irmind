[Español](es/reproducible-builds.md)

# Reproducible builds

Before signing a release, the [release build matrix](../.github/workflows/release-binaries.yml)
builds `irmind` and `irmind-evtx` from two clean checkouts of the same commit,
at different paths. It compares the full SHA-256 of each executable and blocks
publication on a mismatch. This check applies to tags whose workflow uses that
matrix. It covers the standalone executables before native platform signing.
Sigstore bundles and attestations are verified separately.

## First reproducible releases

| Executable | Platforms | Reproducible from |
| --- | --- | --- |
| `irmind` | Linux x86_64 and Arm64, Windows x64 | v0.6.1 |
| `irmind-evtx` | All five release targets | v0.6.1 |
| `irmind` | macOS Intel and Apple Silicon | v0.6.2 |

The v0.6.1 macOS main executable used the runner's workspace, Cargo home and
build directory. The fixed paths entered the macOS main build for v0.6.2.
For v0.6.1, use the commands in the
[tagged release workflow](https://github.com/ns2switch/irmind/blob/v0.6.1/.github/workflows/ci.yml)
and its [build logs](https://github.com/ns2switch/irmind/actions/runs/45056933393).
The signed tool inventory and paired-build command below start with v0.6.2.

## Rehearse publication before tagging

From the candidate branch, run the full release rehearsal:

```sh
gh workflow run ci.yml --ref "$candidate_branch" -f release_dry_run=true
```

Require a successful `release` job on the same Git tree that will be tagged.
The job downloads the five distribution packages and the native mapping
inventory, packages them, generates the SBOMs and attestations, and signs and
verifies the payload with Sigstore. Its `signed-release-dry-run` artifact
contains the verified payload. If the candidate tree changes, repeat the
rehearsal. `release_binary_reproducibility` covers reproducible binaries and
portable Sigma cases only. It does not exercise release packaging.

| Step or job skipped in the full rehearsal | Reason |
| --- | --- |
| Create or update the GitHub release and append its code signing policy | These steps write to a public release and require a tag push. |
| `native_macos` | Developer ID signing is disabled. If activated separately, it requires a protected tag deployment with Apple credentials. |
| `verify_install_linux`, `verify_install_macos`, `verify_install_windows` | These jobs use the public release URL and the tag's signing identity. The rehearsal runs the offline installer tests in the platform matrix and exercises the staged signed payload via `rehearse_install_windows`. |
| `update_homebrew` | The tap updates a published tag after the protected `release` environment is approved. |
| `release_profile` and its profile benchmark and reproducibility jobs | These are separate manual performance experiments. The five-target reproducibility gate runs in the rehearsal. |

## Build inputs

Start with a native host or VM for the target architecture, Git, and Python
3.10 or newer. Use the versions in the verified `BUILD-ENVIRONMENT.json` from
the [release assets](https://github.com/ns2switch/irmind/releases). Each entry
under `targets` records the tools used for that target.

GitHub regularly updates its hosted runner images, including versioned
labels, and retired revisions are unavailable as runnable images. The
`image_os` and `image_version` fields help locate the historical software
list. To reproduce an older binary, install the recorded tool versions on
your own host or VM. [GitHub runner image maintenance](https://github.com/actions/runner-images#software-and-image-support)

| Target argument and release suffix | Release runner | Main executable |
| --- | --- | --- |
| `linux-x86_64` | Ubuntu 22.04 | ThinLTO, one codegen unit, mold 2.42.1 |
| `linux-aarch64` | Ubuntu 24.04 Arm64 | ThinLTO, one codegen unit, system linker |
| `macos-aarch64` | `macos-26` on Apple Silicon | Native Apple linker |
| `macos-x86_64` | `macos-15-intel` on Intel | Native Apple linker |
| `windows-x86_64` | `windows-2025-vs2026` on x64 | ThinLTO, one codegen unit, MSVC with `/Brepro` |

The [build script](../.github/scripts/build_release_binaries.py) passes
`--release --locked`, sets `CARGO_INCREMENTAL=0` and
`CARGO_PROFILE_RELEASE_STRIP=symbols`, and selects the target and linker flags.
Run it from the shell where you selected the matching tools, with the
build settings from the tag. The Windows worktree uses CRLF checkout rules for files such as
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
on macOS and `C:\irmind-evtx-release-v1` on Windows. It uses the build
shell's Cargo home. The fixed staging directories must be free when the script
starts. The script removes the staging directories it creates.

## Build and compare with a release

From a clone of the public repository, set `tag` to the exact release tag.
Verify the inventory and checksum list with cosign 3.1.3 or newer before
choosing the build tools.

```bash
tag='<TAG>'
git fetch --tags origin
git checkout --detach "$tag"
gh release download "$tag" -R ns2switch/irmind \
  -p 'BUILD-ENVIRONMENT.json*' -p 'SHA256SUMS*' -D release-checksums
for file in BUILD-ENVIRONMENT.json SHA256SUMS; do
  cosign verify-blob "release-checksums/$file" \
    --bundle "release-checksums/$file.sigstore.json" \
    --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com || exit 1
done
```

For releases publishing `NATIVE-MAPPING-INPUTS.json`, download it and its
Sigstore bundle alongside the two files above. Verify it with the same
release certificate identity, then check its entry in the signed
`SHA256SUMS`. Use Python 3.11 or newer and add
`--mapping-inputs release-checksums/NATIVE-MAPPING-INPUTS.json` to the
build command below. The workflow combines observations from all five
release targets. The build script checks the selected target's observation
again before accepting the reconstructed binary.

### Install the native tools

Choose the entry under `targets` for the binary being reproduced. Compare
versions in the build shell before compiling.

**Linux.** Use the Ubuntu release and architecture in the table. Install the
compiler and development libraries from the matching Ubuntu archive snapshot,
using the recorded compiler version and the software list linked in the
release workflow's job log. For Arm64, install the matching GNU Binutils and
check the linker resolved by the compiler driver. For x86_64, install the
recorded mold release and put its `bin` directory on `PATH`. Compare
`cc --version` and either the version of the linker returned by
`cc -print-prog-name=ld` on Arm64 or `mold --version` on x86_64 with the
inventory. [Ubuntu Snapshot Service](https://snapshot.ubuntu.com/) ·
[mold releases](https://github.com/rui314/mold/releases)

**macOS.** Download the Xcode version and build shown in `native.xcode` from
Apple Developer Downloads. Use a macOS version that supports that Xcode on
the target architecture. Install the app and use its bundled macOS SDK.
Set `DEVELOPER_DIR` to the installed app's developer directory in the build
shell. Compare the Xcode build, the SDK version and build, and the compiler
and linker with the corresponding `native` fields. [Apple downloads](https://developer.apple.com/download/all/?q=Xcode) ·
[Selecting Xcode tools](https://developer.apple.com/documentation/xcode/configuring-command-line-tools-settings)

```bash
export DEVELOPER_DIR='/Applications/<Xcode app>/Contents/Developer'
unset SDKROOT
xcodebuild -version
xcodebuild -version -sdk macosx
xcrun clang --version
xcrun ld -v
```

**Windows.** Use the fixed-version Build Tools installer for the recorded
`native.visual_studio` build. In Visual Studio Installer, install **Desktop
development with C++**, including the recorded **MSVC C++ x64/x86 build tools**
and **Windows SDK**. Use **Individual components** to select the toolset and
SDK corresponding to `native.msvc_toolset` and `native.windows_sdk`. Open a
fresh Command Prompt and replace the placeholders with that installation's
path and recorded versions. [Visual Studio release history](https://learn.microsoft.com/en-us/visualstudio/releases/2026/release-history) ·
[Build Tools components](https://learn.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-build-tools?view=vs-2026) ·
[Selecting a toolset and SDK](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-140)

```bat
call "<Visual Studio path>\VC\Auxiliary\Build\vcvarsall.bat" x64 <windows_sdk> -vcvars_ver=<msvc_toolset>
echo %VCToolsVersion%
echo %WindowsSDKVersion%
where.exe cl.exe
where.exe link.exe
```

Compare the selected `cl.exe` and `link.exe` file versions in Properties
under **Details** with `native.compiler` and `native.linker`. Launch Git
Bash by running `"<Git for Windows path>\bin\bash.exe"` from that prompt
so it inherits the selected toolchain.

In Git Bash, put the selected MSVC tools first on `PATH` and check where
both executables resolve.

```bash
msvc_bin="$(cygpath -u "$VCToolsInstallDir")/bin/Hostx64/x64"
export PATH="$msvc_bin:$PATH"
command -v cl.exe
command -v link.exe
```

### Install the exact Rust toolchain and rebuild

In the build shell, use the `release` and `host` lines in the target's
`rustc` field to form the rustup toolchain name. For example,
`1.95.0-aarch64-apple-darwin` pairs release `1.95.0` with host
`aarch64-apple-darwin`. Confirm the release agrees with
[`rust-toolchain.toml`](../rust-toolchain.toml) at the tag. Compare the output
of `rustc -vV` and `cargo -vV` with the inventory, including their commit
hashes. [rustup installation](https://rust-lang.github.io/rustup/installation/) ·
[Selecting a toolchain for the shell](https://rust-lang.github.io/rustup/overrides.html)

```bash
toolchain='<release>-<host>'
rustup toolchain install "$toolchain"
export RUSTUP_TOOLCHAIN="$toolchain"
rustc -vV
cargo -vV
```

Select the destination from the table and a new output directory. The
command runs the same paired build as CI.

```bash
destination=macos-aarch64
python .github/scripts/build_release_binaries.py "$destination" reproduced --verify
```

Compare both local executables with their published release asset names:

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
