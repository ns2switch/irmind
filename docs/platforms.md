# Platforms

This page is for people installing IRMind on Linux, macOS, or Windows, including headless SSH hosts. It covers source builds, release verification, keystore backends, and terminal behavior. Start with [getting started](getting-started.md) for the case workflow.

Read the [Code signing policy](../CODE_SIGNING.md) for current verification, team roles,
privacy and the status of native platform signing.

## Build from source

A source build is the recommended path for internal evaluation:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
CARGO_TARGET_DIR=target cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked
```

The second build produces the isolated EVTX helper beside the main executable. In PowerShell, set `$env:CARGO_TARGET_DIR = "target"` before running that helper build. EVTX stays unavailable if its matching helper or the required native sandbox is missing.

Linux x86-64 builds use Ubuntu 22.04 as their userspace ABI baseline. Native Ubuntu 22.04 and 24.04 jobs exercise the same EVTX helper artifact; container probes also cover Debian/Fedora userspaces on those host kernels. ARM64 uses a separate Ubuntu 24.04 runner and has separate compatibility limits. CI also tests native macOS arm64 and x86-64 and Windows x64 with the MSVC toolchain. SQLite is built from bundled sources. Arrow and Parquet use Rust crates. Network TLS uses rustls with native certificate roots, including installed corporate CAs; IRMind does not link system OpenSSL. The native-root approach may differ from platform policy checks performed by a dedicated certificate verifier.

Install a C/C++ compiler before building: GCC or Clang and `pkg-config` on Linux, Xcode Command Line Tools on macOS, or Visual Studio Build Tools with MSVC C++ on Windows. A cold release build still compiles many Rust crates and bundled SQLite. Allow extra time and disk; the exact cost depends on CPU, compiler, and cache. See [benchmarks](development/benchmarks.md) for measured builds.

To rebuild a release and compare the SHA-256 of both executables, see [Reproducible builds](reproducible-builds.md).

## Verify a release before installing

Download the binary for your system and `SHA256SUMS` from the [GitHub release](https://github.com/ns2switch/irmind/releases). Check the exact binary name in the checksum file before executing it. The first pre-release, v0.1.0, has only checksums. Releases from v0.1.1 include Sigstore bundles and GitHub provenance. A checksum alone checks bytes against that file, not the publisher's identity.

| System | Check |
| --- | --- |
| Linux | Check the one line for your exact binary with `sha256sum -c -`. |
| macOS | Check the one line for your exact binary with `shasum -a 256 -c -`. |
| Windows PowerShell | Compare `Get-FileHash` with the one line for your exact binary. |

The checksum file lists every release asset, so a full `SHA256SUMS` check needs every asset downloaded. With only one binary, select its line and require one match before checking it. On Linux or macOS:

```sh
binary=irmind-linux-x86_64 # replace with the downloaded asset name
line=$(awk -v name="$binary" '$2 == name { print }' SHA256SUMS)
test -n "$line" && test "$(printf '%s\n' "$line" | wc -l)" -eq 1 || exit 1
printf '%s\n' "$line" | sha256sum -c - # use shasum -a 256 -c - on macOS
```

On Windows, compare the lowercase `Get-FileHash` result with the digest in the single matching `SHA256SUMS` line for `irmind-windows-x86_64.exe`.

For v0.1.1 and later, also download the matching `.sigstore.json` bundles for the binary and `SHA256SUMS`. Use cosign **3.1.3 or newer**: earlier v3 releases have a [legacy-bundle identity-verification bypass](https://github.com/sigstore/cosign/security/advisories/GHSA-fx35-mq7g-6g98). The installers reject those versions. Verify both files with the exact GitHub Actions identity and issuer below, replacing `<TAG>` and `<BINARY>` with the downloaded release tag and filename:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob "<BINARY>" --bundle "<BINARY>.sigstore.json" \
  --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "<BINARY>" -R ns2switch/irmind
```

For Windows PowerShell, use the same `cosign verify-blob` and `gh attestation verify` commands with Windows paths. Check the certificate identity against the **tag you intended to install**; checking only that a signature exists is insufficient. The attestation binds the binary digest to this repository's build workflow. [Sigstore's verification guide](https://docs.sigstore.dev/cosign/verifying/verify/) and [GitHub's attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) explain the checks.

The source tree contains [install.sh](../install.sh) and [install.ps1](../install.ps1). Download the script and its matching `SHA256SUMS`. First verify the `SHA256SUMS` Sigstore bundle against the expected tag and workflow identity using the command above; then check the **script's exact checksum line** before running it. On Linux or macOS, set `binary=install.sh` in the checksum example above. On Windows, compare `Get-FileHash .\install.ps1 -Algorithm SHA256` with its single matching line. The scripts detect your system, verify the selected binary's checksum, and, when available, use `cosign` and a current `gh` to verify its signature and provenance. A failed verification stops the installation. They never request administrator privileges or change `PATH`.

```sh
# Linux or macOS, after checking install.sh against the release SHA256SUMS:
sh ./install.sh v0.3.0
```

```powershell
# Windows, after checking install.ps1 against the release SHA256SUMS:
& .\install.ps1 -Version v0.3.0
```

Omit the version to select the newest published release, including a pre-release. An optional second POSIX argument or `-InstallDir` PowerShell argument chooses another user-owned directory. By default the binary goes to `~/.local/bin` on Linux and macOS or `%LOCALAPPDATA%\IRMind\bin` on Windows. If it is outside `PATH`, the script prints the path to add manually.

CI also produces test artifacts on relevant nightly runs; these are not GitHub Releases. Pull requests and merges to `main` do not publish binaries. Apple notarization and Windows Authenticode are not available yet, so those systems may still warn after verification.

## Homebrew

Recommended on macOS; also available for Linux. The [tap](https://github.com/ns2switch/homebrew-irmind) supports Apple Silicon, Intel, Linux x86_64 and Linux arm64, including `irmind-evtx`:

```sh
brew install ns2switch/irmind/irmind
irmind --version
irmind demo
brew upgrade ns2switch/irmind/irmind
# Remove both binaries when no longer needed:
brew uninstall ns2switch/irmind/irmind
```

No source build is needed. The updater authenticates the release's `SHA256SUMS` with its exact Sigstore tag/workflow identity before fixing each asset hash in the formula. Homebrew verifies those hashes during installation. Inspect the formula before granting trust; recent Homebrew may request explicit formula trust as described in the [tap instructions](https://github.com/ns2switch/homebrew-irmind#trust-and-native-checks).

The tap checks `brew audit` in strict mode, `brew test`, real demo startup at 80×24, installed bytes and uninstall on clean macOS arm64, macOS Intel and Linux runners. Its macOS test checks quarantine **without removing it** and records command execution. This is not Apple signing or notarization and does not certify every local Gatekeeper policy. Keep the exact creating executable and helper outside Homebrew before upgrading a case; old kegs may be removed by Homebrew cleanup.

## Linux

Use a terminal compatible with xterm, such as GNOME Terminal or Konsole. The `os` backend needs Secret Service through D-Bus; it may be unavailable over SSH. Select `file` explicitly for a headless session. Local files and directories are restricted to the current user with Unix `0600` and `0700` permissions.

## macOS

Use Terminal.app or iTerm2. The `os` backend uses Keychain; the `file` backend is available for explicit SSH use. The release matrix targets Apple Silicon and Intel on native runners. Earlier
releases may contain only Apple Silicon; check the exact tag assets before
installing on Intel. After verifying the release, Gatekeeper may block a downloaded binary without Apple code signing. Follow your organization’s policy and the macOS Privacy & Security review for that verified binary only. Do not disable Gatekeeper or remove quarantine to bypass an unresolved block. The helper requires the same independent verification. Native signing preparation is described below.

## Windows

Use Windows Terminal and the x64 MSVC build. The `os` backend uses Credential Manager; `file` is available when it is explicitly selected. IRMind checks that local case files and the encrypted store are restricted to the current user's SID. SmartScreen or corporate antivirus may warn about a binary without Authenticode. Verify the checksum, Sigstore identity, and provenance, then request a narrow exception from your security team if policy allows it. Do not disable protection globally.

## Data and terminal behavior

Without `--home`, data goes to the platform's standard local application-data directory: XDG on Linux, Application Support on macOS, and LocalAppData on Windows. Evidence names are lower-case hashes; paths stored in the audit and export use relative `/` separators. SQLite holds the audit and case state; signed Parquet artifacts provide derived graph queries.

The TUI uses the alternate screen and sanitizes external text before display. Automated tests cover control sequences and bidirectional controls on all three systems. Visual interaction still needs manual review in each terminal before production use. Over SSH, request a terminal (`ssh -t`), select `file` during setup, and enter the passphrase in the masked TUI field. Backend changes are explicit; IRMind never falls back silently. `verify-export` can run without unlocking a keystore.

## Card expansion and terminal keymaps

Ctrl+O expands or folds the selected expandable card from the input box, conversation or sidebar. Without a suitable selection, it uses the last expandable card. `/expand` performs the same action and remains available if a terminal, SSH client or custom tmux keymap intercepts the key. No focus change or draft clearing is needed.

The byte `0x0f` is covered by the real-binary PTY regression on the CI operating systems. This does not certify individual GUI terminal keymaps. Interactive confirmation in macOS Terminal.app, iTerm2, GNOME Terminal/Konsole, Windows Terminal, SSH and tmux remains a maintainer check. No terminal-specific interception has been confirmed by this automated test; use `/expand` rather than disabling terminal safety settings.

## Native signing preparation

Developer ID signing and notarization for both macOS architectures are prepared but disabled. See the
[maintainer setup](development/native-signing.md); current releases still lack
Apple native signatures. No production secret or activation is required to use
the existing Sigstore verification. Windows Authenticode signing remains pending;
SignPath Foundation may be reevaluated after the public launch. A paid signing
subscription is another future option, not an active service or sponsorship.

Windows may show “Windows protected your PC”, an unrecognized-app warning or an
unknown publisher. Windows 11 Smart App Control can block an unsigned file;
Sigstore verification does not override it. Verify SHA256SUMS, the exact-tag
Sigstore identity and GitHub provenance **before** execution. Follow organizational
policy if execution remains blocked; do not disable protections to make the demo
run. See [Microsoft's explanation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation).
