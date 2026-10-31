# Platforms

This page is for people installing IRMind on Linux, macOS, or Windows, including headless SSH hosts. It covers source builds, release verification, keystore backends, and terminal behavior. Start with [getting started](getting-started.md) for the case workflow.

## Build from source

A source build is the recommended path for internal evaluation:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
```

CI tests Ubuntu Linux, macOS arm64, and Windows x64 with the MSVC toolchain. SQLite is built from bundled sources. Arrow and Parquet use Rust crates. Network TLS uses rustls with native certificate roots, including installed corporate CAs; IRMind does not link system OpenSSL. The native-root approach may differ from platform policy checks performed by a dedicated certificate verifier.

Install a C/C++ compiler before building: GCC or Clang and `pkg-config` on Linux, Xcode Command Line Tools on macOS, or Visual Studio Build Tools with MSVC C++ on Windows. A cold release build still compiles many Rust crates and bundled SQLite. Allow extra time and disk; the exact cost depends on CPU, compiler, and cache. See [benchmarks](development/benchmarks.md) for measured builds.

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
sh ./install.sh v0.1.1
```

```powershell
# Windows, after checking install.ps1 against the release SHA256SUMS:
& .\install.ps1 -Version v0.1.1
```

Omit the version to select the newest published release, including a pre-release. An optional second POSIX argument or `-InstallDir` PowerShell argument chooses another user-owned directory. By default the binary goes to `~/.local/bin` on Linux and macOS or `%LOCALAPPDATA%\IRMind\bin` on Windows. If it is outside `PATH`, the script prints the path to add manually.

CI also produces test artifacts on relevant nightly runs; these are not GitHub Releases. Pull requests and merges to `main` do not publish binaries. Apple notarization and Windows Authenticode are not available yet, so those systems may still warn after verification.

## Linux

Use a terminal compatible with xterm, such as GNOME Terminal or Konsole. The `os` backend needs Secret Service through D-Bus; it may be unavailable over SSH. Select `file` explicitly for a headless session. Local files and directories are restricted to the current user with Unix `0600` and `0700` permissions.

## macOS

Use Terminal.app or iTerm2. The `os` backend uses Keychain; the `file` backend is available for explicit SSH use. CI targets Apple Silicon. After verifying the release, Gatekeeper may block a downloaded binary without Apple code signing. Allow **that binary only** in System Settings → Privacy & Security, or remove only its quarantine attribute with `xattr -d com.apple.quarantine ./irmind`. Never disable Gatekeeper system-wide.

## Windows

Use Windows Terminal and the x64 MSVC build. The `os` backend uses Credential Manager; `file` is available when it is explicitly selected. IRMind checks that local case files and the encrypted store are restricted to the current user's SID. SmartScreen or corporate antivirus may warn about a binary without Authenticode. Verify the checksum, Sigstore identity, and provenance, then request a narrow exception from your security team if policy allows it. Do not disable protection globally.

## Data and terminal behavior

Without `--home`, data goes to the platform's standard local application-data directory: XDG on Linux, Application Support on macOS, and LocalAppData on Windows. Evidence names are lower-case hashes; paths stored in the audit and export use relative `/` separators. SQLite holds the audit and case state; signed Parquet artifacts provide derived graph queries.

The TUI uses the alternate screen and sanitizes external text before display. Automated tests cover control sequences and bidirectional controls on all three systems. Visual interaction still needs manual review in each terminal before production use. Over SSH, request a terminal (`ssh -t`), select `file` during setup, and enter the passphrase in the masked TUI field. Backend changes are explicit; IRMind never falls back silently. `verify-export` can run without unlocking a keystore.
