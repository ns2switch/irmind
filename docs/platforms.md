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

Download the binary for your system and `SHA256SUMS` from the [GitHub release](https://github.com/ns2switch/irmind/releases). Check the exact binary name in the checksum file before executing it. The first pre-release, v0.1.0, has only checksums; later releases will add signed bundles and provenance. A checksum alone checks the downloaded bytes against that file, not the publisher's identity.

| System | Check |
| --- | --- |
| Linux | Run `sha256sum -c SHA256SUMS` in the downloaded asset directory. |
| macOS | Run `shasum -a 256 -c SHA256SUMS` in that directory. |
| Windows PowerShell | Compare `(Get-FileHash .\irmind.exe -Algorithm SHA256).Hash.ToLowerInvariant()` with the line for `irmind.exe` in `SHA256SUMS`. |

The source tree contains [install.sh](../install.sh) and [install.ps1](../install.ps1). Starting with a release that attaches these scripts, download the script and its matching `SHA256SUMS` and verify the script's checksum before running it. The scripts detect your system, verify the selected binary's checksum, and, when installed, use `cosign` and `gh` to verify its signature and provenance. A failed check stops the installation. They never request administrator privileges or change `PATH`.

```sh
# Linux or macOS, after checking install.sh against the release SHA256SUMS:
sh ./install.sh v0.1.1
```

```powershell
# Windows, after checking install.ps1 against the release SHA256SUMS:
& .\install.ps1 -Version v0.1.1
```

Omit the version to select the newest published release, including a pre-release. An optional second POSIX argument or `-InstallDir` PowerShell argument chooses another user-owned directory. By default the binary goes to `~/.local/bin` on Linux and macOS or `%LOCALAPPDATA%\IRMind\bin` on Windows. If it is outside `PATH`, the script prints the path to add manually.

CI also produces unsigned artifacts on release tags and relevant nightly runs. Pull requests and merges to `main` do not publish binaries. Apple notarization and Windows Authenticode are not available yet, so those systems may still warn after verification.

## Linux

Use a terminal compatible with xterm, such as GNOME Terminal or Konsole. The `os` backend needs Secret Service through D-Bus; it may be unavailable over SSH. Select `file` explicitly for a headless session. Local files and directories are restricted to the current user with Unix `0600` and `0700` permissions.

## macOS

Use Terminal.app or iTerm2. The `os` backend uses Keychain; the `file` backend is available for explicit SSH use. CI targets Apple Silicon. After verifying the checksum, Gatekeeper may block the unsigned downloaded binary. Allow **that binary only** in System Settings → Privacy & Security, or remove only its quarantine attribute with `xattr -d com.apple.quarantine ./irmind`. Never disable Gatekeeper system-wide.

## Windows

Use Windows Terminal and the x64 MSVC build. The `os` backend uses Credential Manager; `file` is available when it is explicitly selected. IRMind checks that local case files and the encrypted store are restricted to the current user's SID. SmartScreen or corporate antivirus may warn about an unsigned binary. Verify the checksum and provenance, then request a narrow exception from your security team if policy allows it. Do not disable protection globally.

## Data and terminal behavior

Without `--home`, data goes to the platform's standard local application-data directory: XDG on Linux, Application Support on macOS, and LocalAppData on Windows. Evidence names are lower-case hashes; paths stored in the audit and export use relative `/` separators. SQLite holds the audit and case state; signed Parquet artifacts provide derived graph queries.

The TUI uses the alternate screen and sanitizes external text before display. Automated tests cover control sequences and bidirectional controls on all three systems. Visual interaction still needs manual review in each terminal before production use. Over SSH, request a terminal (`ssh -t`), select `file` during setup, and enter the passphrase in the masked TUI field. Backend changes are explicit; IRMind never falls back silently. `verify-export` can run without unlocking a keystore.
