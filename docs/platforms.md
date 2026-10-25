# Platforms

This page is for people installing IRMind on Linux, macOS, or Windows. It covers build requirements, unsigned CI binaries, keyrings, and terminal behavior. Start with [getting started](getting-started.md) for the case workflow.

## Build from source

A source build is the recommended path for internal evaluation:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
```

CI tests Ubuntu Linux, macOS arm64, and Windows x64 with the MSVC toolchain. SQLite and DuckDB are built from bundled sources. Network TLS uses rustls with native certificate roots, including installed corporate CAs; IRMind does not link system OpenSSL. The native-root approach may differ from platform policy checks performed by a dedicated certificate verifier.

## CI artifacts and checksums

Each platform job publishes the binary, both project licenses, third-party notices, and `SHA256SUMS`. Download from a trusted CI run and compare the checksum **before** executing the file:

| System | Check |
| --- | --- |
| Linux | Run `sha256sum -c SHA256SUMS` in the extracted artifact directory. |
| macOS | Run `shasum -a 256 -c SHA256SUMS` in that directory. |
| Windows PowerShell | Compare `(Get-FileHash .\irmind.exe -Algorithm SHA256).Hash.ToLowerInvariant()` with the line for `irmind.exe` in `SHA256SUMS`. |

The binaries are not signed, notarized, or Authenticode signed. Their checksum proves correspondence with the chosen CI artifact, not the identity of a publisher. A decision on distribution signing is scheduled for review by 2027-04-24.

## Linux

Use a terminal compatible with xterm, such as GNOME Terminal or Konsole. The native Secret Service must be available through D-Bus; IRMind fails closed if the signing key cannot be stored or loaded. Local files and directories are restricted to the current user with Unix `0600` and `0700` permissions.

## macOS

Use Terminal.app or iTerm2. Signing keys live in Keychain. CI targets Apple Silicon. After verifying the checksum, Gatekeeper may block the unsigned downloaded binary. Allow **that binary only** in System Settings → Privacy & Security, or remove only its quarantine attribute with `xattr -d com.apple.quarantine ./irmind`. Never disable Gatekeeper system-wide.

## Windows

Use Windows Terminal and the x64 MSVC build. Signing keys live in Credential Manager. IRMind checks that local case files are restricted to the current user's SID. SmartScreen or corporate antivirus may warn about an unsigned binary. Verify the checksum and provenance, then request a narrow exception from your security team if policy allows it. Do not disable protection globally.

## Data and terminal behavior

Without `--home`, data goes to the platform's standard local application-data directory: XDG on Linux, Application Support on macOS, and LocalAppData on Windows. Evidence names are lower-case hashes; paths stored in the audit and export use relative `/` separators. Each case has a SQLite audit database and a DuckDB derived graph.

The TUI uses the alternate screen and sanitizes external text before display. Automated tests cover control sequences and bidirectional controls on all three systems. Visual interaction still needs manual review in each terminal before production use. There is no encrypted-file fallback if the native keyring is unavailable; `verify-export` can run without a local keyring.
