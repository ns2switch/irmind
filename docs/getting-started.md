# Getting started

This guide is for analysts evaluating IRMind with synthetic data. It takes you from installation to a first local case. Read the [security model](security-model.md) before connecting a real service.

> IRMind is under development. Do not use it for real incidents or sensitive data.

## Install

The recommended internal path is a source build. Install Rust 1.95.0 and a supported terminal. An OS keyring is optional if you explicitly select the encrypted-file backend. Then run:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
./target/release/irmind
```

On Windows, run `.\target\release\irmind.exe` in Windows Terminal. You may instead download a CI binary and check `SHA256SUMS` before use. See [platforms](platforms.md) for system-specific steps. Builds are currently unsigned.

## First launch

Running `irmind` without a subcommand opens the TUI. Choose `os` or `file` separately for signing and module secrets. Both backends are compiled by default; IRMind never switches between them silently. The file backend asks for a passphrase without echo and works through an interactive SSH terminal without a graphical session. On first use IRMind creates an analyst signing key and shows its public-key fingerprint. Save the fingerprint through a separate trusted channel. A lost key cannot be recovered from a case export.

If the selected backend is unavailable, startup stops and the TUI offers an explicit new selection. The chosen backends are stored in `keystore.toml` inside the data directory. Press `k` on the home screen to see the selection and fingerprint, manage module credentials, change the file passphrase, or migrate. Replacing a credential leaves already-created connectors using the old value; press `r` in the keystore view to restart the session.

Press `m` to see which modules are compiled, enabled, and configured. Use the arrow keys to select a module, Tab to select a public field, and `e` to edit its value. Enter selects an LLM or toggles a connector. Press `k` to reach its credentials in the keystore. A change that may send data off this computer asks for signed confirmation. The TUI reloads the session after applying a change. No LLM is enabled automatically.

If `config.toml` needs recovery, the TUI offers restoration or a field-by-field review before any case opens. Session flags and environment overrides that change destinations are shown and require confirmation; rejecting them uses the saved settings.

## A synthetic first case

1. Press `n`, enter a title such as “Demo CloudTrail alert,” select a severity, and leave remote source fields empty. That creates a local-only case with a signed event.
2. In the case view, enter `/ingest` and select [the synthetic CloudTrail file](../examples/cloudtrail-alert.json). The original file is hashed and retained locally.
3. Use `/timeline` or `/graph` to inspect the indexed events. Use `/evidence <hash>` to view an original record.
4. Return to the home screen, press `m`, and choose a model and its public settings as described in [configuration](configuration.md). The session reloads without exiting IRMind. Open the case and ask: “What does the synthetic AssumeRole event suggest?”
5. Review any proposed call before approval. `/pause` cancels an active task; `/help` and `Ctrl+K` show actions.
6. Run `/verify`, review `/report`, and use `/seal` and `/export` only after checking the displayed case hash and signing-key fingerprint.

The export can be checked on a second computer with `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. See the [CLI reference](development/cli.md) for automation.

## Next

Use [configuration](configuration.md) for scopes, policy, backends, and credential names. Use [modules](modules.md) for connector permissions and limitations, and [platforms](platforms.md) for SSH notes. The TUI is the primary workflow; subcommands serve automation.
