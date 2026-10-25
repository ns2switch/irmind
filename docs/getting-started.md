# Getting started

This guide is for analysts evaluating IRMind with synthetic data. It takes you from installation to a first local case. Read the [security model](security-model.md) before connecting a real service.

> IRMind is under development. Do not use it for real incidents or sensitive data.

## Install

The recommended internal path is a source build. Install Rust 1.95.0, a supported terminal, and a native system keyring. Then run:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
./target/release/irmind
```

On Windows, run `.\target\release\irmind.exe` in Windows Terminal. You may instead download a CI binary and check `SHA256SUMS` before use. See [platforms](platforms.md) for system-specific steps. Builds are currently unsigned.

## First launch

Running `irmind` without a subcommand opens the TUI. The first-run view checks the keyring, creates an analyst signing key when none exists, and shows the public-key fingerprint. Save that fingerprint through a separate trusted channel. IRMind cannot recover a lost signing key and will stop if the keyring is unavailable.

Press `m` to see which modules are compiled, enabled, and configured. No LLM is enabled automatically. Local case work remains available without a model.

## A synthetic first case

1. Press `n`, enter a title such as “Demo CloudTrail alert,” select a severity, and leave remote source fields empty. That creates a local-only case with a signed event.
2. In the case view, enter `/ingest` and select [the synthetic CloudTrail file](../examples/cloudtrail-alert.json). The original file is hashed and retained locally.
3. Use `/timeline` or `/graph` to inspect the indexed events. Use `/evidence <hash>` to view an original record.
4. If you have approved a provider, select it as described in [configuration](configuration.md), restart IRMind, open the case, and ask: “What does the synthetic AssumeRole event suggest?”
5. Review any proposed call before approval. `/pause` cancels an active task; `/help` and `Ctrl+K` show actions.
6. Run `/verify`, review `/report`, and use `/seal` and `/export` only after checking the displayed case hash and signing-key fingerprint.

The export can be checked on a second computer with `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. See the [CLI reference](development/cli.md) for automation.

## Next

Use [configuration](configuration.md) for scopes, policy, and keyring accounts. Use [modules](modules.md) for connector permissions and limitations. The TUI is the primary workflow; subcommands serve automation.
