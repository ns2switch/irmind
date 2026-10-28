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
3. Use `/timeline` or `/graph` to inspect the indexed events. `/search <words>` finds matching JSON records in this case. Use `/evidence <hash>` to view an original record.
4. Return to the home screen, press `m`, and choose a model and its public settings as described in [configuration](configuration.md). The session reloads without exiting IRMind. Open the case and ask: “What does the synthetic AssumeRole event suggest?”
5. Review proposed calls in the conversation. Enter sends; Alt+Enter or Shift+Enter adds a line. Type `/` for command suggestions or press `Ctrl+K` for the palette. `/pause` or Esc cancels an active task.
6. Run `/verify`, review `/report`, and use `/seal` and `/export` only after checking the displayed case hash and signing-key fingerprint.

The export can be checked on a second computer with `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. See the [CLI reference](development/cli.md) for automation.

## Navigate the case

The conversation fills the case workspace. Tool proposals, approvals, results, and findings appear as cards in order. `Ctrl+B` shows or hides the case sidebar. Tab cycles its timeline, evidence, approvals, and finding views. Use `Ctrl+L` to focus the conversation and `Ctrl+I` to return to the prompt. Enter or Space expands a selected card; `a`, `d`, and `e` act on a selected approval.

Graph queries and local searches also appear as result cards. Long results start folded; select a card and press Enter or Space to expand it, then scroll within the conversation.

With a configured SIEM, `/siem-alert` retrieves one scoped alert by ID. The result appears as a guarded, foldable card in the same conversation. `/help` shows the argument order.

![Conversation showing a synthetic CloudTrail case and a streaming model reply](assets/conversation.png)

PgUp/PgDn and Ctrl+U/Ctrl+D scroll the focused view. Home/End or `g`/`G` in the conversation move to the start/end. New model text follows the end only while you are there; End clears the new-content indicator. Up/Down recall prompts. `/help` or `?` lists commands and shortcuts. Mouse wheel scrolling is enabled by default. To keep terminal text selection, set `mouse_capture = false` in [configuration](configuration.md) and accept the file change in the TUI.

![Slash-command menu with commands and descriptions above the input field](assets/command-menu.png)

An external lookup waits for a signed approval. The card shows the exact arguments and the synthetic evidence fragment that supplied the tainted value.

![Approval card showing an external lookup, its arguments, and the tainted source fragment](assets/approval-card.png)

## Next

Use [configuration](configuration.md) for scopes, policy, backends, and credential names. Use [modules](modules.md) for connector permissions and limitations, and [platforms](platforms.md) for SSH notes. The TUI is the primary workflow; subcommands serve automation.
