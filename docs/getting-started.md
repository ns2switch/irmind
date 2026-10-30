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

On Windows, run `.\target\release\irmind.exe` in Windows Terminal. When a CI artifact is available, you may instead download it and check `SHA256SUMS` before use. See [platforms](platforms.md) for system-specific steps. Builds are currently unsigned.

## First launch

Running `irmind` without a subcommand opens the TUI. The first-run wizard explains why cases are signed and lets you choose `os` or `file` separately for signing and module secrets. Use Up/Down and Enter to choose each backend; unavailable options appear dimmed with a reason and cannot be selected. Both backends are compiled by default; IRMind never switches between them silently. The wizard preselects `file` when the system keyring is unavailable. It asks for the file passphrase twice in masked fields inside the TUI, checks its length, and works through an interactive SSH terminal without a graphical session. Esc goes back; Ctrl+C asks before exiting. On first use IRMind creates an analyst signing key and shows its public-key fingerprint. Save the fingerprint through a separate trusted channel. A lost key cannot be recovered from a case export.

If unlocking fails, the wizard shows an actionable reason and lets you retry or choose another backend. A wrong passphrase never exits the TUI. Unexpected startup errors point to the private `diagnostics.log` in the data directory. The chosen backends are stored in `keystore.toml`. Type `/keystore` to see the selection and fingerprint, manage credentials, change the file passphrase, or migrate. Secret entry stays masked inside the TUI. Replacing a credential leaves already-created connectors using the old value; type `/restart` to restart the session.

The normal build compiles all current product modules and both keystores, but enables no LLM or connector. The optional first-run “AI model” step, or `/model` later, offers Ollama local, OpenAI-compatible, Anthropic, DeepSeek, and OpenRouter. Ollama checks `http://127.0.0.1:11434` and lists installed models; if unavailable, start it with `ollama serve` and retry. For a remote provider, enter its URL, model, and masked API key. “Test connection” sends synthetic text only. Enabling remote data transfer requires explicit signed confirmation. Type `/modules` to see compiled and enabled modules. Select with arrows, use Tab for public fields, `/edit-param` to edit, and `/keystore` for credentials. The session reloads after an approved change.

After the first run, IRMind normally reopens the most recently used open case after verifying its custody chain. A sealed, deleted, or invalid case takes you to the home screen; an invalid chain also shows a warning. Use `/home` to see all cases or `/config` to turn automatic resumption off. The home screen has no separate search field: type plain text in its bottom input to filter titles, or use `/cases all|open|sealed|inconsistent` to filter by status. Up/Down selects a case and Enter opens it.

`/new` starts with a required title and a severity list (Medium is selected by default). Enter creates a local case. Tab reaches the optional remote-scope step, where each source, account, project, host, object prefix, and UTC bound has a visible field and inline validation. A scope above the organization policy ceiling is rejected before creation. `/modules` groups readable module names by type; its detail pane shows technical IDs, editable public parameters, missing credential names, and the feature needed by an uncompiled module. `/model`, `/modules`, and `/keystore` open centered dialogs; Esc returns home.

![Home screen with recent cases and one bottom input for search and commands](assets/home.png)

If `config.toml` needs recovery, the TUI offers restoration or a field-by-field review before any case opens. Session flags and environment overrides that change destinations are shown and require confirmation; rejecting them uses the saved settings.

## A synthetic first case

1. Type `/new`, enter a title such as “Demo CloudTrail alert,” select a severity, and leave remote source fields empty. That creates a local-only case with a signed event.
2. In the case view, enter `/ingest` and select [the synthetic CloudTrail file](../examples/cloudtrail-alert.json). IRMind hashes it in place and writes a derived Parquet index. The original is copied only if you explicitly use `/ingest --copy-original <path>`.
3. Use `/timeline` or `/graph` to inspect the indexed events. `/search <words>` finds matching JSON records. Use `/raw <hash> <index>` to inspect one indexed record.
4. Type `/model` to select and test a model as described in [configuration](configuration.md). The session reloads without exiting IRMind. Open the case and ask: “What does the synthetic AssumeRole event suggest?”
5. Review proposed calls in the conversation. Enter sends. Type `/` for command suggestions or press `Ctrl+K` for the palette. `/pause` or Esc cancels an active task.
6. Run `/verify <source-root>` to check the original bytes, review `/report`, and use `/seal` and `/export` only after checking the displayed case hash and signing-key fingerprint.

The export can be checked on a second computer with `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. See the [CLI reference](development/cli.md) for automation.

## Navigate the case

The conversation fills the case workspace. The opening card shows the case, model, and signing backend. Tool proposals, approvals, results, and findings appear in order. Long results start folded with a one-line summary. `/sidebar` shows or hides case panels. Tab moves from the prompt to the conversation and through visible panels; Esc returns. Use `Ctrl+O` to expand a selected result. On a selected approval, use Up/Down and Enter, or type 1/2/3 followed by Enter to approve, deny with a reason, or edit arguments.

Graph queries and local searches also appear as result cards. Select a card and press Enter or `Ctrl+O` to expand it, then scroll within the conversation.

For large Parquet cases, add `--from=<UTC> --to=<UTC>`, `--account=<ID>` or `--project=<ID>`, and `--region=<NAME>` to `/search`, `/entity`, `/neighbors`, `/entity-timeline`, or `/path`. For example, `/search AssumeRole --from=2026-10-28T12:00:00Z --to=2026-10-28T13:00:00Z --account=123456789012 --region=eu-west-1` reads only matching partitions and timestamps. Both UTC bounds are required together, and the filter must remain inside the case scope. A neighbor card explicitly says when its 4,096-record sample is partial.

With a configured SIEM, `/siem-alert` retrieves one scoped alert by ID. The result appears as a guarded, foldable card in the same conversation. `/help` shows the argument order.

![Conversation showing a synthetic CloudTrail case and a streaming model reply](assets/conversation.png)

PgUp/PgDn scroll the focused view. New model text follows the end only while you are there. Up/Down recall prompts when the input is empty. `/help` lists every command and the reserved keys. Printable characters always enter the input field; no letter executes a shortcut. Mouse wheel scrolling is enabled by default. To keep terminal text selection, set `mouse_capture = false` in [configuration](configuration.md) and accept the file change in the TUI.

![Slash-command menu with commands and descriptions above the input field](assets/command-menu.png)

An external lookup waits for a signed approval. The card shows the exact arguments and the synthetic evidence fragment that supplied the tainted value.

![Approval card showing an external lookup, its arguments, and the tainted source fragment](assets/approval-card.png)

## Next

Use [configuration](configuration.md) for scopes, policy, backends, and credential names. Use [modules](modules.md) for connector permissions and limitations, and [platforms](platforms.md) for SSH notes. The TUI is the primary workflow; subcommands serve automation.
