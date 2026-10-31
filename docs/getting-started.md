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

On Windows, run `.\target\release\irmind.exe` in Windows Terminal. For a release binary, check `SHA256SUMS`, its Sigstore bundle, and GitHub provenance before use. The v0.1.0 pre-release has only checksums; see [platforms](platforms.md) for the exact version-dependent steps.

## Try it in five minutes

After installing, run `irmind demo`. You can also type `/demo` from the home screen. This starts an isolated temporary case with a small synthetic HuntEval episode, ephemeral signing keys, and a scripted model. No API key, passphrase, account, or network is needed. If a local Ollama model is available and advertises tool support, IRMind offers it as an optional local choice.

The case opens while its bundled evidence is ingested. Ask what happened in the synthetic episode. The scripted model proposes a graph lookup, a finding, and a simulated external lookup. The external lookup still waits for your signed approval, but never reaches a real service. Confirm the proposed finding and type `/demo check` for a local comparison with the episode answers; those answers are loaded only for this check and never sent to a model. Exit with `/quit` and confirm. The temporary case, keys, and evidence are deleted. IRMind then points you to `/new` and `/settings` for normal use.

## First launch

Running `irmind` without a subcommand opens the TUI. The first-run wizard explains why cases are signed and lets you choose `os` or `file` separately for signing and module secrets. Use Up/Down and Enter to choose each backend; unavailable options appear dimmed with a reason and cannot be selected. Both backends are compiled by default; IRMind never switches between them silently. The wizard preselects `file` when the system keyring is unavailable. It asks for the file passphrase twice in masked fields inside the TUI, checks its length, and works through an interactive SSH terminal without a graphical session. Esc goes back; Ctrl+C asks before exiting. On first use IRMind creates an analyst signing key and shows its public-key fingerprint. Save the fingerprint through a separate trusted channel. A lost key cannot be recovered from a case export.

If unlocking fails, the wizard shows an actionable reason and lets you retry or choose another backend. A wrong passphrase never exits the TUI. Unexpected startup errors point to the private `diagnostics.log` in the data directory. The chosen backends are stored in `keystore.toml`. Type `/settings keystore` to see the selection and fingerprint, manage credentials, change the file passphrase, or migrate. Secret entry stays masked inside the TUI. Replacing a credential leaves already-created connectors using the old value; type `/restart` to restart the session.

The normal build compiles all current product modules and both keystores, but enables no LLM or connector. The optional first-run “AI model” step, or `/settings model` later, offers local Ollama, LM Studio, and vLLM, plus approved remote presets. Ollama checks `http://127.0.0.1:11434`; if unavailable, start it with `ollama serve` and retry. Remote setup asks for a URL and masked API key, then asks before listing models or testing with synthetic text. Enabling remote case-data transfer requires separate signed confirmation. Type `/settings connectors` to see compiled and enabled modules. Select with arrows, use Tab and Enter to edit public fields, or open `/settings keystore` for credentials. The session reloads after an approved change.

![Settings navigation with Model, Connectors, Keystore, and Preferences sections](assets/settings.png)

![AI model setup dialog with a list of providers and an option to configure one later](assets/model.png)

After the first run, IRMind normally reopens the most recently used open case after verifying its custody chain. A sealed, deleted, or invalid case takes you to the home screen; an invalid chain also shows a warning. Use `/home` to see all cases or `/settings preferences` to turn automatic resumption off. On the home screen, type plain text in the bottom input to filter titles, or use `/cases all|open|sealed|inconsistent` to filter by status. Up/Down selects a case and Enter opens it.

![Verified recent case reopened with a Resumed notice and the case conversation input](assets/resumed.png)

`/new` starts with a required title and a severity list (Medium is selected by default). Enter creates a local case. Tab reaches the optional remote-scope step, where each source, account, project, host, object prefix, and UTC bound has a visible field and inline validation. A scope above the organization policy ceiling is rejected before creation. `/settings connectors` groups readable module names by type; its detail pane shows technical IDs, editable public parameters, missing credential names, and the feature needed by an uncompiled module. `/settings model`, `/settings connectors`, and `/settings keystore` open centered dialogs; Esc returns to settings.

![New case dialog with a title field, severity choices, and optional remote scope](assets/new.png)

![Grouped module view with readable names, status, public settings, and credential presence](assets/modules.png)

![Keystore settings showing separate signing and secrets backends and credential presence without values](assets/keystore.png)

![Preferences settings for recent-case resumption, mouse capture, and theme](assets/preferences.png)

The offline screenshot fixture lists two illustrative modules; the normal build includes all current product modules.

![Home screen with a recent case list and one input for filtering or slash commands](assets/home.png)

If `config.toml` needs recovery, the TUI offers restoration or a field-by-field review before any case opens. Session flags and environment overrides that change destinations are shown and require confirmation; rejecting them uses the saved settings.

## A synthetic first case

1. Type `/settings model` to choose and test a provider in the TUI, or skip it to work with local evidence only. See [configuration](configuration.md) for the provider choices.
2. Type `/new`, enter a title such as “Demo CloudTrail alert,” and select a severity. Press Enter to create a signed local case; the remote scope is optional.
3. Type `/ingest` and select [the synthetic CloudTrail file](../examples/cloudtrail-alert.json). IRMind hashes it in place and writes a derived Parquet index. It copies the original only if you explicitly use `/ingest --copy-original <path>`.
4. Ask “What does the synthetic AssumeRole event suggest?” and press Enter. The response appears incrementally. Use `/timeline` or `/graph` to inspect indexed events and `/search <words>` to find matching records.
5. Review tool proposals in the conversation. An external lookup requires a signed approval with numbered options; use the arrows and Enter. Type `/` for command suggestions or press Ctrl+K for the palette. If a model limit stops the turn, use `/continue` after reviewing the summary.
6. Run `/verify <source-root>` to check original bytes, review `/report`, and use `/seal` and `/export` only after checking the displayed case hash and signing-key fingerprint.

The export can be checked on a second computer with `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. See the [CLI reference](development/cli.md) for automation.

## Navigate the case

The conversation fills the case workspace. The opening card shows the case, model, and signing backend. Tool proposals, approvals, results, and findings appear in order. Long results start folded with a one-line summary. `/sidebar` shows or hides case panels. Tab moves from the prompt to the conversation and through visible panels; Esc returns. Use `Ctrl+O` to expand a selected result. On a selected approval, use Up/Down and Enter, or type 1/2/3 followed by Enter to approve, deny with a reason, or edit arguments.

Graph queries and local searches also appear as result cards. Select a card and press Enter or `Ctrl+O` to expand it, then scroll within the conversation.

For large Parquet cases, add `--from=<UTC> --to=<UTC>`, `--account=<ID>` or `--project=<ID>`, and `--region=<NAME>` to `/search`, `/entity`, `/neighbors`, `/entity-timeline`, or `/path`. For example, `/search AssumeRole --from=2026-10-28T12:00:00Z --to=2026-10-28T13:00:00Z --account=123456789012 --region=eu-west-1` reads only matching partitions and timestamps. Both UTC bounds are required together, and the filter must remain inside the case scope. A neighbor card explicitly says when its 4,096-record sample is partial.

With a configured SIEM, `/siem-alert` retrieves one scoped alert by ID. The result appears as a guarded, foldable card in the same conversation. `/help` shows the argument order.

![Case conversation with a synthetic CloudTrail question and a model reply appearing incrementally](assets/conversation.png)

PgUp/PgDn scroll the focused view. New model text follows the end only while you are there. Up/Down recall prompts when the input is empty. `/help` lists every command and the reserved keys. Printable characters always enter the input field; no letter executes a shortcut. Mouse wheel scrolling is enabled by default. To keep terminal text selection, set `mouse_capture = false` in [configuration](configuration.md) and accept the file change in the TUI.

![Slash-command menu listing available commands and descriptions above the case input](assets/command-menu.png)

An external lookup waits for a signed approval. The card shows the exact arguments and the synthetic evidence fragment that supplied the tainted value.

![Numbered approval card for a VirusTotal lookup showing exact arguments and a highlighted untrusted evidence fragment](assets/approval-card.png)

## Next

Use [configuration](configuration.md) for scopes, policy, backends, and credential names. Use [modules](modules.md) for connector permissions and limitations, and [platforms](platforms.md) for SSH notes. The TUI is the primary workflow; subcommands serve automation.
