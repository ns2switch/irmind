# Add a parser or connector

This guide is for contributors adding a data format or an external product to IRMind. Start with synthetic data and keep every change behind the existing application ports.

## Before you start

Read the [architecture](architecture.md), [security model](../security-model.md), and [contribution rules](../../CONTRIBUTING.md). A parser processes attacker-controlled bytes. A connector handles credentials and can transmit case data. Neither may bypass the policy, signed audit log, guard, or TLS verification.

## Add a parser

1. Choose a source format and link its official schema in the pull request. Put the parser in `crates/parser-json` when it is a profile of JSON; propose a new parser crate only when the format needs a distinct decoder.
2. Implement `EventParser` and, for large files, `StreamingEventParser`. Emit `Tainted<GraphRecord>` with a typed `Provenance` pointing to the source record. Validate timestamps, field sizes, nesting depth, and record count. Check `CancellationToken` between records or batches.
3. Map source fields to normalized events and deterministic entities. Preserve the original bytes as evidence. Keep source parsing separate from model-facing text; the guard processes text when it is shown or sent to the model.
4. Add small synthetic fixtures for valid, malformed, truncated, and hostile records. Include each supported provider variant and a test for deterministic ordering. Never commit real incident logs.
5. Run the parser tests, graph reconstruction and verification tests, Clippy, and `cargo-deny`. Document supported versions, missing fields, limits, and an example in [modules](../modules.md).

## Add a connector

1. Pick an existing port (`SiemPort`, `EdrPort`, `CloudAuditPort`, `ThreatIntelPort`, or `ObjectSource`). Discuss a new port before adding one. The [SIEM template](../../crates/module-template/src/lib.rs) compiles and passes `run_siem_contract`; it is synthetic and is not registered in the binary.
2. Define a `ModuleManifest` with an ID, port, tools, and configuration fields. Put non-secret settings in `config.toml`; declare secret fields for `SecretBackend`. The composition root injects secrets through `ModuleConfig`. The module must never read environment variables or a key store.
3. Implement the port's single async `execute` method. Accept only `AuthorizedCall`, check the exact tool and source, respect `CancellationToken`, and bound requests and responses. Use HTTPS with host verification, no redirects, and an explicit timeout. Never put credentials, URLs with secrets, or evidence in errors or tracing.
4. Keep product-specific query construction inside the adapter. Translate structured, policy-scoped fields into the product dialect with escaped values. Do not execute model-supplied free-form query text.
5. Run the matching contract suite in `irmind-testkit`. Add recorded synthetic success, failure, cancellation, wrong-source, response-size, and TLS tests. Review that every remote call remains reachable only through the generic authorized dispatch path.
6. Add a Cargo feature and registration in the composition root, leaving the module disabled until configured. Document minimum read-only permissions, setup, risks, and limits in [modules](../modules.md) and its Spanish translation.

## Compile the template

```sh
cargo test -p irmind-module-template --locked
```

The template demonstrates the manifest, `SiemPort`, cancellation, source checks, and the shared contract suite without a network call. Replace its synthetic response only after the adapter has bounded HTTP and recorded-response tests. A production connector also needs the HTTP safety contract.

Before opening a pull request, run `cargo fmt --all -- --check`, Clippy with `-D warnings`, the changed crates' tests, and `cargo deny check`. Use `git commit -s` for every commit.
