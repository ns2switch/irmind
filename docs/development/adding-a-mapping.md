# Add a source mapping

A decoder preserves source fields and provenance. A separately identified mapping
interprets those fields as validated common events. Start with [the module guide](adding-a-module.md)
and the [current mapping inventory](../mappings.md); do not add interpretation to a parser.

1. Select an existing `SourceDecoder`, its dataset/channel and exact supported
   versions. Add a small synthetic `SourceRecordV1` fixture. Missing facts stay
   missing; absent outcomes are `unknown`.
2. Prefer a bounded TOML table under `crates/modules/mapping-<family>/src/`.
   Use [sshd.toml](../../crates/modules/mapping-linux/src/sshd.toml) and
   [the table contract](mapping-tables.md). The current interpreter accepts only
   closed operations, typed paths, finite result tables and declared selectors.
   No expressions, scripts, network, clock or implicit text classification.
3. Give the mapping an ID, version, target schema and disjoint source selectors.
   Pin bundled definition hashes in the module's build. Installed definitions
   require the normal signed admission. Overlapping active selectors are errors.
4. Use validated domain constructors for categories, types, outcomes, roles and
   namespaces. Identical strings in different accounts, hosts or clusters must
   not merge accidentally. A PID is not a process lifetime: only documented
   lifetime identifiers such as Sysmon ProcessGuid justify `process_lifetime`.
5. Cover success, failure, absent status, actor versus target, the same value in
   two roles, namespaces, PID reuse and hostile field values. Include mapping
   contract tests, deterministic bytes, source-to-artifact reconstruction and
   a synthetic investigation episode. Never put evaluator ground truth in evidence.
6. Register the module with its feature and update both language inventories.
   Use native Rust only for bounded logic the tables cannot express, explaining
   why. Keep extraction-only coverage when a semantic mapping is incomplete.

Run the affected module's tests, app/domain contracts, fmt, strict Clippy and
`preserve_order` coverage. New dependencies, ports or signed formats require a
separate design decision. Mapping content is untrusted and grants no permissions.
