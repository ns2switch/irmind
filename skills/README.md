# Bundled forensic methods: pinned upstream copy

The source of these 15 data-only packages is
[ns2switch/irmind-skills/core](https://github.com/ns2switch/irmind-skills/tree/main/core).
Propose methodology, reference-data and synthetic-episode improvements there.
The upstream `catalog/` is separate: it contains optional community packages and
cannot replace a bundled name. Core packages arrive with an IRMind release.

[upstream.json](upstream.json) records the immutable upstream commit, every
canonical package commitment and the SHA-256 of each mirrored resource or
fixture. [package-identities.json](package-identities.json) and
[SHA256SUMS](SHA256SUMS) are local inventories checked against that pin. The
initial mirror preserves the exact package bytes embedded in v0.5.0.

## Review an upstream update

Check out the desired public commit of `ns2switch/irmind-skills` separately.
From the IRMind root, run:

```sh
python3 scripts/sync_core_skills.py <upstream-checkout> <full-40-character-commit>
python3 scripts/sync_core_skills.py
python3 scripts/test_sync_core_skills.py
```

The synchronizer reads only committed data blobs from that local checkout. It
performs no fetch or other network access. Review the package, fixture and pin
diff, run the shared compiler and scripted integration suite, and submit a normal
PR. Never edit the vendored packages alone or refresh hashes to bypass a mismatch.
The normal build uses only checked-in files; CI checks the pin without downloading
skills. Historical design documents explain earlier admission and format decisions.

Each package contains bounded methodology and reference data, without executable
code. All methods declare local reads and finding-proposal tools only. Policy,
case scope, approvals, taint and budgets still apply. Methodology is never evidence
or trusted system instructions. See the [analyst guide](../docs/skills.md) for
sources and coverage limits.

The scripted integration suite exercises ingestion, progressive loading, local
queries, analyst-confirmed findings, chain verification, sealing and independent
export verification. Hostile-evidence tests retain the obedient fake model.
Expected answers stay in evaluator-only fixtures outside packages, evidence and
model context. These tests validate integration and controls, not real-model
accuracy. All methodology is original project-licensed prose with primary-source
references.
