# Runtime date dependency maintenance notices

The locked runtime graph contains two dependencies currently classified as
unmaintained by the RustSec advisory database. The existing dependency policy
rejects both notices. This document changes no policy and applies no exception.

| Dependency | Advisory | Runtime paths |
| --- | --- | --- |
| `chrono 0.4.45` | [RUSTSEC-2026-0543](https://github.com/RustSec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md) | Direct timestamp parsing/formatting in IRMind, Arrow 59 and Parquet 59, and object storage. |
| `humantime 2.4.0` | [RUSTSEC-2026-0542](https://github.com/RustSec/advisory-db/blob/main/crates/humantime/RUSTSEC-2026-0542.md) | `object_store 0.13.2`, through the bounded vendored storage implementation. |

Both database entries have `informational = "unmaintained"` and no patched
version. They concern maintenance status; their text does not describe a concrete
exploit in IRMind. See also the [upstream maintenance announcement](https://github.com/chronotope/chrono/issues/1768).
This classification does not establish that all future findings are harmless.

## Option A: narrowly scoped maintenance exceptions

Keep the locked versions and consider the following explicit exceptions in the
root policy, with no global change to advisory handling:

```toml
[advisories]
ignore = [
    { id = "RUSTSEC-2026-0543", reason = "Maintenance notice: chrono remains required by the pinned Arrow/Parquet runtime; replace it when a supported upstream graph permits removal." },
    { id = "RUSTSEC-2026-0542", reason = "Maintenance notice: humantime remains required by the bounded object_store runtime; remove this exception with that dependency." },
]
```

This is an explicit reduction of the maintenance gate for these two IDs, not a
runtime fix. All other advisories, registry restrictions, licenses and dependency
checks retain their current enforcement. There is no exception for a subsequent
vulnerability, even in either crate. Timestamp validation, bounds, canonical
bytes, custody and isolation remain unchanged. The exceptions must be removed
when their dependencies leave the runtime graph; they are not a permanent
blanket acceptance of unmaintained dependencies.

Before integration, validate the exact policy with `cargo deny check` and repeat
the existing native CI and current-format vectors. The implementation does not
select this option merely to obtain a passing check.

## Option B: remove the affected dependencies first

Replacing first-party uses of `chrono` alone does not resolve the gate: Arrow,
Parquet and object storage also depend on it. Removing `humantime` requires an
upstream storage change or a reviewed modification to the vendored runtime.
Neither advisory offers a version-only upgrade that resolves its classification.

The locked main graph already contains `time 0.3.55` through AWS dependencies,
but making it a direct replacement is a separate dependency and timestamp
semantics decision. A migration must retain validated UTC handling, precision,
stable ordering and current canonical vectors. It must include the transitive
Arrow/Parquet and storage paths, rather than silently excluding their advisories.
An upstream upgrade or maintained replacement also needs license, dependency,
containment and release validation. Until that work is complete, the current
policy continues blocking publication.

## Current validation boundary

The v0.5.3 candidate's full Linux workspace test step passed, including its updated
versioned UI snapshots. Its dependency-advisory check subsequently failed on the
two IDs above. That result does not constitute a passing native release matrix;
no release tag is justified by this document alone.
