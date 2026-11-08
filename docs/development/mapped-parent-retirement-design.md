# Explicit retirement of inactive mapped parents

This proposal is for custody, storage and export maintainers. It describes a future opt-in way to reclaim inactive Parquet bytes while retaining their signed derivation metadata. It is not implemented by the common-event core or enabled as automatic cleanup.

## Measured motivation

The [paired release run](https://github.com/ns2switch/irmind/actions/runs/42507683653) measures retained parents separately. Its candidate is `43558055bfa5a1387e1001d5765aa2301748ad7e`, compared with `3acb485bb56b01a4e19b0e04c659c3f0c0edc4db` on each same Linux runner.

| 15 GB scenario | Inactive parent bytes | Active artifact bytes | Inactive / active | Inactive / retained case |
| --- | ---: | ---: | ---: | ---: |
| Endpoint, disordered, 1 host | 2,995,574,001 | 2,965,277,588 | 101.02% | 50.00% |
| Endpoint, disordered, 64 hosts | 2,875,824,016 | 2,966,572,824 | 96.94% | 48.97% |

The complete matrix and phase measurements belong in [benchmarks](benchmarks.md). This first completed scenario already exceeds the 20% planning threshold. Reclaiming these bytes must be a custody operation, not an unrecorded retention policy.

## Scope and invariants

Start with open cases only. A sealed case cannot acquire another case-chain entry; sealed retirement needs a separate design and is excluded here. Never delete active files, originals, envelopes, source sets, snapshots, profiles, mapping runs, layout receipts or the audit chain.

Only fully inactive V3 parent files with a complete verified path to retained active children are eligible. Authenticate the complete current chain, layout graph and candidate files first. All source sets, exact decoder/mapping identities and builder/partition policies required to regenerate them must remain addressable. Existing V1/V2 files are excluded.

Show the analyst the case, candidate count, bytes, ordered inventory commitment, affected sources, current chain head and analyst key fingerprint. Explain the reduced verification level and regeneration requirements. Require an attended analyst signature; the agent cannot approve or schedule this action. A case lock and a bound to the inspected head prevent a concurrent layout or ingestion from changing the selected inventory.

No disk-pressure fallback, automatic eviction or silent deletion is permitted.

## Proposed signed contract

A future `ParquetParentsRetiredV1` operation needs a new explicit audit kind and domain separator. Its proposed fields bind:

- The case and inspected chain head.
- Ordered complete canonical parent-envelope identities and paths, file SHA-256 values and expected sizes.
- A `u64` count, total bytes and a separate versioned ordered-set commitment.
- The retained active inventory and the existing layout receipts proving each parent's inactivity.
- An explicit verification-policy identifier stating that direct authentication of retired parent files is unavailable.

Keep the existing 1 MiB metadata frame limit. Large candidate inventories use bounded signed chunks with a final ordered count/commitment, rather than enlarging a frame. The final receipt must be derivable from the actual signed chunks; a supplied commitment alone is insufficient. Snapshot/profile/parser/builder identifiers retain their current meanings.

The operation changes retention state only. It does not replace a mapping receipt, reactivate a parent, alter a V3 envelope or reinterpret a historical source. Retired identities remain part of the retained envelope inventory and layout DAG.

## Crash-safe file lifecycle

Use an explicit signed intent followed by a completion receipt. Under the case lock, move authenticated candidate files into a private case-local quarantine on the same filesystem, fsync files/directories, and then atomically append the completion receipt and retention state. Only a complete receipt permits deletion from quarantine.

A crash before completion leaves recoverable intent/quarantine state. Startup reports it and verifies/restores the exact files or requests an explicit reconciliation; it never reports successful retirement silently. A crash after completion can leave physical garbage in quarantine, but cannot change which inventory was authorized for retirement. Cleanup is restricted to that completed inventory and records operational diagnostics.

Storage errors, cancellation and failed signing/audit transactions preserve the previous active generation. Never guess whether an absent file was intentionally retired. A missing file without the complete authorization remains a verification failure.

## Verification levels

| Check | After authorized retirement |
| --- | --- |
| Case-chain signatures and envelope commitments | Remain available. All envelopes and receipts are retained. |
| Layout graph and retained active-file SHA-256/schema checks | Remain available. Every retained active file is still authenticated before reading. |
| Direct SHA-256/physical-schema authentication of an inactive parent | **Unavailable** after its bytes are removed. Metadata signatures alone do not replace this check. |
| Full source/mapping/layout reconstruction | Available only if exact originals and all pinned local implementations remain available; it regenerates parents in dependency order and compares their recorded SHA-256 values before replaying children. |

Report the number/bytes of retired files and the requested verification level. Never label envelope authentication as complete historical file authentication or full reconstruction. Queries still use only the active generation; missing retired bytes do not justify dropping or widening a filter.

Reconstruction needs every involved original or byte-identical retained copy, the exact signed decoder and temporal context, the exact mapping definition/native implementation and target, and the recorded writer/partition/layout policies. A hash or native build snapshot is not executable code. Verification never downloads and executes an implementation.

A manifest-only source can disappear, an object version can become inaccessible, or a pinned implementation can be unavailable. Then complete historical reconstruction cannot be claimed; retain metadata/active-file authentication and an explicit unavailable status. Remote rereads remain subject to the existing read policy, organization ceiling, version pin and transfer budget. This proposal does not enable post-seal remote verification or ambient credentials.

Before confirmation, establish current source availability and explain that it is not a future retention guarantee. Display reconstruction disk/time estimates and any extra remote transfer. An analyst who needs independent historical authentication must retain the parent bytes or an earlier complete export.

## Export capability

Current export V6 requires all parent/child files and rejects omissions. Keep that behavior unchanged. Retirement therefore requires a future export capability, proposed as V7, with explicit retirement receipts and separate envelope/file inventories. A verifier recalculates the authorized omitted set from the signed chain, rejects every other missing or extra file, and authenticates every provided Parquet frame.

Seal inventory V2's canonical encoding can continue committing to all retained envelopes; no historical seal bytes change. New receipt handling and the export capability require their own golden review. Older readers must reject the new capability instead of presenting a partial check as complete.

## Required tests before implementation ships

Cover active/unknown-parent rejection; changed files; incomplete or duplicate retirement chunks; mismatched head/count/commitment; agent signatures; cancellation; every crash boundary; missing files without authorization; retained child tampering; V6 omission rejection; and public-key-only verification of the future explicit capability.

Regenerate retired parents from local originals and version-pinned synthetic cloud objects, then compare their complete bytes and replay all descendant layouts. Also test unavailable originals/implementations and a prior complete export that remains independently authenticatable. No retention control may weaken the existing query or custody limits.
