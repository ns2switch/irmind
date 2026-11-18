# Compressed FDR admission

Design proposal. [Español](../es/development/fdr-compressed-admission.md).

## Reproduction

The synthetic `fdr_gzip_admission_characterization` integration test runs with
`cargo test -p irmind --release --test identity_ingest fdr_gzip_admission_characterization -- --ignored --nocapture`.
It repeats a native-shaped ProcessRollup2 record 150,000 times without padding.

| Encoding | Physical bytes | Decoded bytes | Records | Result |
| --- | ---: | ---: | ---: | --- |
| JSONL | 69,150,000 | 69,150,000 | 150,000 | Ingested and signed verification passed |
| gzip | 954,510 | 69,150,000 | 150,000 | Normalized staging allowance exhausted; no artifact committed |

This is a release-build admission characterization, not a throughput benchmark.
The current default reservation is `physical_bytes * 16 + 64 MiB`: 82,381,024
bytes for this gzip. It bounds the normalized row stream, so a compressed source
can exhaust it even though the equivalent plain source fits. This is distinct
from insufficient free disk. The input remains unchanged and the failed group
rolls back. The current CompactFlow32 exception belongs only to VPC Flow Logs.

## Proposed closed profile

Add `NormalizedExpansionProfile::DecodedJson16`, initially used only by the
FDR decoder. It returns `decoded_bytes * 16 + 64 MiB` through the already optional
`SourceDecoder::normalized_source_budget`; no new port is needed. For the
synthetic source above the allowance would be 1,173,508,864 bytes, identical to
its plain-text allowance. CompactFlow32 and every other decoder remain unchanged.

Before any normalization, a read-only, cancellable pass counts decoded gzip
bytes, validates all concatenated members and their CRC, and rejects compressed
or decoded input above 50 GiB. No decoded evidence is written in this pass.
Existing case-local staging, private permissions, group free-space and scratch
reservation, runtime row/total budgets, rollback, source hash recheck, parser
limits and canonical ordering remain mandatory. The return value never changes
signed bytes or grants a remote capability.

Tests cover equal plain/gzip/concatenated-member allowance, invalid/truncated CRC,
cancellation, the 50 GiB boundary, no preflight writes, and successful ingestion
of this same gzip followed by reconstruction/seal/export verification. A no-space
case must fail before normalizing. Allocation overflow remains an error.

## Alternative

Keep the current allowance and document that large gzip sources may need explicit
external decompression before ingestion. This adds no admission profile, but
leaves valid FDR archives unavailable through the requested direct gzip route.
