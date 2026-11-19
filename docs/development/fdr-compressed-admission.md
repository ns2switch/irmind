# Compressed FDR admission

Implemented in the FDR ingestion pipeline. [Español](../es/development/fdr-compressed-admission.md).

## Admission and reservation

`DecodedJson16` applies only to `parser-fdr/fdr-source-v1`. VPC Flow Logs use
`CompactFlow32`. Extending the decoded JSON profile to ALB, S3 access logs,
CloudTrail gzip or any other decoder requires separate approval.

The first pass opens the original for reading, caps physical and decoded
input at 50 GiB, and validates the CRC and size trailer of every gzip member.
It counts through a reusable 16 KiB buffer with bounded decompressor state.
It does not materialize or spool decoded bytes. For plain JSONL, the original
file length supplies the count without a full extra read.

The count sets the normalized ceiling (`decoded_bytes × 16 + 64 MiB`). The
coordinator then checks available case disk space against the complete group
reservation, including scratch and safety margin, before any normalization.
If disk space is insufficient, the error shows the required and available
bytes. The ceiling does not reserve any physical space by itself.

During normalization, the reader takes at most the admitted bytes plus one
byte to detect expansion. Crossing that ceiling aborts the source. The
original-byte hash check still runs independently before publication of a
successful ingestion. Case-local staging, rollback and order checks continue
to apply.

## Verification

A regression test appends a valid gzip member to the open original after
preflight and requires both the decoder and the parallel ingestion path to
stop at the earlier decoded ceiling. The integration test also checks spool cleanup.
Another test counts 64 MiB across two members using the fixed buffer, then
checks that a truncated final trailer fails. The integration test verifies
reconstruction, sealing and export against the compressed original and
rejects a later modification on reconstruction.

The release benchmark uses the same 1 GiB decoded corpus for JSONL and gzip.
The [measurements](benchmark-data/fdr-gzip-v055.json) include end-to-end
ingestion and a separately timed gzip preflight. Gzip takes 68.323 s versus
71.877 s for JSONL in this single pair. The extra gzip pass takes 0.289 s
when measured separately. Both ingestions verify successfully.

```sh
cargo test -p irmind --release --test identity_ingest one_gib_release_fdr_gzip_and_jsonl -- --ignored --nocapture
```
