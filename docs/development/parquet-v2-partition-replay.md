# Source-bound partition replay

This page explains source-bound profile routing during mixed-parser reconstruction. The optional callback is backward compatible and does not change signed bytes.

## Why the source must reach the profile router

Ingestion receives one selected parser. Reconstruction receives `RebuildParser`, which resolves different signed parsers for different source names. Its existing parsing, identity and random-access callbacks receive the source name. The approved `partition_profile(record)` callback does not.

For a case containing JSON cloud data and Linux endpoint data, forwarding that callback without the source cannot select the signed parser. Defaulting to `Unpartitioned` breaks reconstruction hashes. Remembering the last source in shared mutable state would introduce a race. Guessing the parser from the normalized JSON inside the storage adapter would break module ownership.

## Approved compatible addition

Keep the approved callback unchanged and add a source-aware optional companion:

```rust
fn partition_profile_for_source(
    &self,
    _source: &str,
    record: &GraphRecord,
) -> Result<PartitionProfile, AppError> {
    Ok(self.partition_profile(record))
}
```

Native parsers keep their current implementation. Only `RebuildParser` overrides the companion, looks up the exact signed source parser and delegates to it. An unknown source is an error. The batch coordinator calls the checked companion. No additional dependency, credential, format, capability or permission is introduced.

Add a reconstruction regression with two signed source parsers using different profiles. Worker ordering, cancellation and historical builder replay remain covered separately.
