# Legacy peers in common co-observations

This design is for evidence-store maintainers reviewing the new common schemas. It concerns only `irmind-coobservations-v3`; it does not change historical V1/V2 artifacts.

## Measured duplication

The [initial paired release run](benchmarks/common-core-initial-run.json) ingested 15,685,651,146 synthetic cloud bytes. The candidate wrote 16,517,884,858 Parquet bytes, including 12,712,715,750 co-observation bytes. Its `co_entities` column used 3,774,870,954 compressed bytes and `co_observations` used 6,636,243,859. The bridge emitted no typed roles: both columns described the same legacy entity pairs, with the second repeating unspecified scope/role markers.

This candidate took 1,374.256 seconds against the unchanged 900-second ingestion gate. The matched baseline also missed that gate at 947.159 seconds. Candidate cloud entity lookup reached its deadline in all five samples. The other completed pairs and failures remain in the results; these measurements do not establish a complete matrix or a default-writer gate.

## Adopted representation

- Keep the physical columns, V2 envelope, logical common-event encoding, code table, seal and V5 framing.
- Keep every role-free `(kind, value)` pair in `co_entities`.
- Store only typed role/field/scope observations in `co_observations`. An unclassified bridge record stores `[]` there.
- A reader combines typed descriptors with legacy pairs not represented by a typed `(kind, value)` key. Legacy peers retain the current unspecified-identity rules. Same-value observations with different typed roles or scopes remain distinct before node deduplication.
- Continue reading a complete descriptor list as well as the sparse representation. Reject invalid descriptors rather than falling back around an error.

This removes a redundant encoding, not evidence or a permission check. The measured 6.636 GB column is an upper bound on avoidable compressed payload in this unclassified corpus; replacement pages, metadata and changed batch packing have not been measured. No ingestion-time or latency saving is claimed before implementation and remeasurement. Typed source mappings will have their own descriptor costs.

## Compatibility and validation

Only the new common co-observation physical goldens change. Historical goldens, parser output, logical common JSON and code-table goldens stay frozen. The common builder has not shipped in a release or been enabled in normal ingestion. Both the initial complete descriptor lists and the new sparse lists remain readable. Reconstruction for the reviewed common builder uses the sparse representation.

Required tests compare the complete logical peer sets before/after encoding for legacy-only records, mixed typed/legacy records, same-value roles, namespace collisions and PID reuse. Retain field/role validation, event deduplication, the 4,096-record sample, neighbor/hop/expansion/deadline limits, partial markers, hash-before-read, cancellation and rollback. Verify exact reconstruction and V5 exports. Repeat the three-repetition 1 GiB smoke and full 15 GB matrix with unchanged gates before changing a default.

This does not approve removing event times, replacing record references with integer indices, semantic migration or the co-observation-by-reference work tracked in [issue #37](https://github.com/ns2switch/irmind/issues/37).
