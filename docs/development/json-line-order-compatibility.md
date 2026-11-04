# JSON line ordering: compatibility decision required

This note is for the analyst reviewing artifact V2 partitions in [PR #170](https://github.com/ns2switch/irmind/pull/170). It describes a reproduced historical reconstruction defect. It is a proposal, not authorization to alter existing normalized records.

## Finding

`parser-json` identifies itself as `json-stream-v2`. Its whole-document `RecordSink::accept` explicitly calls `sort_all_objects()` after normalization. Its `parse_reader_report` fast path does not. The fast path handles NDJSON and newline-terminated single-object JSON.

Consequently, enabling `serde_json/preserve_order` changes the normalized `GraphRecord.text` produced from identical source bytes. Bounded entity extraction also traverses maps, so a fix must preserve the historical traversal and extraction caps when replaying old cases; sorting only the final text is insufficient.

The source manifest pins the parser version, not the dependency feature that selected map iteration order. This affects historical V1 artifacts as well as the new partitioned V2 builder. The approved source-aware partition callback does not cause this defect.

## Reproduction and evidence

The new synthetic inputs are in `crates/testkit/fixtures/artifact-v2-partitions/`. The new test `partitioned_parquet_physical_bytes_and_envelopes_are_portable` compares actual artifact bytes and envelopes with one explicit lexical-order fixture. No existing golden has been changed.

Run the same format test normally and with the alternate feature:

```sh
cargo nextest run -p irmind --all-features \
  -E 'test(partitioned_parquet_physical_bytes_and_envelopes_are_portable)'
cargo nextest run -p irmind --all-features --features serde_json/preserve_order \
  -E 'test(partitioned_parquet_physical_bytes_and_envelopes_are_portable)'
```

The first passes and the second fails. The workspace-wide all-features graph also enables the feature and fails this new regression. Historical goldens still pass because their wrapped-document inputs take the already sorted path.

For the supplied `b.json` synthetic cloud source, all source bytes and source SHA-256 values remain identical. A temporary local diagnostic decoded both generated event files and confirmed the only difference in this record is object key order:

```text
Lexical:   awsRegion, eventName, eventTime, recipientAccountId, sourceIPAddress
Insertion: eventTime, eventName, recipientAccountId, awsRegion, sourceIPAddress
```

| Writer | Lexical-order event SHA-256 | Insertion-order event SHA-256 |
| --- | --- | --- |
| Historical V1 | `87c852208cfe1a67633e3dd4489729f9e6728fb7dfdf35ddc261f7dd9c1f4dab` | `33f0fdd406bd762d5d39c3134515c4c158c94445b3b02147cb9eca5f6a44be6a` |
| Partitioned V2 | `45e33a90dfbb9c2ceb3ce87f11a6ddb504948afbaca7e0d4ce639aeccd19a52d` | `abdf34c5ae1e309a54235ab26d8aa24350b50c8240d4c86481329de11fb967ff` |

Across the two sources, enabling the feature changes 2 of 9 historical V1 artifacts and 3 of 12 partitioned V2 artifacts. Entity and co-observation artifact hashes match in this small fixture. That observation does not establish that extraction is order-independent for inputs reaching the extraction cap.

## Proposed correction, pending analyst approval

1. Give new JSON ingests an explicitly canonical parser version. Normalize and recursively order maps before both extraction and normalized-text serialization, independently of the compiled serde map representation. Keep existing source bytes, signature encodings and historical goldens unchanged.
2. Keep historical `json-stream-v2` reconstruction compatible with both observed fast-path interpretations. Implement feature-independent lexical and insertion-order readers inside the JSON module, with the original validation, extraction caps and whole-document behavior. Retained artifacts remain readable without rewriting them.
3. During historical reconstruction, accept an interpretation only when it reproduces the complete signed artifact set for that source/generation, including hashes, counts and envelopes. Do not select from an unsigned assumption about the build. If neither matches, fail verification. Do not treat matching one artifact as permission to ignore the others.
4. Do not reinterpret a historical source as the new parser version automatically. A later explicit migration must prove the approved non-time semantic equivalence and record its replacement parser version through the approved migration operation. Retain the old generation.
5. Exercise both dependency-feature graphs against identical golden bytes for the new parser. Exercise historical lexical and insertion-order cases separately, including nested maps, oversized extraction sets, bad records, cancellation and negative hash checks. Keep this currently failing regression; do not add feature-dependent expected hashes or disable a gate.

No new dependency is proposed. Any additional change needed to an agreed port must be published and approved separately before application. The proposal does not authorize changing a signed wire encoding.

## Work blocked by the decision

Generic partition preparation, source-bound replay and bounded external ordering are implemented in the draft. Step (c) cannot be declared reproducible or merged while the new golden depends on the dependency feature graph. Migration/export V5 and default TUI V2 writing remain deferred. The requested decision is approval of the canonical new JSON version and strict hash-matched historical replay, before implementing either.
