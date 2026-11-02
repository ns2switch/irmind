# JSON ordering and custody compatibility

This page is for maintainers changing JSON dependencies or parser features. It records which bytes are stable and how CI checks them. It does not introduce a new canonical format.

## Compatibility rule

Keep the existing encoding of every signed or reconstructed value. For a `serde_json::Value`, explicitly sort object keys recursively before serializing or performing bounded, order-sensitive extraction. This reproduces the lexical order of the historical default map. Preserve array order. Do not convert a typed structure to a sorted JSON object: its declared field order is already part of existing bytes. Keep original evidence and deliberately retained raw JSON unchanged.

| Boundary | Audit result and treatment |
| --- | --- |
| Domain manifests, approval challenges and migration records | Explicit tagged, length-prefixed fields and bounded ordered collections; no JSON map serialization. Keep their tags and field order. |
| Audit entries and operational chains | Explicit canonical byte encoders; JSON payloads are opaque signed strings. Typed event structures retain declaration order, and argument maps use `BTreeMap`. Never parse and rewrite historical payloads during verification. |
| Configuration, session overrides and parser-definition snapshots | Typed structures and `BTreeMap` fields. Keep declaration order and the existing JSON-to-hex snapshot envelope. The full approved configuration and definition remain signed. |
| Generic JSON and cloud parsers | Sort the normalized JSON tree before both bounded entity extraction and serialization. Sorting only at output would let the 32-entity cap depend on insertion order. Original source hashes remain hashes of the actual input bytes. |
| ECS and OCSF | Explicitly sort normalized objects and nested attributes. Sort the OCSF Parquet row representation before retaining a rejected sample. Limits and source precision remain unchanged. |
| DFIR and declarative parsers | Velociraptor, JSON Hayabusa, Chainsaw and plaso retain original record text. Typed declarative output keeps field order and raw original fields; mapped fields use `BTreeMap`. CSV Hayabusa serializes its ordered column map directly. EZTools sorts the generated wrapper and its column map. |
| Parquet generation and reconstruction | Ordered schemas, entity/relation vectors and explicit deterministic sorts. Embedded record JSON comes from the boundaries above. Artifact metadata uses the unchanged V1 domain encoder. Each generated Parquet hash is frozen in the format fixture. |
| Generated remote evidence | Sort parsed CrowdStrike/SentinelOne values, generated AWS responses and object-listing wrappers before encoding. Raw SIEM, TI and downloaded object bodies remain their original bytes; verification never normalizes them. |
| Seal file and exports | Sort only the generated seal-file `Value` before pretty serialization. V3 bundles and V4 headers/frames use typed structures and an ordered evidence map; preserve their field/frame order. Signed entry/operation payload strings remain opaque. |
| ContentGuard | Traverse JSON strings in explicit lexical key order so split-instruction detection retains its existing behavior with either map backend. No corpus, rule, redaction or signed identifier changes. |

## Golden verification

`crates/bin/tests/fixtures/formats-v1.json` was captured from the unchanged implementation before this correction. Fixed synthetic keys, case ID, clock and source modification times make it reproducible. It contains bytes and SHA-256 for nine parsers' normalized rows, source V1/V2 manifests, generated Parquet artifact envelopes (including their actual file hashes), signed configuration/definition operations, audit entries, the seal file and V3/V4 exports. It contains no real evidence or keys.

The normal Linux suite runs `format_goldens`. The additional `json_formats` job explicitly enables `serde_json/preserve_order` and runs the same test against the same checked-in bytes and hashes. It never regenerates or approves goldens. Features shown for build dependencies by `cargo tree` do not replace explicitly enabling the feature in the tested target's dependency graph.

Run locally with the project's pinned toolchain:

```sh
cargo nextest run -p irmind -E 'binary(format_goldens)' --all-features --locked
cargo nextest run -p irmind -E 'binary(format_goldens)' --all-features --features serde_json/preserve_order --locked
```

A changed historical golden is a custody compatibility decision, not a fixture refresh. Stop for analyst review rather than updating expected values to pass CI. New parsers must use typed/ordered serialization or explicit lexical object sorting from their first release.
