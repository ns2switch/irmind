# JSON serialization compatibility

This page is for maintainers changing parser implementations or JSON dependency features. It defines the supported serialization contract and release-build checks.

## Release audit

The [machine-readable audit](release-json-feature-audit.json) checks the locked build graph for every shipped target from v0.1.0 through v0.1.5: 23 graphs. None enables `serde_json/preserve_order`. Each tagged workflow builds `cargo build --release -p irmind --locked`; the audit uses that package, default features and target, excluding development dependencies.

In workspace tests, the AWS connector's development-only `aws-smithy-http-client/test-util` enables insertion-ordered JSON. Release dependency graphs exclude that utility. Every release-build job checks the shipped normal/build graph before compiling the binary.

## Supported serialization

`json-stream-v2` uses explicit recursive lexicographic object ordering before extraction and serialization on all supported input paths. Array order is preserved. The same bytes and hashes must result with either serde map implementation. Original evidence and deliberately retained raw JSON remain unchanged. Insertion-dependent development artifacts are outside the supported reconstruction contract.

## Parser coverage

| Parser | Representation | Compatibility checks |
| --- | --- | --- |
| JSON | Recursively ordered normalized objects | NDJSON, single objects, documents, nested objects/arrays and bounded extraction |
| ECS | Fixed extraction and recursively ordered normalized maps | Historical normalized, manifest and Parquet bytes |
| OCSF | Fixed extraction and recursively ordered normalized maps | Historical bytes and native Parquet conversion |
| Velociraptor, Chainsaw, plaso | Typed fields and retained original input | Historical bytes for each module |
| Linux journald | Typed normalized fields and retained raw input | Historical normalized, manifest and Parquet bytes |
| Declarative | Ordered mappings and retained RawValue | Historical bytes |

The `format_goldens` suite runs on the normal test graph and explicitly with `preserve_order`. It reuses the same checked-in fixtures. Add equivalent coverage when another JSON parser is integrated. See [the format rules](json-format-order.md) for reproduction commands.
