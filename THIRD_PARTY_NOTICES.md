# Third-party notices

IRMind is licensed under `MIT OR Apache-2.0`. Dependencies retain their own licenses. `Cargo.lock` records their versions, and `deny.toml` lists permitted license expressions.

## Contributor Covenant 3.0

`CODE_OF_CONDUCT.md` and `CODE_OF_CONDUCT.es.md` are adapted from [Contributor Covenant 3.0](https://www.contributor-covenant.org/version/3/0/), stewarded by the Organization for Ethical Source. Copyright remains with its contributors. The text is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); our adaptations and Spanish translation retain that license. This notice does not change the license of IRMind's code.

## HuntEval public episode fixture

`crates/modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json` is copied from
[`ns2switch/HuntEval`](https://github.com/ns2switch/HuntEval), commit
`4cbb555a56bc17cb03b988ad2f15b1374eecf183`, path
`datasets/aws/aws-iam-001/source/events.json`, SHA-256
`f3bb0e0b52d86b5760dd69163479d3eeb4e97b1e6e81ab922127aa8d2646831d`.
Copyright 2026 Aníbal Cañada. Licensed under Apache-2.0; see the upstream
[`LICENSE`](https://github.com/ns2switch/HuntEval/blob/4cbb555a56bc17cb03b988ad2f15b1374eecf183/LICENSE).
`crates/bin/src/demo/expected.json` contains only the event IDs, entity IDs,
and technique IDs needed for the offline demo check, derived from the same
episode's `private/ground-truth.json`. It is parsed only when `/demo check`
runs. The full ground-truth file is not included; the external evaluator
downloads and verifies it only when it runs.

## HuntEval Azure and GCP skill fixtures

The skill integration suite reuses two small synthetic source episodes and their
separately stored evaluator answers from the same Apache-2.0 HuntEval commit above.
Copyright 2026 Aníbal Cañada. The public episode fixtures are copied unchanged to
`crates/testkit/fixtures/skills-expanded/azure-entra-identity-compromise/source/hunteval.json`
and `crates/testkit/fixtures/skills-expanded/gcp-service-account-abuse/source/hunteval.json`.
Evaluator answers live only under `crates/testkit/fixtures/skills-expanded/private/`.
They are not packaged as skills, ingested as evidence or sent to the model.

| Upstream path | SHA-256 |
| --- | --- |
| `datasets/azure/azure-iam-001/source/events.json` | `6eae0dadfb042e9beeed048d5ee8e84daa727d0e0d204ccf46def638c2dea6ad` |
| `datasets/azure/azure-iam-001/private/ground-truth.json` | `316fa58dfbd4cc5555c8a9b9d03b5f260219e5efb67d8da38364aecb6cf335d3` |
| `datasets/gcp/gcp-iam-001/source/events.json` | `9f5dc4a91c5b7347062107c2021224e1fd48bde5145304f4e0e9558269333452` |
| `datasets/gcp/gcp-iam-001/private/ground-truth.json` | `9b7246483efb1734b54558b0aa8df4d52c58785c1167232c4937a6f1137ec81d` |

## `option-ext` 0.2.0

`option-ext` is licensed under [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/). It is included in a larger work without changing the license of IRMind's own code. The source for the used version is available on [crates.io](https://crates.io/crates/option-ext/0.2.0) and in its [repository](https://github.com/soc/option-ext). Its files retain MPL-2.0 and are not relicensed under IRMind's license.

Before a formal external binary release, generate and review complete third-party notices for the exact published version, including the bundled SQLite component. `cargo-deny` checks permitted license expressions but does not replace that notices review.

## EVTX decoding helper

The separately resolved `irmind-evtx` executable uses the official `evtx` 0.15.1 crate (MIT OR Apache-2.0), maintained at https://github.com/omerbenamram/evtx. Its dependencies and native-code audit are distributed with the helper SBOM. The small EVTX fixtures in `crates/testkit/fixtures/parser-evtx` are generated from synthetic events by `scripts/generate_evtx_fixture.py`; they contain no collected incident data.

## winstructs GUID-only subset

The isolated EVTX helper uses a reviewed GUID-only subset of
[winstructs 0.3.2](https://github.com/omerbenamram/winstructs), by Omer Ben-Amram
and Matthew Seyer, under its MIT OR Apache-2.0 license. The retained parsing,
serialization and error files are unchanged; unused NTFS, security and timestamp
modules are omitted. The official EVTX decoder is unchanged. The verified source
archive and file hashes are recorded in
[the provenance manifest](helpers/evtx/vendor/winstructs/UPSTREAM.json), with
[the upstream license](helpers/evtx/vendor/winstructs/LICENSE).


## Reviewed Arrow and Parquet source patches

IRMind includes the published Apache `arrow-array` 59.3.2 and `parquet` 59.3.0
sources under `vendor/`, with calendar dependency substitutions. Both are
Apache-2.0, copyright The Apache Software Foundation. Their original
`LICENSE.txt` and `NOTICE.txt`, archive checksums, original file hashes and local
patch hashes accompany the sources. See each directory's `IRMIND_PATCH.md` and
`UPSTREAM.json`. The Arrow umbrella is replaced by the same versioned array,
schema, select and ordering components; no local Arrow cast patch is required.

## Email syntax library

The experimental email decoder uses [mail-parser 0.11.9](https://github.com/stalwartlabs/mail-parser)
from Stalwart Labs, with optional features disabled, and its compile-time
[hashify 0.2.9](https://github.com/stalwartlabs/hashify) dependency. Both declare
`Apache-2.0 OR MIT`; their source notices and licenses remain their own. IRMind
uses the headers-only parser and bounded transport decoding, with its own MIME
traversal and source limits. These dependencies do not supply network or execution
capabilities to evidence. Release SBOMs record the exact resolved packages.
