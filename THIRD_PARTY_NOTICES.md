# Third-party notices

IRMind is licensed under `MIT OR Apache-2.0`. Dependencies retain their own licenses. `Cargo.lock` records their versions, and `deny.toml` lists permitted license expressions.

## Contributor Covenant 3.0

`CODE_OF_CONDUCT.md` and `CODE_OF_CONDUCT.es.md` are adapted from [Contributor Covenant 3.0](https://www.contributor-covenant.org/version/3/0/), stewarded by the Organization for Ethical Source. Copyright remains with its contributors. The text is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); our adaptations and Spanish translation retain that license. This notice does not change the license of IRMind's code.

## HuntEval public episode fixture

`crates/parser-json/tests/fixtures/hunteval-aws-iam-001.json` is copied from
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

## `option-ext` 0.2.0

`option-ext` is licensed under [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/). It is included in a larger work without changing the license of IRMind's own code. The source for the used version is available on [crates.io](https://crates.io/crates/option-ext/0.2.0) and in its [repository](https://github.com/soc/option-ext). Its files retain MPL-2.0 and are not relicensed under IRMind's license.

Before a formal external binary release, generate and review complete third-party notices for the exact published version, including the bundled SQLite component. `cargo-deny` checks permitted license expressions but does not replace that notices review.
