# Local Sigma evaluator V2 benchmark

Cargo release profile on Linux x86-64 with Rust 1.97.1. The synthetic corpus contains 1,227,731,904 Parquet bytes across 64 enrolled source classes. Each class has one known positive and one deliberately unsupported rule. Rules exercise one representative field per class. The companion binding test exercises every declared field with positive and negative controls.

Times are the sum of rule compilation and scan intervals for each class, reported separately. The test took 3.48 s including fixture generation. Signing and export are covered by the separate distribution test.

| Source family | Classes | Rules | Evaluated | Skipped | Expected positives | Detected positives | False positives | Compile (s) | Scan (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows Security | 17 | 527 | 510 | 17 | 17 | 17 | 0 | 0.005 | 0.343 |
| Windows Sysmon | 5 | 155 | 150 | 5 | 5 | 5 | 0 | 0.001 | 0.102 |
| Windows PowerShell | 2 | 62 | 60 | 2 | 2 | 2 | 0 | 0.001 | 0.040 |
| Linux auth, auditd and ECS | 10 | 310 | 300 | 10 | 10 | 10 | 0 | 0.003 | 0.122 |
| AWS CloudTrail | 1 | 31 | 30 | 1 | 1 | 1 | 0 | 0.000 | 0.010 |
| Zeek | 3 | 93 | 90 | 3 | 3 | 3 | 0 | 0.001 | 0.035 |
| Suricata | 4 | 124 | 120 | 4 | 4 | 4 | 0 | 0.001 | 0.047 |
| Entra ID and Azure Activity | 5 | 155 | 150 | 5 | 5 | 5 | 0 | 0.001 | 0.090 |
| Microsoft 365 | 2 | 63 | 61 | 2 | 2 | 2 | 0 | 0.001 | 0.037 |
| Okta | 1 | 32 | 31 | 1 | 1 | 1 | 0 | 0.000 | 0.018 |
| GCP Cloud Audit Logs | 1 | 32 | 31 | 1 | 1 | 1 | 0 | 0.000 | 0.018 |
| Kubernetes audit, EKS, AKS and GKE | 4 | 128 | 124 | 4 | 4 | 4 | 0 | 0.001 | 0.115 |
| Defender | 4 | 128 | 124 | 4 | 4 | 4 | 0 | 0.001 | 0.083 |
| CrowdStrike FDR | 3 | 96 | 93 | 3 | 3 | 3 | 0 | 0.001 | 0.056 |
| eslogger | 2 | 64 | 62 | 2 | 2 | 2 | 0 | 0.001 | 0.039 |
| **Total** | 64 | 2,000 | 1,936 | 64 | 64 | 64 | 0 | 0.018 | 1.157 |

### Common and original fields

| Field lane | Classes | Rules | Evaluated | Skipped | Expected positives | Detected positives | False positives | Compile (s) | Scan (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Common | 47 | 1,462 | 1,415 | 47 | 47 | 47 | 0 | 0.014 | 0.799 |
| Original | 17 | 538 | 521 | 17 | 17 | 17 | 0 | 0.005 | 0.359 |

### Omitted rules

| Reason | Rules |
| --- | ---: |
| Logsource | 0 |
| Field | 64 |
| Syntax | 0 |
| Modifier | 0 |

For each source class, the benchmark asserts that the sole skipped rule is the deliberately synthetic `__synthetic_unmapped_field|exists` control and that the compiler returns `UnsupportedField`. It also asserts that the field does not appear in the class's reviewed table. No omission is due to a missing approved binding.

### Separate projection benchmark

The separate projection benchmark on 1,205,321,238 Parquet bytes measured 0.814 s and 117,680,585 bytes read for common fields, and 1.510 s and 1,205,083,841 bytes read for original fields. Each lane evaluated 950 rules and skipped 50. Rule `original-0000` matched `LegacyEvent=legacy-signal` in benign record 8224 with `event.action=background`, giving one expected false positive in the original-field lane.

### Signed distribution test

The release rehearsal separately requires signed CloudTrail and Sysmon cases. A Linux distribution binary imports and runs each synthetic rule, the test confirms the finding, publishes Markdown and PDF, seals and exports V10. The native macOS Intel, Apple Silicon and Windows binaries verify both packages and reject mismatched keys and tampered exports. [Distribution test and verification job](https://github.com/ns2switch/irmind/pull/412)

```sh
cargo test -p irmind-infra --locked --release --features sigma --lib -- --ignored --nocapture sigma_reviewed_families_2000_rules_on_one_gib_parquet
cargo test -p irmind-infra --locked --release --features sigma --lib -- --ignored --nocapture sigma_2000_rules_on_one_gib_parquet
```
