# Local Sigma evaluator V2 benchmark

Optimized Cargo release profile on Linux x86-64 with Rust 1.97.1. The synthetic corpus has one independently known incident and one unsupported test rule per reviewed class. This measures rule compilation and scanning. Corpus generation, signing, export and source acquisition are excluded from those timings.

| Source family | Field lane | Classes | Parquet bytes | Rules | Evaluated | Skipped | True positives | False positives | Compile (s) | Scan (s) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CloudTrail | common | 1 | 19,914,996 | 31 | 30 | 1 | 1 | 0 | 0.000 | 0.011 |
| Windows EVTX | common | 24 | 485,825,750 | 744 | 720 | 24 | 24 | 0 | 0.000 | 0.511 |
| Linux auth, auditd and ECS | common | 10 | 200,862,950 | 310 | 300 | 10 | 10 | 0 | 0.000 | 0.126 |
| Zeek and Suricata | common | 7 | 140,519,287 | 217 | 210 | 7 | 7 | 0 | 0.000 | 0.084 |
| Cloud identity and Kubernetes | original | 13 | 198,188,305 | 410 | 397 | 13 | 13 | 0 | 0.000 | 0.288 |
| Defender, FDR and eslogger | original | 4 | 81,652,657 | 128 | 124 | 4 | 4 | 0 | 0.000 | 0.084 |
| Defender, FDR and eslogger | common | 5 | 100,767,959 | 160 | 155 | 5 | 5 | 0 | 0.000 | 0.103 |

The combined run used 64 classes, 2,000 rules and 1,227,731,904 physical Parquet bytes. It found all 64 incidents with zero false positives in this corpus. The test took 3.67 s including synthetic fixture generation. Each class scan evaluated one representative field. Binding fixtures exercise all admitted fields separately.

The separate projection benchmark on 1,205,321,238 Parquet bytes measured 0.814 s and 117,680,585 bytes read for common fields, and 1.510 s and 1,205,083,841 bytes read for original fields. Each lane evaluated 950 rules and skipped 50. Rule `original-0000` intentionally matched `LegacyEvent=legacy-signal` in benign record 8224 with `event.action=background`, giving one false positive in the original-field lane.

```sh
cargo test -p irmind-infra --locked --release --features sigma --lib -- --ignored --nocapture sigma_reviewed_families_2000_rules_on_one_gib_parquet
cargo test -p irmind-infra --locked --release --features sigma --lib -- --ignored --nocapture sigma_2000_rules_on_one_gib_parquet
```
