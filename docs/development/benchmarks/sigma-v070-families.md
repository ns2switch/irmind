# Local Sigma evaluator benchmark

Optimized Cargo release profile on Linux x86-64. The synthetic corpus has one independently known incident and one unsupported test rule per reviewed class. Each parquet row preserves its typed projection and synthetic source fields. Time measures rule compilation and scanning separately. Corpus generation, signing, export and source acquisition are outside these measurements.

| Source family | Classes | Parquet bytes | Rules | Evaluated | Skipped | True positives | False positives | Compile (s) | Scan (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CloudTrail | 1 | 18,665,665 | 31 | 30 | 1 | 1 | 0 | 0.000 | 0.010 |
| Windows EVTX | 24 | 455,348,608 | 744 | 720 | 24 | 24 | 0 | 0.000 | 0.533 |
| Linux auth, auditd and ECS | 10 | 188,262,232 | 310 | 300 | 10 | 10 | 0 | 0.000 | 0.126 |
| Zeek and Suricata | 7 | 131,704,100 | 217 | 210 | 7 | 7 | 0 | 0.000 | 0.089 |
| Cloud identity and Kubernetes | 13 | 244,873,580 | 410 | 397 | 13 | 13 | 0 | 0.000 | 0.218 |
| Defender, FDR and eslogger | 9 | 170,575,496 | 288 | 279 | 9 | 9 | 0 | 0.000 | 0.191 |

The combined run used 64 classes, 2,000 rules and 1,209,429,681 physical Parquet bytes. It found all 64 incidents and no false positives in the family corpora. The elapsed test was 3.94 s, including synthetic fixture generation. Each class scan evaluated one representative field. Binding fixtures separately exercise the other admitted fields.

In the independently pinned projection benchmark on 1,205,321,238 Parquet bytes, the common-field scan took 0.985 s and read 117,680,585 bytes. The original-field scan took 1.854 s and read 1,205,083,841 bytes. Each lane evaluated 950 rules and skipped 50. The original-field lane reported one intentional false positive at record 8224. The broad rule `original-0000` matched the literal `LegacyEvent=legacy-signal` in a benign event with `event.action=background`. The fixture and the matcher agree.

```sh
cargo test -p irmind-infra --locked --release --features sigma --lib -- --ignored --nocapture sigma_reviewed_families_2000_rules_on_one_gib_parquet
cargo test -p irmind-infra --locked --release --features sigma --lib -- --ignored --nocapture sigma_2000_rules_on_one_gib_parquet
```
