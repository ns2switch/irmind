# Sigma V2 and V3 source-class comparison

## Pinned SigmaHQ audit

The release-profile Linux audit used the same
[hash-pinned 3,302 files](sigmahq-v070-admission.md) and the expanded table
from [#433](https://github.com/ns2switch/irmind/pull/433). Both evaluators
used the current admission and compiler. Native mapping recipes expanded
to deterministic fixture identities, as in the earlier audit. Each file
ran in a separate process with 512 MiB of address space and two-second
CPU and elapsed limits. No evidence was used and no file exceeded those
process limits or panicked. Only aggregate counts are published.
[SigmaHQ release](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01).

Of 3,302 files, 3,301 passed admission. V2 compiled 1,159 for every
applicable class. V3 kept all of those and compiled 976 more for at
least one applicable class. The remaining 1,166 admitted rules had
no eligible class. V3 admitted 4,555 rule/class pairs, compared with
2,893 in V2. V3 omitted 5,780 applicable pairs for missing bindings
and 59 for type incompatibility. The slowest call was 128.8 ms for
V2 admission and planning and 107.0 ms for V3 planning. These are
coverage and planning results. They do not estimate detection
accuracy on case evidence.

The ten most frequent missing bindings, counting each field once per
affected admitted rule, were `OriginalFileName` (502), `ParentImage` (324),
`CommandLine` (154), `Image` (135), `ParentCommandLine` (78),
`Description` (67), `cs-uri-query` (62), `Product` (47), `Hashes` (41)
and `Initiated` (41).

The table groups by logsource product, or by service or category
when the product is absent. V3 columns describe rules that passed
admission and have all, some or no eligible classes within that
scope.

| Family | Files | Admitted | V2 | V3 all | V3 some | V3 none | V3 eligible pairs | Missing binding | Incompatible type |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `aws` | 42 | 42 | 33 | 33 | 0 | 9 | 33 | 8 | 0 |
| `azure` | 123 | 123 | 1 | 1 | 0 | 122 | 2 | 152 | 4 |
| `bitbucket` | 12 | 12 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| `category/antivirus` | 9 | 9 | 0 | 0 | 0 | 9 | 0 | 0 | 0 |
| `category/database` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `category/dns` | 10 | 10 | 9 | 9 | 0 | 1 | 18 | 2 | 0 |
| `category/firewall` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `category/proxy` | 51 | 51 | 0 | 0 | 0 | 51 | 0 | 0 | 0 |
| `category/webserver` | 83 | 83 | 0 | 0 | 68 | 15 | 68 | 138 | 1 |
| `cisco` | 12 | 12 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| `django` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `fortigate` | 7 | 7 | 0 | 0 | 0 | 7 | 0 | 0 | 0 |
| `fortios` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `gcp` | 25 | 25 | 0 | 0 | 0 | 25 | 0 | 14 | 0 |
| `github` | 9 | 9 | 0 | 0 | 0 | 9 | 0 | 0 | 0 |
| `jvm` | 5 | 5 | 0 | 0 | 0 | 5 | 0 | 0 | 0 |
| `kubernetes` | 9 | 9 | 0 | 0 | 1 | 8 | 3 | 17 | 0 |
| `linux` | 183 | 183 | 0 | 0 | 98 | 85 | 213 | 267 | 0 |
| `m365` | 18 | 18 | 2 | 2 | 0 | 16 | 2 | 3 | 0 |
| `macos` | 52 | 52 | 1 | 1 | 0 | 51 | 1 | 51 | 0 |
| `nodejs` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `okta` | 20 | 20 | 12 | 12 | 0 | 8 | 12 | 8 | 0 |
| `opencanary` | 24 | 24 | 0 | 0 | 0 | 24 | 0 | 0 | 0 |
| `paloalto` | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| `python` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `rpc_firewall` | 17 | 17 | 0 | 0 | 0 | 17 | 0 | 0 | 0 |
| `ruby_on_rails` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `service/apache` | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| `service/nginx` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `spring` | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| `sql` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `velocity` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `windows` | 2554 | 2553 | 1098 | 1098 | 809 | 646 | 4200 | 5116 | 54 |
| `zeek` | 21 | 21 | 3 | 3 | 0 | 18 | 3 | 4 | 0 |

## Paired mixed-source benchmark

Release-profile Linux on the same machine. The deterministic corpus
has 270,000 synthetic rows and 1,269,940,394 bytes of uncompressed
Parquet across Sysmon, Defender and FDR process-creation classes.
It includes a 4 KiB padding column outside the read projection.
Each run plans all 2,000 rules. Of these, 1,936 deliberately exercise
missing bindings. The `Image` control matches all three classes.
The `ParentImage` rule has two known positives on sources with the
reviewed exact path. FDR supplies no equivalent full path. Each
evaluator uses the same scan deadline, work budget and exact row
projection. Timing covers planning and scanning of prepared
artifacts. Peak RSS covers each benchmark process, including
fixture generation.

| Evaluator | Planning | Scan | Eligible rules | Eligible pairs | Detected / known | False positives | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V2 | 33.9 ms | 949.0 ms | 63 | 189 | 3/5 | 0 | 25,936 KiB |
| V3 | 13.6 ms | 988.5 ms | 64 | 191 | 5/5 | 0 | 25,900 KiB |

V2 and V3 returned the same exact rows for their shared pairs.
V3 scanned two additional pairs and recovered the two known
parent-path matches. V3 recorded 63 rules eligible everywhere
applicable, one partially eligible rule, 1,936 without eligible
classes and 5,809 omitted pairs. There were no indeterminate rows
or operational scan stops in this fixture.
