# Sigma and reports V10 wire contract

**Status.** Approved wire layout and vectors. Case marker 6 and export V10
share this contract.

## Scalars and ordering

A tag is the given ASCII string followed by one zero byte. Integers are
unsigned big-endian unless indicated. A hash is 32 raw SHA-256 bytes. Text is
a u32 byte length followed by well-formed UTF-8, with no implicit Unicode
normalization. Case IDs use a 36-byte lowercase hyphenated UUID inside a text field.
A timestamp bound is a signed i64 UTC microsecond count. A range is half-open and its start precedes its end.
An optional hash uses u8 zero for absent and u8 one followed by the hash
for present. Canonical event bodies become lowercase hex in existing signed
payloads. Unknown tags, nonminimal representations, duplicate keys, bad
ordering and trailing bytes are invalid. The signed frame cap stays 1 MiB.

Objects use `kind u8 | sha256 | size u64 | body[size]`. Digests bind exact
body bytes. A list commitment is
`sha256(tag | count u64 | (kind u8 | sha256 | size u64) repeated)`.
Sort descriptors by (kind, raw hash) and reject repetitions, incorrect sizes
and digests. Tags are `irmind-sigma-proof-set-v1` and
`irmind-report-proof-set-v1`. Both receipt families are independently
bounded and use the export sections below. Rule, scope, set and result
hashes refer to immutable objects. A verifier resolves each by its kind and
hash, checks the length and digest, validates the object's domain and row
references, and rejects an absent, extra or ambiguous object before reporting
verified. A hash by itself cannot stand in for the signed objects. The typed
object schemas and rejection vectors will be reviewed before implementation
of the corresponding parser, evaluator or renderer.

| Record tag | Body in exact order |
| --- | --- |
| `irmind-sigma-pack-admission-v1` | Pack manifest hash, proof-set commitment hash, origin u8 (0 local directory, 1 pinned local release archive), origin label text, optional exact archive hash (required for origin 1), and license identifier text. Analyst signs as a global admission. The existing global-operation section exports the admission when referenced by a run. |
| `irmind-sigma-run-v1` | Case ID text, checkpoint sequence u64 and entry hash, admission operation hash, active artifact inventory commitment hash, selected-source set hash, start i64 and end i64, compiled rule-set hash, field-table hash, evaluator ID text, reserved units u64 and used units u64, status u8, matched rows u64, result manifest hash, and proof-set commitment hash. Status codes are 0 complete, 1 time limit, 2 work limit, 3 oversized input, and 4 cancelled. The engine signs the atomic receipt under the case's policy. Used units must fit the reserved units. Coverage failures stay explicit in the result manifest. |
| `irmind-report-published-v1` | Case ID text, checkpoint sequence u64 and entry hash, confirmed findings and citations manifest hash, optional reviewed model-draft receipt hash, optional digest of analyst-authored sections, mandatory coverage-manifest hash, language u8 (0 English, 1 Spanish), renderer ID text, media type u8 (0 Markdown, 1 PDF), rendered length u64, rendered SHA-256, and proof-set commitment hash. The analyst signs the exact publication. A present analyst-text hash references the exact four typed section slots, including explicit empty sections, so a draft cannot substitute for the published author text. |

Initial bounds for review are 256 UTF-8 bytes per origin label, 128 per
license or evaluator/renderer ID, 4,096 rules, 64 KiB per rule, 64 MiB per
rule pack, 64 MiB per result or report bundle, and 128 MiB total of each
new object family per case. Each type also inherits its existing field and
policy ceilings. Verification streams bodies through the object byte limits.
Table entry indices and record/row coordinates must resolve in the signed
case. Limits apply to counts, aggregate wire bytes and decoded content before
any allocation or publication.

## Export V10

Use ASCII `IRMIND-EXPORT-V10` and zero, then a u64 frame length and UTF-8
compact JSON header using the existing V9 field order
`version, case_id, title, severity, scope, seal`. The seal uses the current
`seq, hash, sig, public_key, analyst_key_fingerprint` order and remains
byte-for-byte unchanged as a signed object. The header writes version 10.
Closed struct serialization defines key order, irrespective of the JSON
map feature. Reject an unsupported marker or schema at admission.

After the header, keep V9's audit, evidence, original sources, operations,
mapping proofs, Parquet, skill proofs, catalog proofs, subagent branches and
query capture sections in that order. Append Sigma objects, then report
objects. Each new section starts with its own u64 count, even when empty.
Require EOF just after the report section. The new counts cannot authorize
omitting any proof referenced by a verified receipt.

Sigma kinds are 0 pack manifest, 1 exact rule bytes, 2 field table,
3 selected sources, 4 compiled rule set and 5 result manifest. Report kinds
are 0 citation manifest, 1 analyst sections, 2 coverage manifest and 3
rendered document. Each record commits only to its own required objects.
The archive holds the union, each object once per section. Scope, matches
and cites bind the source/artifact hashes and logical row indices in the
authenticated ledger. Neither section contains live service keys or paths.

The [independent generator](../../crates/testkit/fixtures/contracts/sigma_report_v10.py)
and [vectors](../../crates/testkit/fixtures/contracts/sigma_report_v10.json) cover
admission, complete and work-limited runs, the signed analyst-text binding,
the V10 header frame and both empty section counts. The header sample fixes
framing and JSON key order using a synthetic seal-shaped value. It does not
represent a sealed case.
