# Sigma compilation by source class

> Historical V3 evaluator and receipt identity. The class matrix and its V3 result body remain active under the [case 7 and V11 contract](case-7-export-v11-contract.md).

[Español](../es/development/sigma-source-class-compilation-contract.md)

**Status:** approved for v0.7.3. The optional proof reader at the end of
this document is approved.

## Scope

The v0.7.2 evaluator already builds a typed program for each source
class. Its run planner drops all programs for a rule if any applicable
class lacks an exact binding. This contract allows a complete rule to run
on the classes where every field has an exact binding. The signed result
identifies the classes it skipped.

The [approved source table](local-sigma-contract.md) and its
[exact retained fields](sigma-retained-source-fields.md) remain the
baseline. This change adds no field bindings, modifiers, rule packs,
dependencies, policy privileges or tools. Evaluate the same local
Parquet evidence with the existing guards, exact row provenance and
analyst-only finding confirmation.

## Planning and evaluation

A class is one entry in the hash-authenticated, materialized field table.
Its stable identifier within the run is its zero-based position in that
table. Each entry fixes the parser and mapping identities, logsource,
dataset or channel where specified, typed bindings and row predicates.
Preserve the table order, including when resolving native mapping
identities. A parser label, an original field name or an inferred source
type alone never qualifies a row.

1. Resolve the existing signed artifact inventory and selected source
   manifests at the run's checkpoint. A class is **available** if a
   selected source has an active CommonEvent artifact whose signed
   pipeline matches that reviewed class. This is a planning fact.
   Matching a channel, dataset and event predicate and falling inside the
   requested time window remain requirements on the individual row.
2. Check each admitted rule's structure, condition, modifiers and
   source-independent limits once. Validate the full rule, including
   nested conditions, all selections, patterns and expansions. A
   source-independent error rejects the entire rule even if a missing
   binding would be encountered first. Recognize a class-local type
   incompatibility only when the rule is otherwise valid and the
   incompatibility is with a reviewed binding.
3. Apply the existing logsource selector. In each available matching
   class, resolve all fields and validate the original predicates. If
   any binding is missing, skip that pair with **missing binding**. If
   all bindings exist but a predicate has an incompatible binding type,
   skip that pair with **incompatible type**. Missing binding takes
   precedence when both reasons apply. Invalid rule syntax, unsupported
   modifiers and global rule limits retain their current rejection path.
   An unexpected compiler error fails the run.
4. Evaluate the complete condition for each eligible pair. Never drop a
   selection, substitute fields or coerce a value to make a rule fit.
   Normal row-level absence and null handling keep their current
   semantics. An explicitly unavailable exact field remains
   indeterminate for a rule that needs it, even under negation and even
   if a different branch of the rule could match. Preserve the event and
   the existing row-gap counts per source and per rule.

For a broad Windows process-creation rule requiring `ParentImage`,
Sysmon and Defender can use reviewed full-path bindings. FDR exposes
`ParentBaseFileName` with different semantics. Evaluate the rule in
Sysmon and Defender and record the missing binding in FDR. A rule scoped
to Sysmon leaves FDR outside its logsource, which is a different state.
An exact binding present in the table but unavailable on a specific
Kubernetes row is a row gap, even when the same rule also has a
class-level gap for GKE.

The existing per-rule summary is derived from the plan. A rule with at
least one eligible pair is `Eligible`. For a structurally supported rule
with no eligible pair, use `UnsupportedField` for any missing binding,
`UnsupportedRule` for incompatible types only, `UnavailableSource` when
the reviewed table has a logsource match but none are available, and
`UnsupportedLogsource` when the reviewed table has no match. A globally
rejected rule uses `UnsupportedRule` regardless of which classes are
available. The pair matrix carries the exact class-level outcome. These
English strings are canonical for the V3 rule-summary proof. The TUI
and report localize them independently.

| Summary | Canonical detail |
| --- | --- |
| Eligible | Absent |
| Unsupported logsource | `No reviewed variant matches the rule logsource` |
| Unsupported field | `A matching source class lacks an exact binding for a rule field` |
| Unavailable source | `No signed event artifact matches the rule's reviewed source classes` |
| Incompatible types with no eligible class | `A matching source class has an incompatible rule field type` |
| Globally rejected | `Rule rejected before source-class compilation` |

Count only applicable classes in the skipped-pair total. Classes from
unenrolled sources stay outside the workset.
When no class is available, the matrix has zero columns and no matches.
The receipt identifies the run as coverage-limited.

## Signed result

Keep case marker 6, the V10 header and sections, `SigmaRunV1`,
`SigmaCompiledRulesV1`, the field table, source scope, pack admission,
and `ReportCoverageV2` layouts. New executions use evaluator
`irmind-sigma-evaluator-v3` and proof object kind 5 with domain
`irmind-sigma-run-results-v3\0`. Historical V1 and V2 receipts and proofs
keep their existing decoders and meanings. Reject unknown evaluator and
proof-version combinations, including new status 6 on an older evaluator.
Builds predating V3 reject a new V3 execution even if they recognize
the V10 envelope.

The proof body starts with the domain bytes (including NUL), followed
by the four existing V2 lists without the V2 domain, in the same wire
encoding and order: rule summaries, exact row matches, unavailable rows
by source, indeterminate rows by rule. Append the following matrix:

| Part | Canonical encoding |
| --- | --- |
| Available class count | One big-endian `u64` |
| Available classes | That many strictly increasing, big-endian `u64` table ordinals, each below the authenticated table length |
| Rule count | One big-endian `u64`, equal to both the compiled-rule and rule-summary counts |
| Pair cells | One row per rule in ascending `(id, SHA-256)` order. Each row is exactly `ceil(class_count / 4)` bytes |

Class position 0 uses bits 0–1 of the first byte, class position 1 uses
bits 2–3, and so on. Each row starts on a byte boundary. Unused high bits
of each row's last byte are zero. Cell codes are fixed:

| Code | Meaning |
| --- | --- |
| 0 | Outside the rule's logsource, or the rule was rejected globally |
| 1 | Eligible for the full predicate. This marks compilation, not completion of the scan |
| 2 | Missing an exact field binding |
| 3 | Incompatible type in a reviewed field binding |

Include every rule in the admitted pack exactly once. The signed rule
summary disambiguates global rejection, unsupported logsource and
unavailable source for rows with only code 0. The compiled-rule variant
list must equal the ordinals for code 1 exactly. Require the matrix
dimensions to agree with the authenticated rule set and available-class
list. Reject duplicates, padding with nonzero bits, truncated or trailing
bytes, and class or rule substitutions. Check sizes before allocating.
With the existing 4,096-rule and 1,024-class caps the matrix adds at most
1,056,784 bytes. The existing 64 MiB object, 128 MiB section and 1 MiB
signed frame caps continue to apply. Exceeding a cap fails publication
before a receipt or finding is committed.

Add `CoverageLimited = 6` to the run status. Apply the following
precedence to the signed status:

1. Preserve the existing first operational stop cause (time, work
   including the match cap, oversized input, or cancellation). Retain
   the complete class plan and any accumulated row-gap counts.
2. Otherwise use `CoverageLimited` when at least one pair was skipped
   with code 2 or 3, or when a rule has no eligible classes. Retain any
   row-gap counts as a separate dimension.
3. Otherwise use `ExactFieldsUnavailable = 5` if any eligible rule has
   indeterminate rows, or `Complete = 0` if it does not.

Cancellation before a complete plan is available publishes no new
execution. A class absent from the scoped artifacts is outside the
denominator when the rule can run on other classes. Even a complete scan
only covers the specified artifacts, row predicates and time window.
A skipped pair supplies no match or non-match decision.

The existing result hash and proof-set commitment authenticate the
matrix. The seal and V10 export carry the proof under the current
inventory and reference rules. Local and export verification must
derive the available classes from the authenticated checkpoint
inventory and scope, recompile the bounded admitted rule bytes against
the signed field table, and check the matrix, rule summaries, compiled
variants and status. Resolve each match to its authenticated row and
check its provenance, time, eligible class and exact predicate,
including any retained-field unavailability. Reuse the same operation
for local and exported row readers. Verification of those decisions
and cited matches is distinct from replaying the full scan to
establish completeness. Apply one bounded verification budget and
fail closed on exhaustion or unsupported evaluator, without substituting
an installed table or version.

## Limits and presentation

Share the existing work budget, 15-second scan deadline and
100,000-match limit across all classes. Before scanning, bound planning
by the existing rule and class caps and the compiler's per-rule limits.
It has a single 15-second wall-clock deadline and checks cancellation
between rules and classes. During the scan, any recompilation counts
against the scan deadline. The receipt's work counters retain their
existing evaluation meaning.

Keep parsed rules and regex state bounded. Retain only one class's
program set at a time. Preserve the canonical class,
artifact and match order irrespective of worker count. Select only
columns that the current class requires and load original fields only
when the class's row filters, exact-gap accounting or bindings need
them.

`/sigma` and `/verify` show rules with all, some or no eligible classes
and eligible and skipped pair counts. The detail view names the
affected class and reason. In a stopped scan, label eligible classes
as planned, unless completion has been established. Present class
gaps separately from indeterminate rows and operating limits, and
retain the V2 explanation that unexpected exact-field values may
indicate source manipulation. For example, “12 rules could run on
some sources only. 19 rule/class pairs were skipped because fields had
no exact mapping. Results do not establish what happened in those
classes.”

Keep `ReportCoverageV2.partial_sigma_runs` as references to all
non-complete receipts. For V3, derive report limitation text from the
authenticated result proof and receipt, naming skipped classes and
counts, indeterminate rows and early stops separately. An empty partial
result cannot support a claim of no matching activity. Keep the existing
report bytes and historical rendering for V1 and V2 runs. Analyst
confirmation is still required for each Sigma finding cited as a fact.

## Acceptance

- Rust reproduces the independent [canonical vectors](../../crates/testkit/fixtures/contracts/sigma_source_class_compilation.json).
  Tests cover a full rule in two classes, a rule that runs in two and
  skips one for a missing field and another for a type error, simultaneous
  row and class gaps, a cancellation with gaps, global rejection, a rule
  outside the selected scope, and rejected matrix and match tampering.
  Exercise true absence, null, unsigned or mismatched parser/mapping
  identities, wrong dataset/channel, logsource narrowing, and
  `not selection` without its field. Verify a signed synthetic case and
  export across platforms, and compare bytes with 1 and N workers and
  with `serde_json/preserve_order`. Keep the existing V1/V2 vectors.
- With the same pinned SigmaHQ archive used for the
  [v0.7 admission baseline](benchmarks/sigmahq-v070-admission.md),
  rerun admission and compilation without evidence. Publish by
  logsource family: total, admitted, all/some/no eligible classes,
  eligible and skipped pairs by reason, rules recovered relative to
  V2 and top missing bindings. Record a gain only when there is an
  eligible class. The baseline's 1,022 fully compiled files and 1,421
  field rejections do not estimate that gain. Keep third-party YAML out
  of the repository and shipped assets.
- Repeat the existing [synthetic release benchmark](benchmarks/sigma-v070-families.md)
  with at least 2,000 rules over 1 GiB. Include a case with several
  classes from the same product and compare V2 and V3 on the same
  runner. Report planning and scanning times, peak memory, evaluated
  rules and pairs, expected and detected positives, false positives
  and class/row gaps. Complete matching pairs must yield the same
  exact hits as V2 restricted to those classes. Test resource limits
  and fuzz the result decoder and class-plan admission with
  AddressSanitizer for 10 minutes each before the release.

## Read-only proof access for report details

This adds the optional
`LargeCaseStore::read_sigma_proof(case, kind, digest, cancel)` method
with the same default-unavailable behavior as the report proof reader.
The local adapter opens an addressed proof in that case, enforces the
existing body limit and authenticates its SHA-256 before returning
the bytes. The caller obtains the digest from the authenticated run
receipt. The V10 verifier already has its bounded object reader.
This would let both report paths resolve the same class names, counts
and row gaps from the signed field table and result. It introduces no
new signed bytes or dependencies.
