# Review of the proposed Sigma YAML reader

**Status.** Dependency review for approval. The IRMind workspace and its
lockfile are unchanged.

## Dependency and cost

Candidate `saphyr-parser = "=0.3.4"` with `default-features = false`.
This is the event parser with no general-purpose YAML deserializer or debug
printing. Version 0.3.4 includes the upstream fix for recognizing a
document start after an unindented block scalar. [Package and license](https://crates.io/crates/saphyr-parser/0.3.4) ·
[Upstream changelog](https://docs.rs/crate/saphyr-parser/0.3.4/source/CHANGELOG.md)

The license is MIT OR Apache-2.0. The release notices would retain both
copyright attributions and the applicable license texts for Chen Yuheng
and Ethiraric, as required by the distributed LICENSE. `arraydeque 0.5.1`
is MIT OR Apache-2.0. The normal/build dependency closure observed in
a standalone, locked probe is:

- `saphyr-parser 0.3.4` and `arraydeque 0.5.1`, two additional packages.
- `thiserror 2.0.21`, plus its existing host-side proc macro and dependencies
  `thiserror-impl 2.0.21`, `syn 3.0.9`, `quote 1.0.47`,
  `proc-macro2 1.0.107` and `unicode-ident 1.0.27`. The probe reused the
  workspace's resolved versions for this part of the closure.

Cargo-deny 0.20.2 with the IRMind policy passed advisory, ban, license
and source checks on the isolated dependency graph. Before integration the
same checks must pass with the exact workspace lock and release feature graph.

On Linux x86_64, Rust 1.97.1, stripped release with ThinLTO and one codegen
unit, a small reader probe grew from 346,664 to 460,808 bytes. The 114,144
byte difference (111.5 KiB) includes the event scanner and the rejection
visitor. Linked size in IRMind still needs to be measured after approval,
as the probe cannot account for cross-crate deduplication.

## Proposed parser configuration

Accept one UTF-8 rule document up to 65,536 bytes. Check that limit while
reading. Reject a byte-order marker at any position. Before the parser sees
text, reject directives beginning with ASCII percent at the start of a
physical line, recognizing CR, LF and CRLF. This also rejects an unused
`%TAG` directive which the parser's public event stream may not emit. A
column-zero directive-looking line is outside the admitted subset.

Use `Parser::new_from_str` and consume its event iterator in order:

- Reject `Alias` and any nonzero anchor ID or any explicit tag on
  `Scalar`, `MappingStart` or `SequenceStart`, including standard and
  non-specific tags. Quoted literal markers remain data.
- Stop on the second `DocumentStart`. Require exactly one completed
  document, one top-level mapping, and the final `StreamEnd`. An unknown
  event or parser error rejects the rule.
- Stop at 4,096 syntax events, depth 24, or any scalar/collection bound.
  Construct only the finite typed Sigma AST. Reject complex keys, duplicate
  keys, `<<` merges, unsupported values and implicit type coercion.
  Enforce expansion and regex budgets in the separate rule compiler.
- Test parser and compiler with synthetic YAML. Fuzz the final admission
  wrapper with AddressSanitizer for the required ten minutes.

The standalone event probe accepted a single valid rule and quoted
structural markers, and rejected unused anchors, aliases, explicit
standard, verbatim and non-specific tags, unused tag directives, multiple
documents, excessive depth and oversized input. This is a feasibility
measurement. The complete admission wrapper and its duplicate-key,
scalar-type and fuzz tests belong to the implementation review.
