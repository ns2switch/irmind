# Bound mapping catalogs by ingestion group

## Current limit

The active mapping registry, the signed mapping profile and its catalog
commitment each admit up to 64 mappings. Ingestion currently copies the
whole effective registry into every profile. One application can reach
that count with compiled modules alone. A new module can then prevent
startup even when its selectors never intersect an existing module.

## Proposed scope

Keep at most 64 snapshots in a signed profile and keep its encoding,
frame size, catalog hash, per-definition size and validation rules.
Allow up to 128 active mappings in the application registry and retain
the existing limit of 64 active analyst-installed definitions. Check
IDs and selector overlap across the full effective registry on startup
and before admission of a configuration change.

Freeze the full verified registry for an ingestion. Before decoding a
group, collect all candidates for each selected parser identity and exact
version. Include every potentially applicable selector, including
selectors for record kinds or channels that do not appear in the source.
Use the existing signed snapshot representation and canonical ordering
for the union. Keep a parser version's candidate set at 64 or fewer
during configuration admission. A version with no candidates remains
eligible for the existing unclassified route.

Use the full registry in profiles while it fits the existing limit.
For a larger registry, preserve the established canonical source order
and close the group before adding a source that would exceed either the
source count or snapshot cap. Apply this selection before commitments,
route tokens and Parquet writing. All staged retries and rebuilds use
the selected profile. When verifying, resolve every signed reference
against the exact locally available implementation, then retain the
existing frozen-profile overlap and capacity checks. Historical
profiles are read in their signed form.

## Acceptance

- A registry with 65 independent mappings boots and ingests using all
  applicable candidates. The 129th mapping fails admission. An analyst
  cannot exceed the current quota for installed definitions.
- A single parser and version cannot exceed the 64-candidate bound.
  Overlap and duplicate IDs still fail across the full registry.
- A multi-source batch whose union exceeds 64 splits in canonical
  order. Test 1 and N workers, disordered input, a rejected source,
  and block-boundary cases. No mapper disappears from a source's set
  after retry. Reproduce the artifact bytes and verify the export.
- Existing signed vectors and reconstruction remain byte-identical.
  Run the same tests with `serde_json/preserve_order`.
