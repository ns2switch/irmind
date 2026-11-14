# Current non-catalog skill vectors

These synthetic vectors exercise `SkillSnapshotV2` for an Analyst-installed
package, including the explicit null catalog receipt, and the unchanged
`SkillLoadV1` shape referring to that snapshot. JSON has exact struct field order
and no trailing whitespace. Payload hex files have one trailing newline.

The synthetic admission hash is a codec input, not a signed admission proof or
a complete case. The [catalog contract vectors](../catalog-format-vectors/README.md)
add publisher signatures, real Analyst admission signatures and catalog provenance.
`SHA256SUMS` covers the vector files except this explanatory document and itself.
