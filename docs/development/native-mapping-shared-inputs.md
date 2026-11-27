# Shared inputs in native mapping identities

[Español](../es/development/native-mapping-shared-inputs.md)

**Status.** v0.9 proposal. The V2 recipe and the signed formats remain as released.

## Measured closure

The signed inventory for v0.8.0-alpha.1 contains 95 production graphs from 19
native mappings on five targets. Intersecting the kind and logical path of all
95 input tables finds 105 tracked files and a generated logical path shared
by every graph. The intersection includes the mapper build-manifest
implementation, the whole compiled domain crate and the shared mapping
contracts actually observed in the shipping build. Package manifests, features,
registry checksums and build settings also contribute via their V2 unit tables.
A tracked-file inventory alone cannot reproduce an identity.

Five shared paths changed from v0.7.4. They are the domain's audit-kind and
custody-manifest roots and the mapping contracts' manifest validation, mapping
module root and new shared role construction. All 19 identities changed.
ECS and OCSF also changed their own source files. The signed inventory bytes
match between the rehearsal and the tag. [Release inventory](https://github.com/ns2switch/irmind/releases/download/v0.8.0-alpha.1/NATIVE-MAPPING-INPUTS.json) ·
[Manifest V2](native-mapping-manifest-v2-contract.md).

The generated key is `outputs/private.rs`, tracked by its unit, digest and
applicable target mask. A logical path may repeat across units. The path alone
does not identify its bytes.

<details>
<summary>105 tracked inputs common to all 95 production graphs</summary>

```text
crates/build-manifest/src/lib.rs
crates/domain/src/approvals.rs
crates/domain/src/audit_kind.rs
crates/domain/src/canonical.rs
crates/domain/src/case_entities.rs
crates/domain/src/case_values.rs
crates/domain/src/common_event/codes.rs
crates/domain/src/common_event/context.rs
crates/domain/src/common_event/entity.rs
crates/domain/src/common_event/error.rs
crates/domain/src/common_event/field_kind.rs
crates/domain/src/common_event/fields.rs
crates/domain/src/common_event/filter.rs
crates/domain/src/common_event/goldens/codes-v1.tsv
crates/domain/src/common_event/header.rs
crates/domain/src/common_event/mod.rs
crates/domain/src/common_event/observation.rs
crates/domain/src/common_event/origin.rs
crates/domain/src/common_event/provider_process.rs
crates/domain/src/common_event/sets.rs
crates/domain/src/common_event/text.rs
crates/domain/src/common_event/value.rs
crates/domain/src/custody_manifest.rs
crates/domain/src/custody_manifest/artifact_v2.rs
crates/domain/src/custody_manifest/artifact_v2/partitions.rs
crates/domain/src/custody_manifest/cluster_extension.rs
crates/domain/src/custody_manifest/commitment.rs
crates/domain/src/custody_manifest/mapping.rs
crates/domain/src/custody_manifest/mapping/artifact.rs
crates/domain/src/custody_manifest/mapping/artifact/codec.rs
crates/domain/src/custody_manifest/mapping/artifact/group.rs
crates/domain/src/custody_manifest/mapping/artifact/pipeline.rs
crates/domain/src/custody_manifest/mapping/binding.rs
crates/domain/src/custody_manifest/mapping/binding/codec.rs
crates/domain/src/custody_manifest/mapping/commitments.rs
crates/domain/src/custody_manifest/mapping/contracts.rs
crates/domain/src/custody_manifest/mapping/layout.rs
crates/domain/src/custody_manifest/mapping/layout/codec.rs
crates/domain/src/custody_manifest/mapping/lineage.rs
crates/domain/src/custody_manifest/mapping/lineage/activation.rs
crates/domain/src/custody_manifest/mapping/profile.rs
crates/domain/src/custody_manifest/mapping/profile/codec.rs
crates/domain/src/custody_manifest/mapping/run.rs
crates/domain/src/custody_manifest/mapping/run/codec.rs
crates/domain/src/custody_manifest/mapping/run/validation.rs
crates/domain/src/custody_manifest/mapping/source_set.rs
crates/domain/src/custody_manifest/mapping/time.rs
crates/domain/src/custody_manifest/mapping/wire.rs
crates/domain/src/custody_manifest/seal_inventory.rs
crates/domain/src/custody_manifest/versioned_artifact.rs
crates/domain/src/entities.rs
crates/domain/src/entities/scope.rs
crates/domain/src/graph_filter.rs
crates/domain/src/graph_filter/common.rs
crates/domain/src/ids.rs
crates/domain/src/indexed_time.rs
crates/domain/src/indexed_time/calendar.rs
crates/domain/src/indexed_time/order.rs
crates/domain/src/indexed_time/parse.rs
crates/domain/src/lib.rs
crates/domain/src/mapping_identity.rs
crates/domain/src/policy.rs
crates/domain/src/policy/scope.rs
crates/domain/src/policy/siem_query.rs
crates/domain/src/policy/validation.rs
crates/domain/src/skills.rs
crates/domain/src/skills/metadata.rs
crates/domain/src/skills/package.rs
crates/domain/src/skills/provenance.rs
crates/domain/src/source_cluster.rs
crates/domain/src/source_cluster/codec.rs
crates/domain/src/source_record.rs
crates/domain/src/source_record/canonical.rs
crates/domain/src/source_record/error.rs
crates/domain/src/source_record/format.rs
crates/domain/src/source_record/number.rs
crates/domain/src/source_record/path.rs
crates/domain/src/source_record/reference.rs
crates/domain/src/source_record/value.rs
crates/domain/src/tainted.rs
crates/mapping-contracts/src/common_event/cluster_audit.rs
crates/mapping-contracts/src/common_event/codec.rs
crates/mapping-contracts/src/common_event/codec/observation.rs
crates/mapping-contracts/src/common_event/codec/time.rs
crates/mapping-contracts/src/common_event/mod.rs
crates/mapping-contracts/src/common_event/values.rs
crates/mapping-contracts/src/lib.rs
crates/mapping-contracts/src/modules.rs
crates/mapping-contracts/src/records.rs
crates/mapping-contracts/src/source_mapping/error.rs
crates/mapping-contracts/src/source_mapping/json.rs
crates/mapping-contracts/src/source_mapping/json/read.rs
crates/mapping-contracts/src/source_mapping/json/write.rs
crates/mapping-contracts/src/source_mapping/manifest.rs
crates/mapping-contracts/src/source_mapping/mod.rs
crates/mapping-contracts/src/source_mapping/native_manifest.rs
crates/mapping-contracts/src/source_mapping/output.rs
crates/mapping-contracts/src/source_mapping/output/provider_process.rs
crates/mapping-contracts/src/source_mapping/output/time.rs
crates/mapping-contracts/src/source_mapping/selector.rs
crates/mapping-contracts/src/source_mapping/selector/intersection.rs
crates/mapping-contracts/src/source_mapping/snapshot.rs
crates/mapping-contracts/src/source_mapping/snapshot/selectors.rs
crates/mapping-contracts/src/source_mapping/snapshot/wire.rs
crates/mapping-contracts/src/source_mapping/structured_roles.rs
```

</details>

## Narrow the compiler boundary in v0.9

Keep the source record, CommonEvent types and codes, mapping identities,
canonical mapping serializers, and the exact validation required to produce
mapped evidence in a small stable foundation. Move frequently edited case
audit kinds, policy and approvals, skills, seal and layout receipts, and query
UI/filter types to a higher-level domain layer when the dependency graph allows
it. Move ECS/OCSF role construction to a crate used by those two families if it
has no wider consumers. Reexport moved public types from the existing API where
it helps callers. Use Cargo's compiler-visible crate edges to separate these
concerns so the fingerprint still includes every file the mapper actually
compiles, including build scripts and generators.

Start with a reachability spike and report closure size and dependency edges
for all targets. Compare Rust fixtures with the old implementation for
CommonEvent bytes, identity scopes, custody vectors, and JSON order with
`preserve_order`. A build-input change to the case ledger, skills or layout must
leave all mapper identities stable after the split. Changing a stable mapper
input or its real production feature must still change the dependent hashes.
Test an ECS/OCSF-only change for an effect restricted to those consumers.
Verify equal V2 manifests and normalized mapped output across the five release
targets and measure cold build time and binary size. Use release inputs for
these tests rather than the provisional identity from a development build.

The split itself changes the dependency graph and therefore changes mapping
implementation hashes once. It can keep the V2 manifest encoding and signed
case envelopes if canonical bytes are preserved. Agree the new package boundary,
the independent vectors and release notes before implementation. Retain the
creating binary for complete reconstruction of data mapped with the old hashes.
