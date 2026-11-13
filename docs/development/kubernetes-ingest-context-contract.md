# Kubernetes source context and cluster partitions

This proposal defines the additional local ingestion contracts needed for
Kubernetes audit logs and Falco. It complements the current
[source/mapping pipeline](source-mapping-design.md); it does not implement a
live Kubernetes connector. Parser modules decode evidence, and independent
mapping modules interpret it.

## Why explicit source context is needed

A native `audit.k8s.io/v1` Event does not identify its cluster. A namespace,
pod name, service-account name or node name is not globally unique. Neither the
file name, its directory, the machine running IRMind nor a timestamp can supply
that missing identity. Falco exports can have the same limitation. Inferring a
cluster silently would merge unrelated entities and would not be reproducible.

The analyst supplies a validated stable cluster identity before ingestion when
it is absent from the export. The TUI shows that choice and can apply it to one
source or an explicitly selected batch. The CLI accepts an explicit ingestion
option. Unattended ingestion without required context is rejected with a clear
reason. The model cannot choose or change acquisition context.

Managed exports may contain an authoritative *source field* identifying an EKS,
GKE or AKS cluster. It remains untrusted evidence, not an authorization grant.
The decoder retains that original identifier and the analyst confirms its
association with the case cluster. Conflicting identifiers are rejected; a
supplied default must never overwrite a conflicting source identifier. An
export containing several clusters preserves each explicit identity and cannot
apply a single contradictory batch default.

## Proposed additive contracts

Add a bounded typed `SourceClusterContext` in the application/domain boundary:

- A versioned cluster identity, with a closed provider kind (`kubernetes`, `eks`,
  `gke`, `aks`) and a stable qualified identifier, at most 512 UTF-8 bytes.
- A closed basis (`analyst`, `command`, `confirmed_source`). A source-derived
  suggestion is not itself confirmation. An optional confirmation binds the
  exact proposed source identifier, not arbitrary text.
- Reject empty identities, control characters, invalid Unicode, surrounding
  whitespace and values beyond the bound. Specify normalization in the current
  canonical contract; never treat the value as a file path. Preserve the
  original source field in the SourceRecord.

Extend the existing selection/decoding contracts as follows:

| Contract | Addition | Existing implementations |
| --- | --- | --- |
| `LogParser` | Optional `cluster_context_requirement(source_name, sample)` and `with_cluster_context(context)` methods. | Requirement defaults to none; configuring unsupported context returns an error. Detection stays pure and sample-bounded. |
| `StreamingEventParser` | Optional `cluster_context()` metadata accessor. | Defaults to none; no new decoding route. |
| `SourceMetadata` | An optional borrowed cluster context, identical for file and stream inputs. | Existing callers pass none; decoders not using cluster context keep their output. This is a source-level struct extension: all initializer sites must be updated. |
| `PartitionProfile` | A closed `KubernetesCluster` variant. | Existing profiles and their limits retain their meanings. |
| `PartitionLimits` | An independently validated cluster cap, default 64 and maximum 1,024. | Account, region and host defaults and maxima remain unchanged. |

`SourceDecoder::decode_reader`, `decode_local_file` and `decode_with_budget`
keep their signatures and execution guarantees. The same context travels in
`SourceMetadata` through each path. Configuring a parser for one ingestion
creates an immutable selection; it does not mutate a global registry or future
ingestions. No context is obtained from environment credentials or kubeconfig.
The parser's decode contract identifies that context affects reconstruction.

A wrapper's cluster claim and the supplied context are validated before
publishing mapped artifacts. Decoder/parser detection never acquires remote
metadata. An analyst confirmation cannot broaden the case or organization
ceiling. There is no new network capability or tool for changing scope.

## Signed provenance and reconstruction

Do not overload `timestamp_context`, parser version, source path or mapping
identity with cluster metadata. Add an explicit optional canonical
`cluster_context` field to the current source manifest and its source-record-set
commitment, and validate agreement between them. Its tag, field order, closed
enum codes, absent/present encoding and bounds receive current-format golden
vectors before implementation is integrated.

The signed record-set commitment covers the actual decoded records, including
resolved cluster identities. Mapping profiles and runs bind the selected mapping
as today. Verification reconstructs with the exact signed cluster context,
validates any original wrapper identity again, and compares the decoded and
mapped commitments. It never consults a mutable preference for reconstruction.

This is an explicit pre-1.0 format change for v0.4.2, announced in CHANGELOG.
Older case/export files are not silently reinterpreted or rewritten. The seal's
signature challenge and existing cryptographic checks are unchanged. Every frame
retains the existing 1 MiB limit. No compatibility reader is added.

## Entities, queries and partitioning

Kubernetes users, service accounts, namespaces, pods, nodes, containers and
images have typed roles and a cluster-qualified identity. Equal display names
in different clusters are distinct. Container/image references retain their
actual source values; image tags are not silently equated with image digests.
A missing cluster must not fall back to an unqualified shared namespace.

The common event gains validated orchestrator/container fields needed by the
mappings. Unavailable source fields stay absent. Reserved `cluster` becomes an
active partition key for Kubernetes sources; it does not replace the real
cluster column or entity identity. Apply the same deterministic cardinality
planning, normalization, hashed directory components and signed overflow
mechanism used for host partitions. Overflow is a physical bucket, never a
cluster identity or a wildcard. It does not merge entity namespaces.

Typed queries can narrow by cluster; invalid or out-of-scope arguments fail
instead of dropping the filter. Existing result/time/memory/path/expansion
limits remain in force. A live API connector and its scope extensions are a
separate design, not part of this contract.

## Required verification

- Unmodified decoder contracts still produce identical records with no context.
- Native audit/Falco data without required context is rejected before any
  successful manifest or mapped artifacts are published.
- TUI and CLI bind the same confirmed context and produce identical commitments.
- File, remote private spool and multicore decode paths receive identical context.
- Explicit wrapper identity conflicts, ambiguous assignments and malformed values
  fail visibly, with rollback and bounded untrusted rejection samples.
- Matching user, pod and service-account names in two clusters stay distinct in
  lookup, neighbors, timeline and path; overflow does not change that property.
- Cardinalities 1, 64, 1,024 and 1,025 exercise ordinary and overflow partitions.
- Mutating or omitting signed context invalidates reconstruction/verification;
  changing a preference after ingestion does not change reconstruction.
- Current source-manifest, source-record-set, common-schema and export vectors
  cover the optional context explicitly; no historical decoder is restored.

No additional production dependency, credential, execution privilege or live
API access is proposed. The required port changes are the five rows above.
