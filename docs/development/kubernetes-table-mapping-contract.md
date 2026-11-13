# Kubernetes table mappings

Kubernetes audit interpretation stays in bundled, hash-pinned TOML definitions.
The decoder retains original fields and precise time; it does not choose roles,
outcomes or permissions. This extends the current finite table interpreter for
cluster-qualified sources without adding an I/O capability or another language.

## Closed additions

- A field may declare `source_index`, an optional integer 0–4,095 applied after
  its explicit key path. This selects, for example, the first original
  `sourceIPs` entry. The complete array remains original evidence, including
  proxy addresses; the selected entry is a source claim, not a trusted identity.
  A missing element remains absent. The full path still has at most 32 steps.
  Invalid indexes fail compilation. Existing definitions omit this optional
  member from canonical bytes.
- An observation may use `scope.kind = "cluster"`. It obtains the cluster only
  from the confirmed SourceRecord metadata, never from a field or configuration.
  Its namespace is absent or comes from one explicit original field path.
  Kubernetes pod and service-account constructors still require a namespace.
- A service-account observation can instead name an explicit principal path for
  its namespace. The only supported grammar is
  `system:serviceaccount:<namespace>:<name>`. A corresponding closed conversion
  selects the account name. Other principals omit that optional observation;
  malformed service-account principals fail validated projection. No string
  expression, regex, fallback namespace or inferred identity is introduced.

The metadata field `irmind.cluster.identity` always comes from acquisition
context. A definition cannot replace it. Entity constructors validate names,
namespaces, roles and source fields as before. Process observations continue to
use source-record scope unless an existing supported source explicitly supplies
its documented lifetime identifier; Kubernetes PIDs do not create lifetimes.

## Projection and partitions

For a cluster source, the table mapper builds its searchable projection from the
validated common event and observations. It never copies `requestObject`,
`responseObject`, credentials or arbitrary original bodies into that projection.
Original bytes and decoded-record commitments remain bound by custody. Existing
non-cluster table definitions retain their current projection and canonical
bytes.

The cluster partition and exact row column use the confirmed acquisition
identity. Ordinary cardinality, hashed paths and signed overflow follow the
existing cluster contract. A table cannot choose an unrelated partition or use
an overflow bucket as an identity.

## Bounds and validation

The additions retain the current 64-field, 256-rule, 8,192-operation, 32-step
path, common-context and observation limits. Index steps and namespace extraction
are charged to that same operation budget. Service-account parsing checks its
fixed maximum length before splitting. Mapping remains pure: no filesystem,
network, clock, environment, secrets or permission changes.

Tests cover missing/invalid indexes; namespace and cluster isolation; ordinary
users versus service accounts; an actor account in a different namespace from
the target pod; conflicting identity fields; and unchanged existing definition
hashes. A Windows/Linux/cloud authentication fixture remains a regression test.
New Kubernetes fixtures cover successful, failed and missing outcomes, actor and
impersonated target, resource scope and omitted optional values.

This is an extension of the current pre-1.0 interpreter. No port signature,
Parquet envelope, audit event, seal challenge, export frame or cryptographic
limit changes. Existing common-field and acquisition-context extensions are
specified in the [cluster contract](kubernetes-ingest-context-contract.md).
