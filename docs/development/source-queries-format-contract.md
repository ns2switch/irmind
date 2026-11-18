# Source-query ports, signed acquisition and export V9

[Español](../es/source-queries-format-contract.md)

**Status: approved v0.6 contract with reduced scope; implementation follows separately.**
Companion to the [source-query architecture](source-queries-design.md). This
proposes application boundaries, case marker 5, export V9 and synthetic canonical
vectors. No source, dependency, credential, existing golden or workflow changes
are made by this document. Entra client-secret credentials and SourceQueryExecutor are approved.
Certificate credentials remain future work. Query modules remain independent.

## 1. Scope and unchanged boundaries

Initial modules: `query-athena` for CloudTrail, `query-bigquery` for Cloud Audit
Logs, and `query-azure-log-analytics` for verified Analytics tables. Security Lake
OCSF and linked Cloud Logging reuse the first two only after their source-field
contracts pass. CloudTrail Lake, ADX, Basic and Auxiliary remain unavailable.
An unavailable module cannot be replaced by an unfiltered SIEM/object call.

Keep `SourceDecoder`, `SourceMapper`, `SourceRecordV1`, `ParquetArtifactV3`,
`MappingProfileV1`, `MappingRunV1`, seal inventory V2, existing SignedEntry and
SignedOperation challenges, and `export_case` unchanged. Reuse the approved
case-local spool, evidence publication, mapped ingest, case lock, branch store
and budget broker. No new cache, remap operation or historical reader is added.
Existing event labels and golden bytes are not reinterpreted.

### Proposed case/version changes

`CaseCreated.version = 5`. Ordered top-level keys are
`version,title,severity,scope,budget,source_queries`; `budget` keeps its current
three dimensions. Required `source_queries` is the initial allocation below,
including explicit disabled/zero state. Producers reject case markers other than
5 before opening, verifying or exporting, with creator-version guidance when
safely readable and the alternatives of using that executable or re-ingesting.
The pre-1.0 policy permits this break; there is no implicit migration.

Export magic becomes `IRMIND-EXPORT-V9\0`, header `version=9`, with the same
ordered header fields as V8. Signatures and the seal commitment algorithm do not
change. Skills, catalog proofs, subagent branches and current mapped artifacts
remain fully verified, including when query sections are empty.

## 2. Validated types, limits and identities

`SourceQueryV1` contains `version,source,dataset,from,to,filters,fields,result,limit`.
Constructors validate the architecture's closed common-field/operator/value
sets; model arguments cannot contain SQL/KQL, account/workspace/table identifiers,
endpoints, provider options or page tokens. Unknown fields, duplicate keys,
unsupported exact translations and incompatible mapping projections are errors.
A missing predicate is never filled by removing a scope restriction.

| Quantity | Proposed default / fixed bound |
| --- | --- |
| Interval | 31 days by organization policy; nonempty `[from,to)` inside case scope. Proposed compiled maximum 366 days; reducing it for a service is allowed. No implicit machine-clock window. |
| Filters / membership / projected fields | At most 16 / 32 / 32; values at most 256 UTF-8 bytes, validated by common-field type. Canonical filters sorted and unique; fields sorted by wire name. |
| Query evidence | At most 100,000 rows and 100,000,000 decoded capture bytes; first reached wins. Requested `limit` can reduce the row cap. Existing per-record decoder limits remain. |
| Case evidence | Proposed initial allocation 1,000,000 rows / 1,000,000,000 decoded capture bytes, reducible by organization and case. Counts include all principal acquisitions, not only active graph files. |
| Scans | Separate nullable allocation `scan_bytes`, query ceiling and approval threshold; no enabled scan-priced module without explicit organization/case allocation. No monetary default is invented. |
| Azure execution | 180 seconds end-to-end, one outstanding query and six submissions per rolling minute per workspace/credential, shared across principal requests and processes. Retries count. Other modules use the smaller configured/provider deadline. |
| Wire/control data | At most 128 KiB canonical query record; existing SignedEntry frame at most 1 MiB including envelope/signature. Check final serialized size before signing. Depth at most 32, at most 4,096 nodes, no unbounded map/string allocation. |
| Capture streaming | At most 64 KiB transport chunks and 512 KiB export chunks. At most 4,096 response pages per acquisition; opaque cursors at most 4 KiB, never exported or shown to the model. Oversized individual rows are rejected, not split. |
| Model view | Existing guarded tool-summary limit, independent of retained rows/bytes. Guard 1,000,000 bytes, stream 2,000,000 bytes and signed frame 1 MiB are unchanged. |

The retained-byte limit counts decoded response bodies including envelopes,
not compressed transfer bytes, Parquet size or model tokens. Spool reservation
includes the full admitted capture size, known publication/staging overhead and
the existing free-space margin before network work. Disk and decoder limits can
reject a query sooner; none are replaced by this table.

`ResolvedQuerySourceV1` freezes a registered module/version, source alias,
account/project/workspace and owner, location, dataset/table identity, approved
partition bindings, credential *reference* and configuration/policy revision.
A reference is not credential material and grants no capability. Result locations
are fixed by configuration. Runtime endpoints are resolved internally, with TLS,
CA/hostname checks and no credential-forwarding redirects.

`CompiledSourceQueryV1` freezes exact UTF-8 query text, ordered typed bindings,
source-field translation identity/hash, decoder/mapping identity, required source
columns, deterministic order/tie key and source/scope predicates. It is produced
only by the module's pure compiler. Unknown status/role translations fail; a
literal prefix preserves literal `%`/`_`, never wildcard scope. Date-partitioned
sources compile the complete bounded date set plus account/region predicates.

### Canonical record bytes

For the **new records only**, `J(x)` is compact UTF-8 JSON, recursively sorted by
UTF-8 key bytes, without whitespace/newline/BOM. Reject unknown/duplicate keys,
floats, noncanonical integers, invalid Unicode and trailing bytes before accepting
J; absence uses an explicit `null` where the schema permits it. Strings use JSON
escapes for controls/quote/backslash, otherwise literal UTF-8 (no normalization
of evidence). Integers are checked u64, booleans are JSON booleans, hashes are
64 lowercase hex. UUIDs are canonical lowercase. Timestamps have fixed UTC form
`YYYY-MM-DDTHH:MM:SS.fffffffffZ`, with nine fraction digits.

`Id(D,x) = SHA256(UTF8(D) || 00 || J(x))`, where the domain is the table below.
A signed audit payload is exactly J(x) as the existing payload string, with the
new exact `AuditEventKind` label and existing Actor challenge/envelope. The new
content identity is not a substitute for that audit signature. No decoder relies
on serde_json's map feature. Noncanonical input is rejected rather than silently
re-serialized before signature checking.

All records have `version=1` and `case_id`; optional task identity is an explicit
`task_id:null` for the principal. IDs point only backward. A plan does not contain
its own ID, a reservation ID or a later approval/result; those would be cycles.

## 3. Concrete application ports

These signatures are proposals, not additions to the executable. Async dispatch
uses the existing async-trait/cancellation conventions; no new runtime or SDK.

```rust
#[async_trait]
pub trait SourceQueryExecutor: Send + Sync {
    fn descriptor(&self) -> SourceQueryModuleV1;
    fn compile(&self, source: &ResolvedQuerySourceV1, query: &SourceQueryV1)
        -> Result<CompiledSourceQueryV1, AppError>; // pure; no I/O
    async fn preflight(&self, call: &AuthorizedCall,
        query: &CompiledSourceQueryV1, cancel: &CancellationToken)
        -> Result<QueryPreflightV1, AppError>;
    async fn submit(&self, lease: &AdmittedSourceQuery,
        cancel: &CancellationToken) -> Result<SubmitObservationV1, AppError>;
    async fn reconcile(&self, lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef, cancel: &CancellationToken)
        -> Result<ExecutionObservationV1, AppError>;
    async fn fetch(&self, lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef, cursor: &QueryResultCursor,
        cancel: &CancellationToken) -> Result<QueryResponsePage, AppError>;
    async fn cancel(&self, lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef, cancel: &CancellationToken)
        -> Result<CancelObservationV1, AppError>;
}

```

`SourceQueryModuleV1` declares stable id/version, exact supported field/filter and
result capabilities, source formats, accounting mode, enforced-ceiling semantics,
recoverable-submit/cancellation support and API versions. Capability is checked
before a plan/approval, never discovered by executing a broader query.

`QueryPreflightV1` contains the resolved configuration commitment, observed source
metadata and capture time, exact-plan digest, estimate with unit/basis/uncertainty,
provider ceiling and accounting mode (`scan_priced` or
`analytics_no_query_charge`). It cannot approve. Preflight network metadata/dry
runs require their own source-restricted AuthorizedCall; policy, TLS, deadlines
and call/rate accounting apply. No preflight executes a real query or creates a
provider resource that costs money without admission.

`AdmittedSourceQuery` has private fields and no deserializer. Only the broker
creates it after policy/scope/approval/reservation checks. It binds case, source,
plan, limits, allocation revision, actor and operation phase, never a signer or
Analyst key. v0.6 rejects any non-null task_id with
`SourceQueriesUnavailableForSubagents` before preflight, reservation or network.
The module rejects a lease for another module/source/phase/compiled plan. Every
HTTP request checks the lease, including retries/poll/fetch/cancel.

`QueryExecutionRef` binds plan, attempt and opaque native job ID, not a model URL.
`QueryResultCursor` is minted by the engine from a validated response and bound
to execution/ordinal; adapters cannot reuse it for another plan. Repeated or
out-of-order cursors fail. `QueryResponsePage` returns checked status/headers,
next-cursor metadata and a cancellation-aware stream of bounded byte chunks,
not a case path. Azure's synchronous response uses one page; streaming body
ownership passes to the engine without first buffering 100 MB.

The engine stages/hashes/parses the chunks. The adapter never signs, publishes
evidence, widens scope, edits budget or automatically retries an uncertain submit.
`SubmitObservationV1` distinguishes accepted, definitively-not-submitted and
unknown; unknown is not an ordinary retryable transport error. Reconcile or
cancel can return `unsupported` honestly. No fictitious job status or successful
cancellation is synthesized for a synchronous API lacking that facility.

### Wiring and storage

Propose optional `EnginePorts::with_source_queries(SourceQueryPorts)` with one
executor module map. Existing `EnginePorts::new` remains unchanged;
absence is `SourceQueriesUnavailable`, never fallback. Module keys are unique,
feature-gated and registered explicitly. Existing HTTP, AWS SigV4 and Google
keystore-backed OAuth/RS256 are reused before considering SDKs.

The existing case-local spool and evidence/mapped-ingest publication interfaces
are reused, not new generic storage ports. Captured files live under hash-derived
case-owned acquisition paths and are copied originals of the **derived source**,
not references to temporary files. Private Unix 0600/0700 / Windows user ACLs,
no-follow opens, space checks, cancellation and orphan cleanup remain mandatory.
If actual implementation needs a missing durable publication primitive, stop for
a narrow additive contract; do not use a system temporary or bypass atomic append.

### Model-facing dispatch

Propose closed `Tool::SourceQuery` / wire name `source_query`, taking exactly
SourceQueryV1. Its risk is `Read`, like current cloud audit reads, **with** the
additional non-bypassable source-query admission, scan/retention broker and
exact-plan approvals defined here. A normal Read decision alone never submits
it. No tool can change its source configuration, table plan, allocation or
credential. Existing SIEM tools retain their own 24-hour/row contracts.

In v0.6 only the principal agent can use source_query. All six child types and
their existing inventory/snapshot formats remain unchanged; no child receives
this tool. A direct or aliased child attempt is rejected before any remote work.
The future cloud type V2, SubagentPlanV2 and remote-original verification are
[deferred beyond v0.6](source-queries-deferred.md).

## 4. Budget broker, approvals and uncertain jobs

`SourceQueryAllocationV1` contains `enabled,analytics_allowed,scan_bytes,
retained_rows,retained_bytes`. Zero/disabled defaults are explicit. Organization
policy additionally caps interval, per-query rows/bytes/scans, deadlines, source
frequency/concurrency and scan-approval threshold. Case changes use a new
Analyst-signed `SourceQueryBudgetV1`; allocations cannot exceed organization
ceilings or revoke already used/reserved resources by setting an impossible cap.

One broker serializes admission across principal requests and processes under the
existing case/plan coordination locks. Used + outstanding reservations + new
reservation must fit every relevant dimension. Do not hold those locks while
waiting for UI/network. Scan allocations never reinterpret `cloud_bytes`, which
keeps its object-transfer meaning. Query response traffic/retention is separately
accounted. Post-seal remote-original verification is not included in v0.6.

Source queries consume ordinary principal tool-call budget plus their independent
scan/retention allocations. Existing subagent limits and the whole-plan 25% rule
remain unchanged: no query allocation is delegated in v0.6. Exhausted case
allocations reject before network work; no token-debt exception applies.

Exact-plan approval is required above the scan threshold, for unreliable scan
estimates and whenever existing external-query policy requires it. Analytics
price eligibility is explicit policy, not unknown scan-price approval. A signed
approval never overrides an unenforceable hard ceiling. Preview includes exact
translated query/bindings, source/scope, time axis/window, fields, partition plan,
estimate/range/unknown, ceilings, retention caps and remaining case allocation.
Any changed query/configuration/mapping/limits invalidates that consent.

State order: compile → preflight → signed plan → optional Analyst approval →
signed reservation and submit intent → network submit → observations → capture
and validated result → atomic evidence publication → settlement. No result is
visible as admitted evidence before all references validate and the bounded
audit append succeeds. Failed signatures/publication roll back local admission;
remote usage and uncertain-job holds remain, because network work cannot roll back.

A submit intent is durable before network dispatch. On timeout/crash, reconcile
by the same provider job ID/idempotency key; never issue a new paid query simply
because the original HTTP reply was lost. Idempotent resubmission of the *same*
request is allowed only when the service documents that exact guarantee and the
module contract proves it. Otherwise persist unknown, retain the hold and block
conflicting work. Poll/fetch retries obey deadline/rate/call bounds and cannot
reset acquisition row/byte caps.

Settlement is once per reservation and references an earlier terminal observation
plus actual admitted-retention counts. Preserve reported processed/scanned/billed
bytes separately; unknown counters are `null` with a reason, not zero. Provider
cancellations can still cost scans. Athena's cutoff is a cancellation trigger,
not a physically exact byte boundary: retain the overrun, block subsequent scans
and mark the contract not suitable for an organization requiring an exact hard
byte cap. Do not extend model-token debt capacity to scans.

For a non-reconcilable synchronous Azure timeout, record `unknown`, not success
or cancellation. An unresolved job blocks that source's execution slot. Proposed
recovery is a separate Analyst-signed acknowledgement after a documented
provider maximum lifetime covering queueing as well as execution: release the slot only, keep the uncertainty and
observed consumption; do not turn unknown scan usage into zero or authorize a
scan-priced adapter through this path. This bounded recovery rule is a review
point, not an implemented exception. If that complete lifetime is not documented, this recovery is unavailable; a
600-second running-time limit alone does not establish it. If remote termination
is mandatory policy and cannot be verified, the adapter is unavailable.

## 5. Azure Analytics check and credential proposal

Use only allowlisted `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`
and `AzureActivity` initially; actual schema and exact mapping/pushdown must pass
contracts. Check `plan=Analytics`, effective interactive retention, stable table
state and owner immediately before submit. Record the preflight and post-query
observations, including plan-change time when provided. Reject Basic, Auxiliary,
unknown plans, unreadable metadata, archive/search/restored-result tables,
cross-table expressions, resource functions and unverifiable underlying sources.

The [official pricing](https://azure.microsoft.com/en-us/pricing/details/monitor/)
separates Analytics queries from Basic/Auxiliary scan charges; record price basis
`analytics_no_query_charge`, display “no query charge under the table plan”, and
leave scan/billed bytes `null:not_reported` unless the provider reports them.
This does not describe ingestion, retention or transfer as free. The
[table metadata API](https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/get?view=rest-loganalytics-2025-07-01)
does not lock the plan during the query. A detected external plan change records
uncertainty and disables further execution; do not claim retroactive prevention.

Proposed new keystore fields: `query-azure-log-analytics/<source>/tenant-id`,
`client-id` and `client-secret`; metadata/API audiences are fixed by the adapter.
These names and the client-credentials flow require approval with this contract;
no credentials are created here. Token requests use the
[documented Entra flow](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api),
separate management and query audiences, in-memory access tokens and full TLS.
No environment, CLI, delegated-login or managed-identity fallback. Logs Query v1
POST carries compiler-owned KQL and explicit timespan, never model KQL. ARM table
metadata uses `tables/read`; query grants remain table/row constrained and cannot
be broadened just to make a metadata check pass.

## 6. New signed records and acyclic links

All new domains below are lowercase names prefixed by `irmind-` and terminated
by one zero byte before J. Exact audit labels are the names in the first column.
Fields below are required; nullable values must still be present. J sorts them,
so this list defines membership rather than serialization order.

| Label / domain suffix | Fields beyond `version,case_id`; actor |
| --- | --- |
| `SourceQueryBudgetV1` / `source-query-budget-v1` | `revision,previous,budget,reason,at`; Analyst. `previous` is the preceding budget-record ID or null for the initial allocation authenticated in CaseCreated. |
| `SourceQueryPlanV1` / `source-query-plan-v1` | `task_id,attempt,query,compiled,source,scope,configuration,policy,allocation_revision,preflight,limits,decoder,mapping,at`; Agent. No later approval, reservation or result ID. |
| `SourceQueryApprovalV1` / `source-query-approval-v1` | `plan,task_id,decision,reason,at`; Analyst. `decision` is approve or deny; the exact plan includes the budget revision. Existing policy approval still applies. |
| `SourceQueryReservationV1` / `source-query-reservation-v1` | `plan,task_id,approval,allocation_revision,scan_bytes,retained_rows,retained_bytes,at`; Agent/broker. `approval=null` is allowed only if all policy and plan-consent rules permit it. |
| `SourceQueryExecutionV1` / `source-query-execution-v1` | `plan,reservation,previous,attempt,phase,execution_key,provider_id,provider_request_id,started_at,observed_at,provider_at,status,usage,source_observation,reason`; Agent. `previous` chains observations for the same attempt. |
| `SourceQueryResultV1` / `source-query-result-v1` | `plan,reservation,execution,capture_sha256,capture_bytes,page_count,page_commitment,row_count,rejected_rows,completeness,coverage,decoder,mapping,at`; Agent. `execution` is the earlier terminal/partial observation, never a later settlement. |
| `SourceQuerySettlementV1` / `source-query-settlement-v1` | `plan,reservation,execution,result,scan_charged,retained_rows,retained_bytes,usage,uncertainty,at`; Agent/broker, exactly once. `result=null` for no admitted capture; unresolved scan usage prevents ordinary settlement. |
| `SourceQueryRecoveryV1` / `source-query-recovery-v1` | `plan,reservation,execution,action,reason,not_before,at`; Analyst. Only acknowledgement of a documented expired non-reconcilable Analytics execution; no grant of scan capacity or assertion of provider success. |

`SourceQueryExecutionV1.phase` is intent, accepted, running or terminal;
`status` is pending, succeeded, failed, cancelled, partial or unknown, with
validated transitions (unknown is not terminal proof). `source_observation` is
null or the bounded source-metadata snapshot, including Azure's post-query plan.
Intents have no provider job ID; a terminal job ID cannot later change. Result
receipts refer to terminal/partial observations, or explicit rejected/cancelled
captures with the corresponding state; unknown never yields a successful result.

`compiled` includes exact query text, bindings and translator identity/hash;
`source/scope/policy/limits` are complete bounded nonsecret resolved snapshots,
not just hashes. The verifier can check their commitments and the source-specific
query grammar/scope offline using the versioned compiler. The policy snapshot is
an Analyst-authenticated ceiling/allocation proof, never a ceiling invented and
signed only by the Agent. Propose global operation `source-query-configuration-v1:`
followed by hex(J({version,source,policy})), signed through the unchanged global
SignedOperation challenge; include that adoption proof in export. This attests
the Analyst-adopted policy snapshot, not an independent enterprise authority.
Normal source configuration stores only keystore references, never secrets.
`preflight` includes table-plan evidence/estimate, observed time and uncertainty.
Provider JSON is not authority to select another endpoint or scope.

`usage` is `{scanned_bytes,processed_bytes,billed_bytes,returned_wire_bytes,
returned_decoded_bytes,query_price_basis}` with explicit nullable scan fields and
an accompanying reason in `uncertainty` when unavailable. Monetary estimates
remain optional and require a complete versioned price profile, not a zero price
inferred from missing metrics. Record actual provider request IDs as untrusted
bounded strings; no tokens, authorization headers, signed URLs or private keys.

A derived capture contains *retained* raw decoded service pages, not fabricated
original cloud events. Its byte-stream container has magic `IRMIND-QUERY-CAPTURE-V1\0`,
a canonical descriptor frame (at most 128 KiB, no later result ID), u64 page count,
then each page's canonical metadata frame and u64 body length/body bytes. Page
metadata binds ordinal, provider-native columns/types, returned row count,
content encoding, full-body SHA-256 and completeness. The per-query byte ceiling
includes descriptors and envelopes; no descriptor can exempt its body bytes.
The capture ordinary SHA-256 is calculated before SourceQueryResultV1.

`PageCommitment = SHA256("irmind-source-query-pages-v1" || 00 || u64(count) ||
concat(u64(ordinal) || hash32(body) || u64(bytes) || u64(rows) || u8(completeness)))`.
Ordinals are contiguous from zero; duplicates, missing/reordered pages and
changed row/length/body invalidate the commitment. Completeness codes are
0=complete, 1=provider_partial, 2=local_limit, 3=cancelled, 4=rejected.
Overall completeness preserves all applicable causes in a sorted unique list.
A complete response limited by compiler LIMIT is still `local_limit` if all
matches cannot be proven acquired; do not infer completeness from exactly N rows.

Existing SourceManifestV2 binds the capture's hash/size and checked case-relative
`queries/<capture_sha256>.sqc` identity with `copied=true`; it is not authority to
open an arbitrary path. SourceRecordSetV1 uses `SourceKind::ToolResult` and
`acquisition=SourceQueryResultV1 ID`, then MappingRunV1 and ParquetArtifactV3 link
normally. Service page decoders preserve event fields, true page/row ordinals
and native timestamps. Byte offsets describe the captured bytes only; no source
S3 or remote-table offsets are invented. Capture descriptor → pages → capture
hash → result → manifest/source-set → mapping/artifacts is acyclic. Profiles may
precede the result; no back-link into a later result is added to them.

### Nested wire members

The vector [schemas](source-query-format-vectors/schemas.json) list exact member
sets for each example and the closed enums; concrete serializers must reject
extras, including when the outer record's signature is valid. Core nested types:

- `compiled`: `{text,bindings,translator,required_fields,order}`; binding
  `{name,type,value}`, translator `{id,version,sha256}`. SQL identifiers are from
  `source`, not binding values. `type` is text, u64, bool, ip or timestamp.
- `source`: `{module,module_version,id,owner,location,dataset,table,partitions}`;
  `partitions` is a finite sorted list of typed name/value bindings, not SQL.
- `scope`: `{accounts,projects,workspaces,regions,from,to,proof}`; sorted unique
  lists under current scope bounds, an empty unrelated dimension means not
  applicable, never wildcard. `proof` is an authenticated source/task-scope
  admission reference.
- `configuration`: `{sha256,adoption}`; adoption is the included signed global
  source-query configuration proof. `policy` contains `{sha256,rules,adoption}`.
- `limits`: `{interval_seconds,rows,retained_bytes,scan_bytes,deadline_seconds,
  queries_per_minute,concurrency}`; `scan_bytes=null` only for verified Analytics.
- `preflight`: `{plan_digest,observed_at,accounting,estimate,provider_ceiling,
  source_metadata,uncertainty}`. `plan_digest` hashes the compiled query, source,
  scope and limits, **not** the later SourceQueryPlanV1 containing preflight.
  Estimate `{unit,value,basis,reliable}` permits value null; an unknown priced
  estimate is not zero. Metadata is a bounded closed service-specific snapshot.
- Decoder/mapping references are current identified `{id,version}` values;
  mappings additionally carry their existing immutable definition hash and
  target-schema identity. The vector's extraction mapping is synthetic and is
  not an assertion that its production implementation exists.

## 7. Retention, local analysis and atomic publication

Reserve acquisition rows/bytes before sending. Retain once, validate the service
schema, select the frozen decoder/mapping, and ingest through the normal mapped
writer. Include all fields needed by that mapping or reject the projection.
Missing roles/classification remain unknown with coverage, never inferred from
free text. Aggregates use a separate statistical response format and cannot
manufacture CommonEvent observations or event-level findings.

Stop at the smaller row/byte/deadline cap. Already completed valid pages or a
framed complete-record prefix may be admitted as explicitly partial. A truncated
single JSON envelope cannot be repaired or indexed by guessing its missing tail:
retain its bounded rejected capture and receipt, without graph records from that
invalid page. Provider partial errors, local truncation, invalid rows and mapping
coverage gaps are different counters/flags. All malformed rows are reported with
the existing bounded, tainted rejection samples.

Publish capture, SourceQueryResultV1, manifests, mapping/Parquet receipts and
retention settlement atomically in the principal case transaction after
hash and final-frame checks. Earlier execution/scan-usage receipts remain even
if local admission rolls back. Prepared files on failed append are removed or
unreferenced and cleaned diagnostically; no half-admitted source is visible.
No query data enters system prompts. Provider/evidence values and summaries pass
through existing provenance, ContentGuard and nonce-isolated UNTRUSTED handling.

Return only source ID/hash, interval, retained counts, completeness/coverage and
the bounded model preview. Timeline, search, entity lookup and raw-record tools
then use that source locally under existing scopes, samples and deadlines. They
must not trigger additional network queries. Local pages do not spend remote scan
budget. A requested new remote acquisition is a distinct signed/budgeted plan.

## 8. Export V9 and seal

Retain V8 body order through catalog proofs and subagent branch chunks. The
signed-operation section additionally includes exactly the Analyst-signed
source-query-configuration-v1 adoption proofs referenced by exported plans:
case operations in their existing order, then unique global proofs sorted by
operation hash. Verify the unchanged signature challenge and expected Analyst,
then match adopted source/policy bytes to each plan. Missing/unrelated/other-key
proofs invalidate verification; do not export unrelated global configuration.

After branch chunks append **one** mandatory big-endian u64 query-capture count,
possibly zero. There is **no detached-receipt count, not even a zero**, in v0.6 V9.
Captures are sorted by SHA-256. Each has a canonical descriptor frame
`{capture_sha256,bytes,chunks}`, then exactly that many raw byte frames, at most
512 KiB each. Reject unreferenced/duplicate/missing captures, changed lengths,
reordered chunks, mismatched hashes/counts, overflow and trailing bytes.

Query captures are required even when external originals are omitted; do not
emit them twice in the optional-originals section, which covers external File
originals. The inventory must match verified SourceQueryResultV1 entries in the
principal chain. Children have no source-query receipts in v0.6. All existing
branch/skill/catalog/Parquet verification remains mandatory and bounded.

Seal inventory V2 bytes/algorithm remain unchanged. The authenticated chain
anchors query records/capture commitments before sealing. The Parquet inventory
count is not a query-capture count. Offline verification proves IRMind's signed
admission, linkage, retained bytes and deterministic local decode/map replay,
not the truth/completeness of the remote service or a cloud-provider signature.
Re-running the remote query is a new acquisition, not reconstruction.

RemoteOriginalVerifier, RemoteOriginalVerificationV1, its admission operation and
its export section are preserved as [future design](source-queries-deferred.md),
not accepted in the v0.6 parser or enabled by this contract.

## 9. Vectors and implementation tests

[Vector inventory and method](source-query-format-vectors/README.md) fixes:

- Case marker 5, V9 magic and one empty capture count.
- Exact-plan/approval/reservation/observation/result/settlement identities,
  canonical preimages, a complete derived capture, page commitment and V9 tail.
- Analytics eligibility with null scan metrics, a rejected Basic plan and a
  partial result; malicious literal remains data.
- Public synthetic Analyst/Agent signatures using the unchanged audit challenge.
- Mutation vectors for altered query after approval, changed allocation/source,
  missing/reordered pages, changed capture, fabricated zero scans, rejected child
  attempts and duplicate settlement.

Vectors are format examples/reference calculations only. They do not claim an
executor, verifier or all current application admission logic has been implemented.
The implementation must add tests for every failure above plus source-specific
HTTP contracts, malformed/oversized streaming records, no system temporaries,
disk exhaustion, cancellation/blocked callbacks, rollback and crash recovery,
concurrent principal oversubscription, malicious obedient model attempts,
child rejection and offline V9 reconstruction. Golden tests must also run
with serde_json/preserve_order and 1/N workers without changing current golden.

No real cloud calls, billable dry runs or credentials in CI. Release benchmarks
measure compiler/preflight and retained-result decode/map/write separately from
fake-service latency; optional real-service validation stays an analyst action.
Implementation order: shared types/compiler/admission/broker/records/capture and
case 5/export V9 with no captures; Athena; BigQuery; Analytics-only Azure; then
budget/status-bar/docs and optional per-service real validation. Each step has
its own PR and fake-service contracts. New dependencies still require approval. This proposal does not itself enable
any module or introduce a dependency.
