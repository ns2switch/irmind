# Source-side queries for v0.6

[Español](../es/source-queries-design.md)

**Status: architecture approved with the adjustments below; not implemented or enabled.**
This proposes remote, read-only evidence queries through independently selectable
modules. It does not enable a provider, provision cloud resources, add credentials
or dependencies, or change a current port or signed format. The
[source/mapping pipeline](source-mapping-design.md),
[common schema](common-event-schema.md), [budget controls](../configuration.md)
and [subagent design](subagents-design.md) remain the starting contracts.

## 1. Scope and priorities

| Priority | Module and source | Proposed delivery |
| --- | --- | --- |
| v0.6 first | `query-athena`: existing CloudTrail tables over S3 | Athena SQL engine 3, a fixed Glue catalog/database/table and enforced workgroup; native CloudTrail rows. |
| v0.6 first | `query-bigquery`: existing Cloud Audit Logs tables | BigQuery REST v2, fixed billing project, location and approved tables/views; on-demand query jobs with a provider byte cap. |
| v0.6 after those contracts pass | Security Lake through `query-athena` | Existing regional Lake Formation query access and OCSF tables; no separate query engine or subscriber provisioning. |
| v0.6 after those contracts pass | Cloud Logging Log Analytics through `query-bigquery` | An already linked BigQuery dataset/log view; same job, scope and scan controls. The UI is now documented as Observability Analytics. |
| Later, explicit opt-in design extension | `query-cloudtrail-lake` | Existing customers only; unknown preflight scan estimate and no documented equivalent of BigQuery's per-job byte cap. |
| Later, cost-enforcement prerequisite | `query-azure-data-explorer` | Fixed cluster/database/table, Kusto read-only query endpoint; no management operations. |
| v0.6, Analytics tables only | `query-azure-log-analytics` | Fixed workspace and verified Analytics table plan, Azure Monitor Logs Query API v1 with generated KQL. Entra client credentials require a separate concrete approval. |

These are priorities, not release promises. AWS states that **CloudTrail Lake is
closed to new customers from 2026-05-31**; it is not the onboarding recommendation.
Security Lake query access uses Lake Formation tables, commonly through Athena.
Cloud Logging SQL from external clients uses linked BigQuery datasets. These
facts favor two reusable execution modules before additional service adapters.
[CloudTrail availability/API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartQuery.html),
[Security Lake query access](https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-query-access.html),
[Cloud Logging linked datasets](https://docs.cloud.google.com/logging/docs/analyze/query-and-view).

Each module has its own Cargo feature, manifest, configuration, contract suite
and experimental status. No source-side query is available merely because the
binary contains its module. Source configuration and policy admission are required.
IRMind does not create tables, export sinks, subscriptions, workgroups or datasets.

## 2. Bounded structured query

Propose a validated domain value `SourceQueryV1`; the model never supplies SQL,
KQL, URLs, table names, credentials or service request options. Reuse validated
common-field and entity-role types rather than text field paths.

| Component | Proposed closed representation and limits |
| --- | --- |
| Source | One configured `SourceId` and one analyst-approved dataset alias; resolve to immutable account/project/workspace, region/location and table identity before approval. No wildcard or cross-service source expression. |
| Time | Required UTC half-open interval `[from, to)`, nonempty, within both case and organization scope. Proposed independent organization default: 31 days (2,678,400 seconds), configurable under a compiled bound in the concrete contract. Case scope, scan budget and approval still apply; do not inherit the SIEM 24-hour cap. Date-partitioned sources must prune every included date partition. No implicit recent window or server clock expression. |
| Filters | AND of at most 16 predicates; equality, finite membership (at most 32 values), typed range, literal prefix and explicit missing-field test. No arbitrary Boolean expression, regex, function, subquery or negation of scope. |
| Fields | At most 32 approved common fields: timestamp, category/type/action/outcome, actor/target identities, source/destination IP and port, host, cloud and resource identity. Each backend advertises an exact supported subset. |
| Values | Checked enums, integers, IPs and UTC instants; bounded text of at most 256 UTF-8 bytes. Control characters and invalid Unicode/identifiers are rejected. Literal punctuation remains data. |
| Result | Events, exact count, count grouped by at most two approved fields, or top counts. No joins, UDFs, arbitrary arithmetic, approximate distinct count, writes or exports to a model-chosen location. |
| Evidence rows | Separate acquisition policy, proposed up to 100,000 rows or 100 MB (100,000,000 decoded payload bytes), whichever comes first across all pages; also reserve case-wide rows and retained bytes. Provider and parser limits can reduce this. A row cap is not a scan cap. |
| Model view | Existing bounded tool summary/context only; never send the full acquisition to the model. Subsequent timeline/search/entity queries run locally over the derived source. |
| Work | Existing calls, guard, stream, record, custody and context limits remain. The dedicated acquisition path streams bounded pages/chunks under the new retained-evidence policy; it does not increase existing SIEM tool-response limits. Explicit scan, elapsed-time, frequency and case-retention admission are additional. |

Illustrative data, **not a currently supported command or installed definition**:

```json
{
  "version": 1,
  "source": "aws-lab",
  "dataset": "cloudtrail-management",
  "from": "2026-11-17T00:00:00Z",
  "to": "2026-11-18T00:00:00Z",
  "filters": [
    {"field": "event.category", "op": "eq", "value": "authentication"},
    {"field": "event.outcome", "op": "eq", "value": "failure"}
  ],
  "fields": ["@timestamp", "event.action", "user.target.name", "source.ip"],
  "result": "events",
  "limit": 100000
}
```

The engine validates scope first, resolves mapping capabilities, then compiles a
single read-only AST using versioned adapter-owned identifiers/operators. An
unrecognized field, conflicting source, unsupported filter or absent account
binding is an actionable error, never a retry without that restriction. The
model cannot add sources by encoding them in a value.

Resource identifiers from signed configuration must still pass the service's
identifier grammar and exact allowlist: a signature does not make a SQL fragment
an identifier. Literal-prefix translation must escape `%`, `_` and the escape
character where a dialect uses LIKE, or use an adapter-owned literal-prefix
operator with equivalent semantics. Parameter binding alone does not remove
wildcard semantics.

### Translation and completeness

| Service | Safe translation and result retrieval |
| --- | --- |
| Athena / Security Lake | Fixed `SELECT` skeleton, explicit columns and order, positional `?` execution parameters in supported predicate positions. The adapter encodes each typed value as an Athena parameter literal; parameter strings are not raw SQL supplied by the model. Catalog/table/partition-column names come only from signed configuration. Use `StartQueryExecution`, poll `GetQueryExecution`, page `GetQueryResults`, cancel with `StopQueryExecution`. |
| BigQuery / linked Logging | GoogleSQL with named typed `queryParameters`, `useLegacySql=false`, frozen table references and location. Use REST v2 jobs with a chosen job ID for idempotency; dry-run the identical resolved plan, then execute with `maximumBytesBilled`, poll and retrieve bounded results. No remote functions or external connections. |
| CloudTrail Lake | `StartQuery.QueryStatement` from a closed AST and a tested typed-literal encoder. Its `QueryParameters` is documented for dashboard query aliases, not arbitrary prepared predicates: do not assume general parameter binding. Poll `DescribeQuery`, page `GetQueryResults`; no optional S3 delivery in the initial adapter. |
| Azure Data Explorer | POST `/v2/rest/query`, fixed database/table and `x-ms-readonly`; declared scalar query parameters supplied in `properties.Parameters`. Compiler-owned timeout/truncation options only. No `/mgmt`, stored functions, cross-cluster expressions, plugins or external data. |
| Azure Log Analytics | POST `/v1/workspaces/{fixed-id}/query`, explicit `timespan` and an identical `TimeGenerated` predicate. The public request shape is not assumed to support ADX's parameter bag. Generate a small KQL AST with a dedicated scalar-literal encoder; never concatenate model text. No `workspace()`, `app()`, `resource()`, unions, search jobs or cross-resource queries. |

Parameter support and request shapes:
[Athena](https://docs.aws.amazon.com/athena/latest/ug/querying-with-prepared-statements.html),
[BigQuery](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query),
[CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartQuery.html),
[Kusto HTTP](https://learn.microsoft.com/en-us/kusto/api/rest/request),
[Kusto parameters](https://learn.microsoft.com/en-us/kusto/query/query-parameters-statement),
[Azure Logs API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview).

Common-schema filters require a versioned source-field translation associated
with the selected mapping. For example, authentication/failure over CloudTrail
means the mapper's documented operation/status rules, not a text search for
"failure". Preserve absence/unknown and role/namespace semantics. If exact
pushdown is unavailable, v0.6 rejects that semantic filter and explains the
coverage gap. It must not run an unfiltered query and discard rows after a
provider LIMIT, then claim completeness. Counts require exact pushdown too.
No implicit full-table fetch or cross-cloud join substitutes for missing support.

Generated queries have deterministic ordering by source time and a documented
native tie key where available. Receipt-bound page tokens cannot be supplied by
the model or moved across jobs; repeated/missing pages are detected. A service
without snapshot-stable paging is labelled accordingly, not described as a
point-in-time reconstruction.

## 3. Scan budget, estimates and approval

The current `CaseBudgetLimits.cloud_bytes` measures reserved **object transfer**,
not remote engine scans. Keep it intact. Propose separate `scan_bytes_per_query`,
`scan_bytes_per_case`, and `scan_approval_threshold` in organization policy, plus
analyst-signed case allocations no greater than that ceiling. No configured scan
allocation makes scan-priced adapters unavailable. Verified Analytics queries use
the explicit no-query-charge admission below, never a fabricated zero-byte scan. No production default is silently
increased. The model cannot edit any allocation.

The unit must be explicit: bytes processed, bytes billed, object bytes and bytes
returned are different counters. Record original provider statistics as well as
the adapter's versioned budget interpretation. For on-demand BigQuery reserve
against its billed-byte ceiling and retain processed bytes separately; Athena
records scanned bytes. Capacity-based CPU/slot costs are not converted into a
fictional byte or currency amount. Prices, when explicitly configured, have a
currency, region, unit and version; otherwise cost is unavailable.

| Backend | Preflight and provider enforcement | Consequence |
| --- | --- | --- |
| BigQuery | Dry run of the exact job; `maximumBytesBilled` in the real job. External/federated tables or row-security cases can make estimates unusable. | Initial support is on-demand approved native tables/views with verified accounting. An unreliable estimate requires signed approval; an unknown or unenforceable ceiling is denied. |
| Athena | Resolve approved date/account/region partitions, verify fixed workgroup with `EnforceWorkGroupConfiguration` and `BytesScannedCutoffPerQuery`; inspect bounded metadata when authorized. Compressed source sizes/EXPLAIN are not a guaranteed billed-byte dry run. | Sign the estimate's basis and uncertainty. Without a defensible bound, require approval and a workgroup cutoff no greater than the reserved allowance. Never change workgroup settings automatically. |
| Security Lake | Same Athena cutoff; derive partitions from the registered table schema, not guessed directory conventions. | Missing partition metadata means unknown estimate, not zero. Lake Formation controls remain additional. |
| Linked Cloud Logging | BigQuery job controls apply; check actual table/view and dry-run limitations. | A link is provisioned by the administrator, never by IRMind; billing project is explicit. |
| CloudTrail Lake | `DescribeQuery` reports `BytesScanned` after execution; time predicates are not a guaranteed scan ceiling. | Later support requires a reviewed unknown-cost policy; signed approval alone cannot override a hard byte ceiling. |
| Azure Log Analytics, Analytics only | Check the exact table plan and interactive retention before every execution; ordinary read queries only. Provider pricing distinguishes this from scan-priced plans. | Admit under explicit Analytics policy plus time, rows, retained bytes and rate limits. Record “no query charge under the table plan”; scanned/billed bytes are unavailable unless actually reported, not zero. |
| ADX / Basic / Auxiliary | No enforceable scan-priced ceiling established here for ADX; Basic/Auxiliary are excluded regardless of approval. | Unavailable by default; never substitute result-size, ingestion charges or CPU for scan bytes. |

Provider constraints:
[BigQuery dry-run limitations](https://docs.cloud.google.com/bigquery/docs/running-queries),
[Athena cutoff](https://docs.aws.amazon.com/athena/latest/APIReference/API_WorkGroupConfiguration.html),
[Athena cancellation charges](https://docs.aws.amazon.com/athena/latest/ug/workgroups-setting-control-limits-cloudwatch.html),
[CloudTrail statistics](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeQuery.html),
[Kusto resource statistics](https://learn.microsoft.com/en-us/kusto/concepts/query-resource-consumption),
[Azure Logs statistics](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/prefer-options).

Admission is atomic across the principal and all children: existing used amounts
+ outstanding reservations + this reservation must fit case and organization
ceilings. An estimate is not the reservation: reserve the admitted execution
ceiling. Show the resolved source/scope, interval, query text and typed bindings,
estimate/range/unknown, maximum reservation and cost availability before signed
approval whenever the threshold is exceeded or the estimate is unreliable.
Bind approval to the exact plan hash, configuration, mapping identity and budget
revision. Any change invalidates it. Existing policy-required external approvals
still apply even below this cost threshold.

Poll using bounded backoff. Cancellation requests do not release the reservation
until terminal provider status and usage are reconciled. Charge failed/cancelled
jobs if the service reports usage. A submitted execution with unknown outcome
remains reserved and blocks conflicting work; do not blindly submit again after
a timeout. Athena may scan beyond its cancellation trigger: record the reported
overrun honestly and block subsequent queries, never pretend the trigger is an
exact physical ceiling. This proposal does **not** extend the approved model-token
debt exception to scan budgets. Services unable to meet an organization's hard
enforcement requirement remain disabled. A future soft-cost policy is a separate
decision, not part of this design's default.

`/budget` shows scans used/reserved/remaining, scanned versus billed versus
transferred bytes, uncertain/unsettled executions, and estimated monetary cost
only when available. A new closed status-bar segment shows scan usage and the
existing 80% warning behavior. Exhaustion names the counter and points to
`/budget`; changing it remains an analyst-signed operation under the ceiling.
Neither local result caching nor provider query-cache hits are presumed free;
use reported statistics and label cache/reuse explicitly.

### Azure Analytics eligibility and accounting

The official [Azure Monitor pricing, Query section](https://azure.microsoft.com/en-us/pricing/details/monitor/)
confirms no query charge for Analytics, and per-GB scanned charges for Basic and
Auxiliary. This is not a claim that ingestion, retention, export or the workspace
is free. [Cost guidance](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-logs)
also distinguishes long-term-retention searches. v0.6 excludes archive/search
jobs, restored/search-result tables, cross-table/resource expressions and
provider functions whose underlying sources cannot be enumerated.

Before each submit, read the configured table through the
[Tables Get API, 2025-07-01](https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/get?view=rest-loganalytics-2025-07-01),
requiring explicit `plan=Analytics`, readable effective interactive retention and
stable provisioning state. Missing/unknown metadata, Basic/Auxiliary or a window
outside interactive retention is a visible rejection. Re-read immediately before
submit and record a post-query observation; a change invalidates admission for
future calls. The metadata and query APIs do not provide an atomic table-plan
lock: record that race honestly, do not promise protection against an external
administrator changing billing mid-query. An organization requiring that stronger
guarantee leaves the adapter unavailable.

Start with `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` and
`AzureActivity`; resolve their actual schemas and existing Entra/Azure Activity
mapping contracts, including any missing exact pushdown. Use `TimeGenerated`
bounds plus native event time where the mapping requires it. Do not silently
substitute one time axis or classification for another.

Proposed defaults, reducible by organization/case: 31-day interval, 100,000 rows,
100 MB decoded evidence, 180 seconds elapsed time, one in-flight query and six
submissions per rolling minute for the configured workspace/credential, shared
across parent and children. Retry attempts also consume rate/call budget; no
automatic query splitting or resubmission to circumvent a limit. The stricter
[provider limits](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits)
always win. Unknown scan bytes stay `null` with reason `not_reported`, while the
query-price basis is `analytics_no_query_charge`. Do not debit fictional bytes
or display a whole-workspace zero cost. Retention, transfer and tool budgets
still apply. New Entra client-credentials admission is not approved by this design.

## 4. Credentials, scope and minimum permissions

Source credentials and refresh/session material live only in the keystore, not
environment variables, arguments, configuration, translated SQL or receipts.
Reuse existing AWS SigV4 and Google RS256/keystore adapters where applicable;
Azure client authentication is a proposed new credential flow requiring concrete
approval: tenant/client identifiers and client secret in the keystore, separate
tokens for management-plane table metadata and Logs Query audiences, in-memory
access tokens only. Use the documented
[Entra client-credentials flow](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api);
no delegated/ambient fallback or new secret is activated by this document. Require full TLS/hostname verification and the existing per-source
CA option. No ambient credential discovery. Endpoints and result locations come
from analyst configuration; reject redirects that would forward authentication
to another origin. Check region, billing project and resource owner independently
of model arguments and re-check resolved metadata before execution.

Effective query scope is the intersection of organization ceiling, case scope,
configured tables/partitions and (for a child) assigned sources and narrower
scope. A subscription-level identity or cross-account table does not grant
case-wide access. Account/project/region predicates are compiler-injected and
cannot be replaced by a user predicate. Query tables without reliable tenant
isolation are unavailable for a narrower case. Do not silently widen to an
instance, workspace or organization. There is no new model tool to configure scope.

"Read-only" means no changes to **source evidence**. Query execution can create
provider jobs, anonymous result tables or output objects. The analyst must see
those bounded side effects. A dedicated Athena result prefix is the sole allowed
write destination; no source-bucket write, DDL/DML, persistent destination table,
result publishing or IAM modification is allowed. Prefer preconfigured lifecycle
cleanup by the administrator over granting IRMind object deletion.

| Service | Minimum grant example, scoped to configured resources |
| --- | --- |
| Athena | `athena:GetWorkGroup`, `StartQueryExecution`, `GetQueryExecution`, `GetQueryResults`, `StopQueryExecution` on one workgroup ARN. Glue read metadata only on the configured catalog/database/table. Source S3 List/Get only on approved prefixes; result-bucket location/List/Get/Put and required multipart lifecycle operations only on its dedicated result prefix. KMS decrypt for sources, and narrowly scoped result-key encryption grants only if the deployment uses them. No FullAccess managed policy. |
| Security Lake | Athena permissions above plus Lake Formation SELECT/DESCRIBE on shared regional tables and `lakeformation:GetDataAccess` as required by that access model. Administrator creates grants/resource links; IRMind never grants itself access or creates subscribers. |
| CloudTrail Lake | `cloudtrail:StartQuery`, `DescribeQuery`, `GetQueryResults`, `CancelQuery`, `GetEventDataStore` for the fixed event-data-store deployment. Action/resource support must be validated separately; no `CreateEventDataStore`, ingestion or optional result delivery. |
| BigQuery | Custom execution-project role with `bigquery.jobs.create`, and Data Viewer on the exact allowed dataset/table or authorized view. No project Editor, dataset creator or Data Editor. Own-job retrieval/cancellation must pass native service tests without adding broad job-administrator access. |
| Linked Cloud Logging | BigQuery grants plus Logs View Accessor on the exact log view as required by linked-view access. No Logging Admin or link creation. |
| ADX | Database Viewer on a dedicated database, not database/cluster Admin or Ingestor; Viewer reads the database broadly, so use administrator-managed restricted views/database separation where scope is narrower. |
| Azure Log Analytics | `Microsoft.OperationalInsights/workspaces/tables/read` to verify the plan, workspace metadata/query read plus table data/read restricted by granular RBAC to approved tables/rows. Prefer Log Analytics Data Reader with scoped conditions over broad Reader/Contributor; no sharedKeys, ingestion, search-job or workspace-write permissions. |

Permission references:
[Athena actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_athena.html),
[Athena workgroup policy examples](https://docs.aws.amazon.com/athena/latest/ug/example-policies-workgroup.html),
[CloudTrail IAM resources](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_service-with-iam.html),
[BigQuery query permissions](https://docs.cloud.google.com/bigquery/docs/running-queries),
[linked-view access](https://docs.cloud.google.com/logging/docs/analyze/query-with-bigquery-studio),
[ADX roles](https://learn.microsoft.com/en-us/kusto/access-control/role-based-access-control),
[Azure granular RBAC](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/granular-rbac-log-analytics).

An illustrative Athena workgroup statement (incomplete without the separate
resource-scoped Glue/S3/KMS grants described above):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["athena:GetWorkGroup", "athena:StartQueryExecution",
      "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution"],
    "Resource": "arn:aws:athena:eu-west-1:111122223333:workgroup/irmind-lab"
  }]
}
```

A GCP custom execution role example is `{"includedPermissions":["bigquery.jobs.create"]}`
on the billing project, paired with `roles/bigquery.dataViewer` on one approved
dataset/view. Azure's role shape is `Actions = [workspace/read, workspace/query/read]`
and `DataActions = [workspace/tables/data/read]` using the full
`Microsoft.OperationalInsights/workspaces/...` names, assigned at the configured
workspace with table/row conditions. These are deployment templates, not claims
of tested policies. CloudTrail action-level resource constraints and each
deployment's encryption grants are explicit contract-test/real-validation gates;
if an endpoint/permission cannot be confirmed, that adapter fails unavailable
with the missing grant named, without broadening permissions automatically.

## 5. Custody, derived evidence and mapping

Propose the following **new records for a later concrete format review**; names
here do not allocate audit tags or alter current golden bytes:

| Record | Signed content and purpose |
| --- | --- |
| `SourceQueryPlanV1` | Canonical structured query, exact compiled query UTF-8 and ordered typed bindings, translator/version/hash, source configuration commitment, account/project/workspace, region, scope, timestamp, mapping/decoder identities, limits, estimate basis and reservation/approval references. Secrets and Authorization headers excluded. |
| `SourceQueryExecutionV1` | Plan hash, service execution/request ID, idempotency key, submitting actor/child, local submit/finish instants and reported service instants, state, provider usage units/counters, reservation settlement, retries/cancellation and explicit unknown fields. |
| `SourceQueryResultV1` | Execution link, page order/count, hash and byte length of each bounded captured payload and an ordered result-set commitment, row counts, provider partial/error/truncation flags and local retention limits. SourceRecordSet and mapping receipts link each derived source to this acquisition. |

Sign the plan before submission; obtain required analyst approval separately,
then sign execution/outcome and admitted evidence with the existing actor-key
rules. A child signs in its branch, never as Analyst. Capture the **full exact
translated query and bindings**, not only a hash or model-friendly explanation.
Tainted values remain tainted even in compiler-owned query text: escape terminal
display and pass any model-facing view through ContentGuard/UNTRUSTED. Do not log
credentials, temporary signed URLs, refresh tokens or raw sensitive values in
diagnostics. A requested projection that could expose secrets remains subject
to existing redaction and scope checks.

Persist captured response bodies in bounded, private case-local acquisition
files, never a system temporary. Hash the original captured bytes before decoding;
define whether transport decompression has occurred and record content encoding.
Commit admitted pages/receipts atomically, use the existing spool free-space,
permissions, cancellation and rollback controls, and distinguish retained partial
evidence from a successful complete query. A rejected/malformed result has a
signed rejection and usage receipt, not silently dropped rows. HTTP success alone
is insufficient: Azure Logs can return `PartialError` with HTTP 200.
[Azure response semantics](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format).

The bytes returned by the remote query become a derived source. Service-specific
bounded response decoders preserve original field names/types in `SourceRecordV1`,
including execution/page/row provenance rather than invented object offsets.
Then select the existing identified mapping, or an explicit versioned wrapper
adapter: CloudTrail for Athena/Lake, OCSF for Security Lake, Entra ID/Azure Activity
for Azure logs, and Cloud Audit Logs for BigQuery/Logging. Validate response shape
against that mapping's input contract. A missing semantic mapping produces an
honest unclassified result/coverage notice; it cannot manufacture roles/outcomes.
Aggregation rows are derived statistical results, not synthetic authentication
events; preserve grouping/query/window provenance without treating counts as
original events. Native event IDs are retained only when actually supplied.

The export must include the query, bindings, plan/approval/execution/usage records,
captured results, source/mapping commitments and child-branch proofs, subject to
existing per-frame **1 MiB** and guard/stream limits. Large results span bounded
evidence assets, never one oversized audit frame. Current case marker 4 and
export V8 do not silently acquire new semantics: propose the next case/export
format with explicit query-acquisition sections in a separate contract and
golden review before implementation. Do not change the `export_case` port name
or make verification depend on credentials/cloud access. Include the nonsecret
resolved source binding, effective scope/limit snapshot and admission proofs
needed to check the commitments offline; a configuration hash alone does not
prove that the query respected its ceiling. Never export the underlying
credential material with that snapshot.

An offline third party can verify signatures, approval/scope admission, execution
links, byte hashes, completeness of the **retained** result set and deterministic
decoding/mapping from those bytes. This authenticates IRMind's acquisition record,
not a cloud-provider signature or the truth/completeness of the remote database.
The same remote query is **not reproducible**: retention, late arrivals, permissions,
provider engine and source contents can change. Re-execution creates new evidence
and a comparison; it never replaces the signed original. Local reconstruction of
the retained result remains a separate, reproducible check.

### Fetch once, analyze locally

Acquisition and model output are different surfaces. Reserve and retain at most
the approved 100,000 rows / 100 MB per query, streamed to private case-local
files, then ingest those exact retained bytes with an identified decoder and
mapping. The next contract fixes a separate case allocation (proposed initial
1,000,000 rows / 1 GB), with organization ceilings and signed case changes. Local
index overhead is bounded separately by existing disk/ingest controls. Preserve
provider envelopes, projection, typed values, query/execution/page/row identity
and capture hashes so a selected-column result is never described as a complete
original event. Include the fields required by the selected mapping or reject
an incompatible projection; do not manufacture missing source fields.

Return only the existing guarded summary: source hash/ID, retained row/byte
counts, interval, completeness/coverage and a bounded preview. The analyst or
agent then uses the existing timeline, search, entity and evidence tools against
that local source. Repeating those local tools causes **no new remote query**.
A second remote acquisition is a new admitted, budgeted plan, not a hidden next
page of a model summary. This is the recommended cost-reduction pattern.

Stop at the first retention cap without splitting a record. Preserve a valid
complete prefix only when decoding can prove its row boundaries, and label it
partial with the exact cause; a malformed envelope is not salvaged by guessing.
Provider truncation and `PartialError` are distinct from local retention. Never
claim all matching events were acquired because the model preview is complete.
The signed frame remains 1 MiB, ContentGuard and stream limits are unchanged,
and the full evidence file never becomes a model message.

## 6. Remote re-verification after sealing

Recheck only object originals with a signed immutable identity: S3 VersionId,
GCS generation or Azure Blob version/snapshot plus the recorded ETag and length.
Use authenticated HEAD/metadata requests against the **exact signed version**;
also report if the current live object points elsewhere when authorized. An
ETag is an opaque condition, not universally a content hash. Metadata equality
is reported as identity/metadata confirmation, never SHA-256 verification.

For byte equality, separately admit a full conditional GET under transfer/scope
budget and stream SHA-256 over the exact version. Check metadata before/after;
reject a race, version substitution or missing original. Access denied, deleted,
changed and unavailable are distinct outcomes; absence cannot be inferred from
an ambiguous 403. Sources lacking immutable versions are explicitly weaker.
[S3 HEAD](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html),
[GCS generations/preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions),
[Azure Blob properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties).

A sealed chain is never reopened or appended for this. Propose a detached signed
re-verification receipt binding seal hash, object reference, verification time,
method, result, bytes/cost and actor. Store it as an additional verification
product; do not overwrite an existing export. Its transport/verification format
also needs the later concrete contract. Queries over mutable tables do not gain
object-version guarantees merely because their results were sealed.

## 7. Subagents and engine boundaries

A cloud child receives exact configured query sources as well as its permitted
local source hashes, a narrower scope and a scan reservation. The engine broker
alone holds credentials and submits queries with an unforgeable authorized-call
token. Children cannot choose accounts, add tables, increase budgets or approve
unknown-cost work. Pending approvals identify child, source, exact plan and scan
reservation. Cancellation and recovery retain unresolved provider-job holds.

Propose an additional scan-byte dimension in the shared reservation broker;
never reinterpret the current `cloud_bytes` transfer dimension. Case remaining
minus all parent/child holds is the sole allocatable pool. Apply the approved
whole-plan 25% confirmation rule to this new dimension as well; that is a
proposed extension requiring explicit contract approval. Tool, token, round and
transfer limits continue independently. No scan-debt exception is inherited from
model-output settlement. Return only guarded summaries to the parent; full
results and receipts remain in the child's verified branch and deterministic
merge/export.

Proposed new application boundary: `SourceQueryExecutor` with preflight, submit,
poll, fetch and cancel over validated plans/authorization, and
`RemoteOriginalVerifier` for version-bound metadata/hash checks. Adapters may not
sign, approve or mutate case policy. Budget reservations and receipt assembly
belong to the engine. Prefer a separate port over repurposing `ObjectSource`
as a query runner. These are **port proposals**, not approved signatures; concrete
types, cancellation/recovery and canonical vectors need review before code.

## 8. Dependencies and authentication choices

| Backend | Full SDK option | Proposed smaller alternative; review before adding anything |
| --- | --- | --- |
| Athena | AWS SDK for Athena plus Glue/STS as actually needed | Existing HTTP client, bounded AWS JSON API and existing SigV4; no generated SQL client or AWS CLI subprocess. |
| CloudTrail Lake | AWS SDK for CloudTrail | Same signed HTTP approach; existing-customer and cost-policy gates remain. |
| Security Lake | Athena/Glue/Lake Formation SDKs | Query existing shared tables through Athena; no Security Lake admin SDK in the runtime. |
| BigQuery / Logging | BigQuery SDK and Google auth libraries | REST v2 with existing keystore-backed service-account RS256/OAuth machinery; no ambient ADC or `gcloud` subprocess. Linked Logging requires no second execution client. |
| ADX / Azure Logs | Kusto / Azure Identity / Azure Monitor query SDKs | Existing HTTP/TLS client and explicitly configured Entra OAuth client credentials in keystore; assess token flow, certificate support and endpoint allowlist separately. |
| Remote objects | Existing object-store adapter | Reuse version-conditional metadata/GET where available; an additive metadata-only capability may need review. No new cloud SDK by default. |

No dependency, feature, credential or port change is authorized by this design
publication. Implementation must first inventory the exact existing signer/auth
APIs, benchmark SDK footprint versus HTTP, document minimum API/region support,
then request approval for additions. No external CLI handling secrets and no
automatic fallback to environmental credentials.

## 9. Contract tests and optional analyst validation

CI uses fake service endpoints, synthetic credentials and recorded synthetic
responses, never real cloud accounts or paid scans. The minimum suite covers:

- AST/golden requests for every enabled adapter and each supported filter,
  stable binding order and identical scope predicates for model and child calls.
- Malicious values such as `' OR 1=1 --`, backticks, `'; .drop table X`, pipes,
  `workspace("other")`, LIKE wildcard/escape characters, encoded newlines and Unicode controls: reject invalid
  values or bind/encode them as a single literal, with no additional syntax.
  Reject malicious table/field identifiers rather than quoting arbitrary input.
- Account/project/region/workspace substitution, unsupported semantic filters,
  manipulated metadata, absent mappings and unknown credential/endpoint cases.
- Dry-run zero/unknown estimates, changed plan between approval and submit,
  provider scan-cap rejection, partial/cancelled charged work, cache statistics,
  concurrency oversubscription, crash recovery and unknown-outcome holds.
- Pagination replay/cross-job tokens, invalid/oversized rows, duplicate IDs,
  malformed response schemas, HTTP 200 partial errors and explicit truncation.
- Fake obedient model plus malicious evidence/skill/child attempting arbitrary
  SQL, external URLs, scope expansion, budget edits or self-approval; no execution.
- Signed receipts, mutation/reordering/removal, derived-result reconstruction,
  verification without network, seal/export round trip and detached sealed-object
  verification without modifying the case chain.
- S3/GCS/Blob exact-version match, changed live version, deletion, denied access,
  ETag equality with a different byte hash, mid-read races and cancelled GET.

After implementation, add an optional analyst guide for one disposable source
per supported service: provision a small public/synthetic dataset independently,
record exact service/region/table schema, create minimal read/query grants and
keystore credentials, set low scan/transfer caps and an approval threshold, run
one event query and one exact count, then test rejection/approval, budget usage,
verification, seal and offline export verification. Record actual billed metrics
from the service, cleanup jobs/results with administrator tooling, and revoke
test credentials. Never run this paid/credentialed procedure automatically.

| Service / API / region | IRMind / adapter / mapping version | Estimate and basis | Cap / actual scanned / billed / returned | Approval / partial | Hash / seal / export | Result and untested checks |
| --- | --- | --- | --- | --- | --- | --- |
| Pending analyst execution after implementation | | | | | | |

## 10. Review and implementation sequence

1. Review this scope, the unavailable-by-default unknown-cost cases and the new
   scan dimension, then approve concrete ports and format vectors separately.
2. Implement shared typed query compiler/admission and receipt/export verification
   with fakes; preserve all current limits and untrusted-content boundaries.
3. Add Athena CloudTrail, on-demand BigQuery and Analytics-only Azure Logs in
   separate module PRs; Azure authentication needs its concrete approval first.
   Measure planning and bounded result decode/map/write in release builds.
4. Add Security Lake/linked Logging on those validated executors and explicit
   mappings. Publish coverage and optional real-service observations separately.
5. Revisit CloudTrail Lake and Azure Data Explorer only with a demonstrated cost-enforcement
   contract. Do not claim support based solely on successful HTTP queries.

This PR is documentation only. It does not close connector validation, authorize
cloud spending or implement any source-side query.
