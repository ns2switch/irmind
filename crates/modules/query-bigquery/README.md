# BigQuery Cloud Audit Logs

This experimental adapter targets on-demand GoogleSQL jobs in the project that
owns the dataset. Configure a Cloud Logging sink with a BigQuery dataset as its
destination. Use a dedicated dataset and grant the sink writer identity access
to write there. Grant the separate query identity read access to the adopted
dataset and permission to create jobs in the project. Start with the
[Cloud Logging sink setup](https://docs.cloud.google.com/logging/docs/export/configure_export_v2)
and [BigQuery export schemas](https://docs.cloud.google.com/logging/docs/export/bigquery).

Set the sink inclusion filter for the supported log families.

```text
LOG_ID("cloudaudit.googleapis.com/activity")
OR LOG_ID("cloudaudit.googleapis.com/data_access")
OR LOG_ID("cloudaudit.googleapis.com/system_event")
```

See [Cloud Audit Logs and Data Access settings](https://docs.cloud.google.com/logging/docs/audit).

Choose the table layout at sink creation. In the Console, choose whether to use
partitioned tables. With `gcloud logging sinks create`, pass
`--use-partitioned-tables` for timestamp partitioning. The default export uses
UTC date suffixes. Write to distinct datasets when moving between layouts. For
a daily-table dataset, reserve each wildcard prefix for the sink's own
consistently shaped base tables. BigQuery can use the schema of the latest
table matching a wildcard, so unrelated backup tables and views must stay
outside the prefix. [Wildcard rules](https://docs.cloud.google.com/bigquery/docs/querying-wildcard-tables).

In the analyst-adopted source, choose one base name in `table`
(`<dataset>.cloudaudit_googleapis_com_activity`, `_data_access`, or
`_system_event` with the same prefix) and declare exactly one descriptor in
`partitions`.

| Sink layout | Descriptor | Query |
| --- | --- | --- |
| Partitioned on the event timestamp | `{"name":"layout","type":"text","value":"timestamp-partitioned"}` | Exact table with a half-open `timestamp` interval. |
| UTC daily tables | `{"name":"layout","type":"text","value":"date-sharded"}` | The adapter appends `_*` and uses bound `_TABLE_SUFFIX BETWEEN` dates plus the same exact time interval. |

The daily filter stops at the UTC date of the last microsecond before the end
of the half-open interval. Supply the base name without a wildcard or date.
The model selects an adopted source ID and cannot set its table or layout.

The full reserved billed-byte limit goes to `maximumBytesBilled`. A processed
byte dry-run estimate can inform approval while the billed total is uncertain.
Settlement uses the final `totalBytesBilled` value, separately from processed
bytes. [On-demand pricing](https://cloud.google.com/bigquery/pricing) ·
[Job statistics](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/Job#JobStatistics2).

## Service-account authentication design

The application obtains short-lived Google access tokens from the configured
service account. The exchange uses the pinned Google OAuth endpoint and the
BigQuery-specific scope supported by [jobs.insert](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/insert#authorization-scopes).
The IAM grants restrict table access to approved datasets and allow job
creation in the query project. Queries use the structured compiler. The
private key remains in the IRMind keystore. Tokens are used only in HTTP
authorization and are excluded from signed plans, captures, diagnostics and
exports.

The shared implementation can move the existing RS256 signing and bounded
OAuth token exchange from the Chronicle adapter into `irmind-http`. An optional
feature would use the same `ring 0.17.14` already pinned in the workspace.
Chronicle keeps its existing identity, credential names and scope. BigQuery
uses its own keystore source binding. No production package needs a new
third-party crate. Both services keep separate tokens and test the exchange
against local fake endpoints. Issuing and refreshing a token occurs only after
an authorized operation, with bounded requests and cancellation.
