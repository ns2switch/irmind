# Manual validation of source queries

[Español](../es/source-query-validation.md)

This exercise is optional and uses an account and synthetic data that the
analyst is authorized to query. Athena and BigQuery can incur scan charges.
Use a separate case per provider and a narrow UTC interval containing known
test records. The repository test suite uses simulated providers.

## Prepare one test source

| Provider | Test source and expected accounting |
| --- | --- |
| Athena | Use a partitioned CloudTrail management-events table and a dedicated workgroup with enforced configuration and a per-query scan cutoff. Allow the workgroup's cutoff semantics explicitly in the source policy. Observe billed scan bytes with the 10 MiB minimum and MiB rounding. |
| BigQuery | Use a Cloud Logging sink containing synthetic Cloud Audit Logs. Declare the source as `timestamp-partitioned` or `date-sharded` to match the sink. Run the exercise once for each layout if both are deployed. Check the dry-run basis, maximum billed bytes and final billed bytes. |
| Azure Log Analytics | Test an Analytics-plan table from `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` or `AzureActivity`. Confirm the selected table's plan and Analytics price basis. Scan bytes are unavailable for this route. A Basic or Auxiliary test table must be rejected before a query starts. |

Use the resource and permission definitions in the
[source query design](source-queries-design.md) and the
[configuration guide](../configuration.md#source-queries). Set a small source
and case allocation that can accommodate the provider's stated minimum or
preflight estimate. Enter credentials in **Settings → Keystore**, then adopt
the source and allocate case resources as an analyst.

## Run and record

1. Ask the main agent for events from the configured source in the test
   interval. Set a low row limit, with more matching events than the limit.
   Review the translated query, scope and budget with
   `/source-query show <plan-id>` if consent is requested. Approve exactly that
   plan with `/source-query approve <plan-id>`.
2. Check that the tool and `/verify` report the local row limit. Compare
   `/budget` and the provider's usage report. Query the ingested capture
   locally by timeline or entity and compare a known event with its original.
3. Propose an out-of-scope source or interval. Confirm rejection before
   submission. For Azure, separately test rejection of a non-Analytics table.
4. Seal and export the test case. Verify the export with the expected Analyst
   public key and check the capture and partial-result notices.

| Provider and source layout | Case and export verified | Billed and reserved bytes | Retained rows and bytes | Limit notice and scope rejection |
| --- | --- | --- | --- | --- |
| Athena | | | | |
| BigQuery | | | | |
| Azure Log Analytics | | | | |
