# Athena CloudTrail

Use an on-demand Athena engine version 3 SQL workgroup dedicated to IRMind,
with enforced workgroup settings, a per-query scan cutoff and prior consent
to Athena's threshold cancellation behavior. The adapter starts with a
date-partitioned CloudTrail table and always restricts the adopted AWS account.

The `source.ip` equality filter uses Athena's IPADDRESS type and an IP binding,
so equivalent IPv6 spellings compare by address. It preserves the IP family
for IPv4-mapped IPv6 addresses. An account filter must equal
the adopted account. [Athena data types](https://docs.aws.amazon.com/athena/latest/ug/data-types.html).

Admission is based on the billed-byte ceiling. The adapter rounds the workgroup
cutoff up to a 1,048,576-byte unit with a ten-unit minimum before comparing it to
the signed ceiling. The workgroup API accepts a raw cutoff from 10,000,000 scan bytes. It keeps the raw bytes scanned separately and applies the
same rounding to successful or cancelled terminal executions. A definitive
failed execution has no Athena scan charge. When billed usage cannot be
established, the reservation remains held. [Athena pricing](https://aws.amazon.com/athena/pricing/) ·
[Workgroup controls](https://docs.aws.amazon.com/athena/latest/APIReference/API_WorkGroupConfigurationUpdates.html) · [AWS usage units](https://aws.amazon.com/blogs/big-data/amazon-athena-introduces-system-tables-for-query-execution-observability/).
