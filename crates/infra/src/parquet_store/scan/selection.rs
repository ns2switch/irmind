use super::{AppError, GraphQueryFilter, ParquetArtifact, Predicate, ScanSpec, common};

pub(in crate::parquet_store) fn partition_matches(
    artifact: &ParquetArtifact,
    filter: &GraphQueryFilter,
) -> bool {
    if !filter.common().is_empty() && !common::supported(artifact) {
        return false;
    }
    let ParquetArtifact::V3(value) = artifact;
    let v = value.core();
    scope_partition_matches(&v.partition, filter)
        && filter.time_range().is_none_or(|(from, to)| {
            artifact.partition_date() == "unknown"
                || (artifact.partition_date() >= &from[..10]
                    && artifact.partition_date() <= &to[..10])
        })
}

pub(super) fn rules_for_artifact(
    spec: &ScanSpec<'_>,
    precise: bool,
    artifact: &ParquetArtifact,
) -> Result<Vec<Predicate>, AppError> {
    let mut rules = Vec::new();
    for rule in spec.predicates {
        if let Predicate::Range("event_time", from, to) = rule {
            let first = irmind_app::IndexedTime::from_rfc3339(from, false)
                .map_err(|_| super::super::invalid_source())?
                .instant();
            let last = irmind_app::IndexedTime::from_rfc3339(to, false)
                .map_err(|_| super::super::invalid_source())?
                .instant();
            rules.push(Predicate::TimeRange(first, last));
            continue;
        }
        rules.push(rule.clone());
    }
    if precise {
        if let Some(host) = spec.filter.host() {
            rules.push(Predicate::Equal("scope_host", host.into()));
        }
        if let Some(account) = spec.filter.account_or_project() {
            rules.push(Predicate::Equal("scope_account", account.into()));
        }
        if let Some(region) = spec.filter.region() {
            rules.push(Predicate::Equal("scope_region", region.into()));
        }
    }
    rules.extend(common::rules(artifact, spec.filter));
    Ok(rules)
}

fn scope_partition_matches(
    partition: &irmind_domain::ArtifactPartitionV2,
    filter: &GraphQueryFilter,
) -> bool {
    use irmind_domain::{ScopePartitionKey as Key, ScopePartitionValue as Value};
    [
        (Key::Account, filter.account_or_project()),
        (Key::Region, filter.region()),
        (Key::Host, filter.host()),
    ]
    .iter()
    .all(|(key, raw)| {
        let Some(expected) = raw else {
            return true;
        };
        let Some(scope) = partition.scopes.iter().find(|s| s.key == *key) else {
            return true;
        };
        match &scope.value {
            Value::Overflow(_) => true,
            Value::Ordinary(value) => {
                super::super::partitioning::normalize(expected).is_none_or(|n| n == *value)
            }
        }
    })
}

pub(super) fn required_columns<'a>(
    spec: &ScanSpec<'a>,
    precise: bool,
    common: bool,
) -> Vec<&'a str> {
    let mut columns = spec
        .columns
        .iter()
        .copied()
        .filter(|name| common || !common::is_extra(name))
        .collect::<Vec<_>>();
    columns.extend(["source_hash", "record_index", "event_time"]);
    if precise {
        columns.extend([
            "submicro_nanos",
            "time_precision",
            "time_inferred",
            "source_offset",
        ]);
    }
    columns.sort_unstable();
    columns.dedup();
    columns
}
