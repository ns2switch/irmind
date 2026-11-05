use super::*;
mod columns;
use irmind_domain::{GraphQueryFilter, ParquetArtifact, ScopePartitionValue};
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::collections::BTreeSet;

pub(super) fn report_storage(
    store: &LocalStore,
    id: &CaseId,
    root: &Path,
    scenario: &Scenario,
) -> u64 {
    let entries = store.entries(id).unwrap();
    let catalog = irmind_app::artifact_catalog(&entries).unwrap();
    let mut partitions = BTreeSet::new();
    let mut ordinary_hosts = BTreeSet::new();
    let mut overflow = 0usize;
    let mut columns = columns::ColumnBudget::default();
    for artifact in &catalog.active {
        if let ParquetArtifact::V2(v) = artifact {
            partitions.insert(v.partition.path_prefix().unwrap());
            for scope in &v.partition.scopes {
                match &scope.value {
                    ScopePartitionValue::Ordinary(host)
                        if scope.key == irmind_domain::ScopePartitionKey::Host =>
                    {
                        ordinary_hosts.insert(host);
                    }
                    ScopePartitionValue::Overflow(_) => overflow += 1,
                    ScopePartitionValue::Ordinary(_) => {}
                }
            }
        }
        let file =
            fs::File::open(root.join("parquet").join(id.as_str()).join(artifact.path())).unwrap();
        let reader = SerializedFileReader::new(file).unwrap();
        columns.observe(artifact, reader.metadata());
    }
    let coobs = catalog
        .all
        .iter()
        .filter(|a| a.schema_version().starts_with("irmind-coobservations-"))
        .map(ParquetArtifact::size)
        .sum::<u64>();
    println!(
        "PARQUET_LAYOUT scenario={} historical_files={} active_files={} partitions={} ordinary_hosts={} overflow_artifacts={overflow} active_bytes={}",
        scenario.name(),
        catalog.all.len(),
        catalog.active.len(),
        partitions.len(),
        ordinary_hosts.len(),
        catalog
            .active
            .iter()
            .map(ParquetArtifact::size)
            .sum::<u64>()
    );
    columns.print(&scenario.name());
    coobs
}

pub(super) fn report_queries(
    store: &LocalStore,
    id: &CaseId,
    scenario: &Scenario,
    profile: &ParquetProfile,
) -> bool {
    let filter = GraphQueryFilter::default();
    let mut met_target = sample_queries(store, id, scenario, &filter, "all", profile);
    if let Some(hosts) = scenario.hosts {
        for host in [0, hosts - 1].into_iter().collect::<BTreeSet<_>>() {
            let name = format!("endpoint-{host:04}");
            let filter =
                GraphQueryFilter::parse_with_host(None, None, None, None, None, Some(&name))
                    .unwrap();
            met_target = sample_queries(store, id, scenario, &filter, &name, profile) && met_target;
        }
    }
    met_target
}

fn sample_queries(
    store: &LocalStore,
    id: &CaseId,
    scenario: &Scenario,
    filter: &GraphQueryFilter,
    scope: &str,
    profile: &ParquetProfile,
) -> bool {
    let (kind, value, to_kind, to_value) = scenario.target();
    let value = if scope.starts_with("endpoint-") {
        scope
    } else {
        value
    };
    let mut met_target = true;
    for label in ["term", "entity", "neighbors", "timeline", "path"] {
        let before = profile.query_detail_snapshot();
        let mut timings = Vec::new();
        let mut errors = 0;
        for _ in 0..5 {
            let started = Instant::now();
            let result = match label {
                "term" => store
                    .text_search_filtered(id, filter, &scenario.term(scope), 10)
                    .map(|_| ()),
                "entity" => store
                    .entity_lookup_filtered(id, filter, kind, value)
                    .map(|_| ()),
                "neighbors" => store
                    .neighbors_filtered(id, filter, kind, value, 10)
                    .map(|_| ()),
                "timeline" => store.timeline_filtered(id, filter, 10).map(|_| ()),
                _ => store
                    .graph_path_filtered(id, filter, (kind, value), (to_kind, to_value))
                    .map(|_| ()),
            };
            timings.push(started.elapsed());
            if result.is_err() {
                errors += 1;
            }
        }
        timings.sort();
        println!(
            "PARQUET_QUERY scenario={} scope={scope} name={label} p50_seconds={:.3} p95_seconds={:.3} errors={errors}",
            scenario.name(),
            timings[2].as_secs_f64(),
            timings[4].as_secs_f64()
        );
        let after = profile.query_detail_snapshot();
        let phase = std::array::from_fn::<_, 4, _>(|i| {
            after[i].checked_sub(before[i]).unwrap().as_secs_f64() / 5.0
        });
        println!(
            "PARQUET_QUERY_PROFILE scenario={} scope={scope} name={label} verify_seconds={:.6} scan_seconds={:.6} normalize_seconds={:.6} aggregate_seconds={:.6}",
            scenario.name(),
            phase[0],
            phase[1],
            phase[2],
            phase[3]
        );
        met_target &= errors == 0 && timings[4] < std::time::Duration::from_secs(10);
    }
    met_target
}
