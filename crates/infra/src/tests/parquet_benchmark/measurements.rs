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
        if let Some(v) = artifact.precise_metadata() {
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
    let active_paths = catalog
        .active
        .iter()
        .map(ParquetArtifact::path)
        .collect::<BTreeSet<_>>();
    let active_bytes = catalog
        .active
        .iter()
        .map(ParquetArtifact::size)
        .sum::<u64>();
    let inactive_bytes = catalog
        .all
        .iter()
        .filter(|a| !active_paths.contains(a.path()))
        .map(ParquetArtifact::size)
        .sum::<u64>();
    if std::env::var("IRMIND_BENCH_COMMON_EVENT").as_deref() == Ok("1") {
        assert_eq!(
            inactive_bytes, 0,
            "initial direct ingestion must not retain inactive parents"
        );
    }
    let case_bytes = directory_bytes(root);
    println!(
        "PARQUET_RETAINED_PARENTS scenario={} inactive_parent_bytes={inactive_bytes} active_artifact_bytes={active_bytes} retained_case_bytes={case_bytes} inactive_case_basis_points={} inactive_active_basis_points={}",
        scenario.name(),
        basis_points(inactive_bytes, case_bytes),
        basis_points(inactive_bytes, active_bytes)
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
        let mut time_budget_hits = 0;
        for _ in 0..5 {
            let started = Instant::now();
            let result = match label {
                "term" => store
                    .text_search_filtered(id, filter, &scenario.term(scope), 10)
                    .map(|text| text.contains("10-second time budget")),
                "entity" => store
                    .entity_lookup_filtered(id, filter, kind, value)
                    .map(|text| text.contains("10-second time budget")),
                "neighbors" => store
                    .neighbors_filtered(id, filter, kind, value, 10)
                    .map(|text| text.contains("10-second time budget")),
                "timeline" => store.timeline_filtered(id, filter, 10).map(|_| false),
                _ => store
                    .graph_path_filtered(id, filter, (kind, value), (to_kind, to_value))
                    .map(|text| text.contains("10-second time budget")),
            };
            timings.push(started.elapsed());
            if matches!(result, Ok(true)) {
                time_budget_hits += 1;
            }
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
        println!(
            "PARQUET_QUERY_EXACT scenario={} scope={scope} name={label} p50_ns={} p95_ns={} errors={errors} time_budget_hits={time_budget_hits}",
            scenario.name(),
            timings[2].as_nanos(),
            timings[4].as_nanos()
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
        met_target &=
            errors == 0 && time_budget_hits == 0 && timings[4] < std::time::Duration::from_secs(10);
    }
    met_target
}

fn basis_points(part: u64, total: u64) -> u128 {
    if total == 0 {
        0
    } else {
        u128::from(part) * 10_000 / u128::from(total)
    }
}
