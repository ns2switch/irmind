#![allow(clippy::unwrap_used)]
use super::super::ordered;
use super::*;
use crate::parquet_store::ParquetStore;
use crate::parquet_store::scan::ScanFlow;
use irmind_app::LargeCaseStore as _;

#[test]
fn bounded_precise_timeline_matches_the_full_scan_in_both_directions() {
    let root = tempfile::tempdir().unwrap();
    let sources = tempfile::tempdir().unwrap();
    let old = crate::parquet_store::fixtures::store(root.path());
    let new = crate::parquet_store::fixtures::store(root.path());
    let id = CaseId::parse("00000000-0000-0000-0000-000000000022").unwrap();
    let token = CancellationToken::new();
    let mut names = std::collections::BTreeMap::new();
    let mut artifacts = Vec::new();
    let inputs = [
        ("a.json", "2026-11-01T00:00:00Z", &old),
        ("b.json", "2026-11-01T00:00:01.000000100Z", &new),
        ("c.json", "2026-11-01T00:00:01.000000900Z", &new),
        ("d.json", "2026-11-01T00:00:01Z", &old),
        ("e.json", "2026-11-01T00:00:01Z", &old),
        ("unknown.json", "", &new),
    ];
    for (name, at, store) in inputs {
        let row = if at.is_empty() {
            serde_json::json!({"eventName":name})
        } else {
            serde_json::json!({"eventName":name,"eventTime":at})
        };
        std::fs::write(sources.path().join(name), row.to_string()).unwrap();
        let p = crate::parquet_store::fixtures::one_source(
            store,
            &id,
            sources.path(),
            name,
            false,
            &token,
        )
        .unwrap();
        names.insert(p.manifest.sha256.as_str().into(), name.into());
        artifacts.extend(p.artifacts);
    }
    let query = new.queries(&names);
    let filter = GraphQueryFilter::default();
    for newest in [false, true] {
        for limit in [1, 2, 4, 20] {
            let spec = ScanSpec {
                id: &id,
                artifacts: &artifacts,
                filter: &filter,
                schema: "irmind-events-v4",
                columns: &["event_time", "event", "source_hash", "record_index"],
                predicates: &[],
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel: &token,
            };
            let mut expected = Vec::new();
            complete(
                query
                    .scan_artifacts(spec, |batch| {
                        for row in 0..batch.num_rows() {
                            expected.push(EventHit::from_batch(batch, row, true)?);
                        }
                        Ok(ScanFlow::Continue)
                    })
                    .unwrap(),
            )
            .unwrap();
            ordered(&mut expected, limit, newest).unwrap();
            assert!(query.timeline_hits(spec, limit, newest).unwrap() == expected);
        }
    }
    // Even an older file that could be pruned must authenticate its statistics.
    let oldest = artifacts
        .iter()
        .find(|a| a.schema_version() == "irmind-events-v4")
        .unwrap();
    std::fs::write(new.case_dir(&id).unwrap().join(oldest.path()), b"altered").unwrap();
    assert!(matches!(
        query.timeline_native(&id, &artifacts, &filter, 1, &token),
        Err(AppError::EvidenceMismatch(_))
    ));
}

#[test]
fn compacted_style_files_prune_row_groups_in_both_directions() {
    let sources = ordered_sources();
    {
        let data = tempfile::tempdir().unwrap();
        let store = crate::parquet_store::fixtures::store(data.path());
        let id = CaseId::parse("00000000-0000-0000-0000-000000000023").unwrap();
        let token = CancellationToken::new();
        let source = crate::parquet_store::fixtures::one_source(
            &store,
            &id,
            sources.path(),
            "events.json",
            false,
            &token,
        )
        .unwrap();
        let names = [(source.manifest.sha256.as_str().into(), "events.json".into())]
            .into_iter()
            .collect();
        let query = store.queries(&names);
        let events = source
            .artifacts
            .iter()
            .filter(|a| a.schema_version().starts_with("irmind-events-"))
            .cloned()
            .collect::<Vec<_>>();
        let filter = GraphQueryFilter::default();
        for newest in [false, true] {
            let spec = ScanSpec {
                id: &id,
                artifacts: &events,
                filter: &filter,
                schema: "irmind-events-v4",
                columns: &["event_time", "event", "source_hash", "record_index"],
                predicates: &[],
                deadline: Instant::now() + QUERY_DEADLINE,
                cancel: &token,
            };
            let mut hits = Vec::new();
            let mut visited = 0;
            let status = store
                .scan_time_ordered_file(spec, &names, newest, None, |batch| {
                    visited += batch.num_rows();
                    for row in 0..batch.num_rows() {
                        hits.push(EventHit::from_batch(batch, row, true)?);
                    }
                    ordered(&mut hits, 10, newest)?;
                    Ok(hits
                        .last()
                        .map(|h| crate::parquet_store::scan::TimeCutoff(h.time.clone())))
                })
                .unwrap();
            complete(status).unwrap();
            assert!(visited < 10_000, "visited={visited}; newest={newest}");
            let expected = if newest {
                (19_990..20_000).rev().collect::<Vec<_>>()
            } else {
                (0..10).collect()
            };
            assert_eq!(hits.iter().map(|h| h.index).collect::<Vec<_>>(), expected);
            assert!(query.timeline_hits(spec, 10, newest).unwrap() == hits);
        }
    }
}

fn ordered_sources() -> tempfile::TempDir {
    use std::fmt::Write as _;
    let sources = tempfile::tempdir().unwrap();
    let mut text = String::new();
    for i in 0..20_000 {
        writeln!(
            text,
            "{{\"eventTime\":\"2026-11-01T{:02}:{:02}:{:02}Z\",\"eventName\":\"Read\"}}",
            i / 3600,
            i % 3600 / 60,
            i % 60
        )
        .unwrap();
    }
    std::fs::write(sources.path().join("events.json"), text).unwrap();
    sources
}

mod ties;
