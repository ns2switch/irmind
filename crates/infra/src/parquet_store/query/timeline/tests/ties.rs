use super::*;
use std::fmt::Write as _;

#[test]
fn precise_same_time_ties_keep_all_candidate_groups_without_changing_order() {
    let source = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = crate::parquet_store::fixtures::store(data.path());
    let id = CaseId::parse("00000000-0000-0000-0000-000000000025").unwrap();
    let token = CancellationToken::new();
    let mut artifacts = Vec::new();
    let mut names = std::collections::BTreeMap::new();
    for name in ["z.json", "a.json"] {
        write_tied_source(source.path(), name);
        let prepared = crate::parquet_store::fixtures::one_source(
            &store,
            &id,
            source.path(),
            name,
            false,
            &token,
        )
        .unwrap();
        names.insert(prepared.manifest.sha256.as_str().into(), name.into());
        artifacts.extend(
            prepared
                .artifacts
                .into_iter()
                .filter(|a| a.schema_version() == "irmind-events-v4"),
        );
    }
    let compacted = store.compact_artifacts(&id, &artifacts, &token).unwrap();
    let query = store.queries(&names);
    let filter = GraphQueryFilter::default();
    for inventory in [artifacts, vec![compacted]] {
        for newest in [false, true] {
            let spec = ScanSpec {
                id: &id,
                artifacts: &inventory,
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
            ordered(&mut expected, 10, newest).unwrap();
            assert!(query.timeline_hits(spec, 10, newest).unwrap() == expected);
            assert!(expected.iter().all(|hit| hit.event.starts_with("a.json")));
            assert_eq!(
                expected.iter().map(|hit| hit.index).collect::<Vec<_>>(),
                (0..10).collect::<Vec<_>>()
            );
            for artifact in &inventory {
                assert_tie_scan(
                    &store,
                    ScanSpec {
                        artifacts: std::slice::from_ref(artifact),
                        ..spec
                    },
                    &names,
                    newest,
                );
            }
        }
    }
}

fn assert_tie_scan(
    store: &ParquetStore,
    spec: ScanSpec<'_>,
    names: &std::collections::BTreeMap<String, String>,
    newest: bool,
) {
    let mut visited = 0;
    let mut hits = Vec::new();
    complete(
        store
            .scan_time_ordered_file(spec, names, newest, None, |batch| {
                visited += batch.num_rows();
                for row in 0..batch.num_rows() {
                    hits.push(EventHit::from_batch(batch, row, true)?);
                }
                ordered(&mut hits, 10, newest)?;
                Ok(hits
                    .last()
                    .map(|h| crate::parquet_store::scan::TimeCutoff(h.time.clone())))
            })
            .unwrap(),
    )
    .unwrap();
    // Equal precise instants cannot be pruned using a whole-second key bound:
    // all sources and offsets must remain candidates for stable tie ordering.
    let expected = spec
        .artifacts
        .iter()
        .map(|a| match a {
            irmind_domain::ParquetArtifact::V3(v) => v.pipeline().rows(),
            _ => unreachable!(),
        })
        .sum::<u64>();
    assert_eq!(visited as u64, expected);
}

fn write_tied_source(root: &std::path::Path, name: &str) {
    let mut text = String::new();
    for i in 0..12_000 {
        writeln!(
            text,
            "{{\"eventTime\":\"2026-11-01T00:00:00.123456Z\",\"eventName\":\"{name}-{i}\"}}"
        )
        .unwrap();
    }
    std::fs::write(root.join(name), text).unwrap();
}
