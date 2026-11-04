#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{
    GraphRecord, IndexedGraphRecord, IndexedTime, LargeCaseStore, LocalBatchRequest,
    PartitionLimits,
};
use irmind_domain::{EvidenceHash, ParquetArtifact, PartitionOverflowReason, ScopePartitionValue};

fn case() -> CaseId {
    CaseId::parse("00000000-0000-0000-0000-000000000020").unwrap()
}
fn row(n: usize) -> RecordRow {
    let record = GraphRecord {
        index: n,
        at: format!("2026-11-01T00:00:0{n}Z"),
        event: "read".into(),
        text: "{}".into(),
        entities: vec![],
        relations: vec![],
    };
    let time = Some(IndexedTime::from_rfc3339(&record.at, false).unwrap());
    RecordRow::from_partitioned(
        &IndexedGraphRecord {
            record,
            time,
            source_offset: None,
        },
        &EvidenceHash::parse(&"a".repeat(64)).unwrap(),
    )
    .unwrap()
}
#[test]
fn binary_merge_levels_keep_global_order_and_clean_every_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(dir.path()).unwrap();
    let cancel = CancellationToken::new();
    let mut levels = Vec::new();
    for n in [9, 4, 8, 1, 2, 0, 7] {
        add_run(
            &store,
            &case(),
            &mut levels,
            sorted_run(&store, &case(), vec![row(n)], &cancel).unwrap(),
            &cancel,
        )
        .unwrap();
    }
    let run = finish_runs(&store, &case(), levels, &cancel).unwrap();
    let mut reader = run.reader().unwrap();
    let mut order = Vec::new();
    while let Some(row) = reader.next(&cancel).unwrap() {
        order.push(row.sort_key().record_index);
    }
    assert_eq!(order, [0, 1, 2, 4, 7, 8, 9]);
    drop(reader);
    drop(run);
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&case()).unwrap())
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn cancellation_during_merge_drops_private_runs() {
    let dir = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(dir.path()).unwrap();
    let cancel = CancellationToken::new();
    let a = sorted_run(&store, &case(), vec![row(1)], &cancel).unwrap();
    let b = sorted_run(&store, &case(), vec![row(0)], &cancel).unwrap();
    cancel.cancel();
    assert!(matches!(
        merge(&store, &case(), &a, &b, &cancel),
        Err(AppError::Cancelled)
    ));
    drop(a);
    drop(b);
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&case()).unwrap())
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn out_of_order_input_allocates_by_the_shared_stable_order_and_rebuilds() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(data.path()).unwrap();
    std::fs::write(inputs.path().join("events.json"), b"{\"eventTime\":\"2026-11-01T00:00:02Z\",\"host\":\"late\"}\n{\"eventTime\":\"2026-11-01T00:00:01Z\",\"host\":\"early\"}\n").unwrap();
    let paths = ["events.json".into()];
    let prepared = store
        .prepare_local_batch(
            LocalBatchRequest {
                case_id: &case(),
                source_root: inputs.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &irmind_mod_parser_json::JsonParser,
                committed_artifacts: &[],
                limits: PartitionLimits {
                    host: 1,
                    ..PartitionLimits::default()
                },
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let ordinary = prepared[0]
        .artifacts
        .iter()
        .filter_map(|a| {
            if let ParquetArtifact::V2(v) = a {
                Some(&v.partition.scopes[0].value)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(ordinary.contains(&&ScopePartitionValue::Ordinary("early".into())));
    assert!(ordinary.contains(&&ScopePartitionValue::Overflow(
        PartitionOverflowReason::Cardinality
    )));
    assert!(!ordinary.contains(&&ScopePartitionValue::Ordinary("late".into())));
    store
        .rebuild_compare(
            &case(),
            inputs.path(),
            &[prepared[0].manifest.clone()],
            &prepared[0].artifacts,
            &irmind_mod_parser_json::JsonParser,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&case()).unwrap())
            .unwrap()
            .count(),
        0
    );
}
