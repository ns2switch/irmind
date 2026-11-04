#![allow(clippy::panic)]
use super::*;
use irmind_domain::{GraphQueryFilter, ParquetArtifact, TimePrecision};

fn source(time: &str, event: &str) -> String {
    format!(
        r#"{{"eventTime":"{time}","eventName":"{event}","recipientAccountId":"123456789012","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.4","userIdentity":{{"userName":"alice"}}}}"#
    )
}
fn prepare(
    store: &ParquetStore,
    id: &CaseId,
    root: &Path,
    name: &str,
    rows: &str,
) -> PreparedSource {
    fs::write(root.join(name), rows).unwrap();
    store
        .prepare_local(
            id,
            root,
            name,
            false,
            &JsonParser,
            &CancellationToken::new(),
        )
        .unwrap()
}
fn names(sources: &[(&str, &PreparedSource)]) -> BTreeMap<String, String> {
    sources
        .iter()
        .map(|(name, p)| (p.manifest.sha256.as_str().into(), (*name).into()))
        .collect()
}
#[test]
fn precise_rows_retain_submicroseconds_across_all_three_artifact_families() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let rows = source("1969-12-31T23:59:59.999999900Z", "BeforeEpoch");
    let p = prepare(&store, &id, root.path(), "precise.json", &rows);
    assert_eq!(p.artifacts.len(), 3);
    for a in &p.artifacts {
        let ParquetArtifact::V2(a) = a else {
            panic!("expected V2")
        };
        assert_eq!(a.partition.date, "1969-12-31");
        let file = File::open(store.case_dir(&id).unwrap().join(&a.path)).unwrap();
        let builder =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        super::super::format::validate_schema(&a.clone().into(), builder.schema()).unwrap();
        for batch in builder.build().unwrap() {
            let batch = batch.unwrap();
            for row in 0..batch.num_rows() {
                let time = super::super::time_cell::read_time(&batch, row)
                    .unwrap()
                    .unwrap();
                assert_eq!(time.instant().unix_micros(), -1);
                assert_eq!(time.instant().submicro_nanos(), 900);
                assert_eq!(time.precision(), TimePrecision::Nanosecond);
                assert!(!time.inferred());
            }
        }
    }
    assert_eq!(
        store
            .rebuild_compare(
                &id,
                root.path(),
                &[p.manifest],
                &p.artifacts,
                &JsonParser,
                &CancellationToken::new()
            )
            .unwrap(),
        1
    );
}
#[test]
fn mixed_queries_share_numeric_time_and_signed_source_order() {
    let root = tempfile::tempdir().unwrap();
    let old = ParquetStore::open(root.path()).unwrap();
    let new = ParquetStore::open_precise(root.path()).unwrap();
    let id = CaseId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let p0 = prepare(
        &old,
        &id,
        root.path(),
        "coarse.json",
        &source("2026-11-01T00:00:00Z", "Coarse"),
    );
    let rows = format!(
        "{}\n{}",
        source("2026-11-01T00:00:00.000001100Z", "Fine1"),
        source("2026-11-01T00:00:00.000001900Z", "Fine9")
    );
    let p1 = prepare(&new, &id, root.path(), "z.json", &rows);
    let p2 = prepare(
        &new,
        &id,
        root.path(),
        "a.json",
        &source("2026-11-01T00:00:00.000001100Z", "FirstSource"),
    );
    let names = names(&[("coarse.json", &p0), ("z.json", &p1), ("a.json", &p2)]);
    let artifacts = [p0.artifacts, p1.artifacts, p2.artifacts].concat();
    let q = new.queries(&names);
    let token = CancellationToken::new();
    let filter = GraphQueryFilter::default();
    let timeline = q
        .timeline_native(&id, &artifacts, &filter, 10, &token)
        .unwrap();
    assert_eq!(timeline.len(), 4);
    assert!(timeline[0].event.starts_with("Fine9"));
    assert!(timeline[1].event.starts_with("FirstSource"));
    assert!(timeline[2].event.starts_with("Fine1"));
    assert!(timeline[3].event.contains("second precision"));
    let narrow = GraphQueryFilter::parse(
        Some("2026-11-01T00:00:00.000001100Z"),
        Some("2026-11-01T00:00:00.000001100Z"),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        q.timeline_native(&id, &artifacts, &narrow, 10, &token)
            .unwrap()
            .len(),
        2
    );
    let entity = q
        .entity_timeline_native(&id, &artifacts, &filter, ("ip", "203.0.113.4"), 10, &token)
        .unwrap();
    assert!(entity.find("Fine9").unwrap() < entity.find("FirstSource").unwrap());
    let lookup = q
        .entity_native(&id, &artifacts, &filter, "ip", "203.0.113.4", &token)
        .unwrap();
    assert!(lookup.contains("count=4"));
    assert!(lookup.contains("last=2026-11-01T00:00:00.000001900Z"));
    assert!(
        q.neighbors_native(&id, &artifacts, &filter, ("ip", "203.0.113.4"), 10, &token)
            .unwrap()
            .contains("alice")
    );
    assert!(
        q.path_native(
            &id,
            &artifacts,
            &filter,
            ("ip", "203.0.113.4"),
            ("user", "alice"),
            &token
        )
        .unwrap()
        .contains("co-observed")
    );
}
#[test]
fn precise_compaction_preserves_queries_reconstruction_and_hash_checks() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(root.path()).unwrap();
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    let a = prepare(
        &store,
        &id,
        root.path(),
        "a.json",
        &source("2026-11-01T00:00:00.000001Z", "A"),
    );
    let b = prepare(
        &store,
        &id,
        root.path(),
        "b.json",
        &source("2026-11-01T00:00:00.000002Z", "B"),
    );
    let names = names(&[("a.json", &a), ("b.json", &b)]);
    let all = [a.artifacts, b.artifacts].concat();
    let mut bundles = Vec::new();
    let token = CancellationToken::new();
    for schema in [
        "irmind-events-v3",
        "irmind-entities-v3",
        "irmind-coobservations-v2",
    ] {
        let inputs = all
            .iter()
            .filter(|a| a.schema_version() == schema)
            .cloned()
            .collect::<Vec<_>>();
        bundles.push(store.compact_artifacts(&id, &inputs, &token).unwrap());
    }
    let q = store.queries(&names);
    let snapshot = |artifacts: &[ParquetArtifact]| {
        q.timeline_native(&id, artifacts, &GraphQueryFilter::default(), 10, &token)
            .unwrap()
            .into_iter()
            .map(|e| (e.at, e.event, e.evidence_hash, e.record_index))
            .collect::<Vec<_>>()
    };
    assert_eq!(snapshot(&all), snapshot(&bundles));
    let with_bundles = [all, bundles.clone()].concat();
    assert_eq!(
        store
            .rebuild_compare(
                &id,
                root.path(),
                &[a.manifest, b.manifest],
                &with_bundles,
                &JsonParser,
                &token
            )
            .unwrap(),
        2
    );
    let file = store.case_dir(&id).unwrap().join(bundles[0].path());
    fs::write(file, b"tampered").unwrap();
    assert!(matches!(
        q.summary_native(&id, &bundles, &token),
        Err(AppError::EvidenceMismatch(_))
    ));
}
