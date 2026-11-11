#![allow(clippy::panic)]
use super::*;
use arrow::array::{UInt8Array, UInt32Array};
use irmind_domain::GraphQueryFilter;

#[test]
fn mapping_owned_unclassified_projection_writes_checked_schemas_and_precision() {
    let root = tempfile::tempdir().unwrap();
    let store = mapped::compat_store(root.path());
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    let input=br#"{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Failure is just source text","host":"host-a","sourceIPAddress":"203.0.113.77"}"#;
    fs::write(root.path().join("event.json"), input).unwrap();
    let paths = ["event.json".into()];
    let prepared = crate::parquet_store::fixtures::successive_sources(
        &store,
        irmind_app::MappedIngestRequest {
            case_id: &id,
            source_root: root.path(),
            relative_paths: &paths,
            copy_original: false,
            parser: &crate::parquet_store::fixtures::parser(),
            committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
            limits: irmind_app::PartitionLimits::default(),
        },
        &CancellationToken::new(),
    )
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(prepared.records, 1);
    assert_eq!(prepared.artifacts.len(), 3);
    for artifact in &prepared.artifacts {
        let ParquetArtifact::V3(mapped) = artifact else {
            panic!("expected mapped V3")
        };
        let envelope = mapped.core();
        assert!(envelope.schema.is_common());
        assert_eq!(
            envelope.builder_version,
            irmind_domain::COMMON_EVENT_DIRECT_BUILDER
        );
        let file = File::open(store.case_dir(&id).unwrap().join(&envelope.path)).unwrap();
        let reader =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        crate::parquet_store::format::validate_schema(artifact, reader.schema()).unwrap();
        for batch in reader.build().unwrap() {
            let batch = batch.unwrap();
            let categories = batch
                .column_by_name("event_category_bits")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt32Array>()
                .unwrap();
            let outcomes = batch
                .column_by_name("event_outcome")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt8Array>()
                .unwrap();
            for row in 0..batch.num_rows() {
                assert_eq!(categories.value(row), 0);
                assert_eq!(outcomes.value(row), 0);
                assert_eq!(
                    crate::parquet_store::time_cell::read_time(&batch, row)
                        .unwrap()
                        .unwrap()
                        .instant()
                        .submicro_nanos(),
                    789
                );
            }
        }
    }
    let prepared_mapping = prepared.mapping;
    assert!(prepared_mapping.records() == 1 && prepared_mapping.commitment().as_str().len() == 64);
}

mod compaction;
mod extrema;
mod mapped;
#[test]
#[allow(clippy::too_many_lines)]
fn common_queries_keep_roles_pid_scopes_and_closed_filters() {
    let root = tempfile::tempdir().unwrap();
    let store = mapped::store(root.path());
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    let input = concat!(
        "{\"eventTime\":\"2026-11-01T00:00:00.123456789Z\",\"eventName\":\"Login\",\"source_ip\":\"203.0.113.1\",\"destination_ip\":\"203.0.113.1\",\"outcome\":\"failure\",\"pid\":42}\n",
        "{\"eventTime\":\"2026-11-01T00:00:01.123456789Z\",\"eventName\":\"Login\",\"source_ip\":\"203.0.113.2\",\"outcome\":\"success\",\"pid\":42}\n",
        "{\"eventTime\":\"2026-11-01T00:00:02Z\",\"eventName\":\"Login\",\"source_ip\":\"203.0.113.3\"}\n"
    );
    fs::write(root.path().join("mapped.ndjson"), input).unwrap();
    let paths = ["mapped.ndjson".into()];
    let prepared = crate::parquet_store::fixtures::successive_sources(
        &store,
        irmind_app::MappedIngestRequest {
            case_id: &id,
            source_root: root.path(),
            relative_paths: &paths,
            copy_original: false,
            parser: &crate::parquet_store::fixtures::parser(),
            committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
            limits: irmind_app::PartitionLimits::default(),
        },
        &CancellationToken::new(),
    )
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(prepared.records, 3);
    let names = BTreeMap::from([(
        prepared.manifest.sha256.as_str().into(),
        "mapped.ndjson".into(),
    )]);
    let query = store.queries(&names);
    let all = GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    let lookup = query
        .entity_native(&id, &prepared.artifacts, &all, "ip", "203.0.113.1", &cancel)
        .unwrap();
    assert!(
        lookup.contains("source=1") && lookup.contains("destination=1"),
        "{lookup}"
    );
    assert!(
        query
            .entity_timeline_native(
                &id,
                &prepared.artifacts,
                &all,
                ("ip", "203.0.113.1"),
                20,
                &cancel
            )
            .unwrap()
            .lines()
            .count()
            == 1
    );
    let failure = GraphQueryFilter::from_args(&BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_outcome".into(), "failure".into()),
    ]))
    .unwrap();
    assert_eq!(
        query
            .timeline_native(&id, &prepared.artifacts, &failure, 20, &cancel)
            .unwrap()
            .len(),
        1
    );
    let destination = all
        .clone()
        .with_common(irmind_app::common_event::CommonEventFilter {
            role: Some(irmind_app::common_event::EntityRole::Destination),
            ..Default::default()
        });
    assert_eq!(
        query
            .timeline_native(&id, &prepared.artifacts, &destination, 20, &cancel)
            .unwrap()
            .len(),
        1
    );
    let path = query
        .path_native(
            &id,
            &prepared.artifacts,
            &all,
            ("ip", "203.0.113.1"),
            ("ip", "203.0.113.2"),
            &cancel,
        )
        .unwrap();
    assert!(path.contains("no co-observation path"), "{path}");
    mapped::assert_rebuild(root.path(), &["mapped.ndjson".into()], false);
}

mod layout;
