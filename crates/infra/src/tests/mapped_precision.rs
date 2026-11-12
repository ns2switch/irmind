use super::*;
use irmind_app::{LargeCaseUseCases, ParserSelection};
use irmind_domain::{AuditEventKind, ParserSelectionMode};

#[test]
#[allow(clippy::too_many_lines)]
fn signed_case_preserves_precise_time_and_rejects_decoder_substitution() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("inputs");
    fs::create_dir(&sources).unwrap();
    let store = Arc::new(open_source_store(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[31; 32]),
        actor: Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("Mixed precision", "local only").unwrap();
    let old = br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Coarse","sourceIPAddress":"203.0.113.4","userIdentity":{"userName":"alice"}}"#;
    fs::write(sources.join("old.json"), old).unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json_source_parser(),
    }
    .ingest_local(
        &case.id,
        &sources,
        "old.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let new = br#"{"eventTime":"2026-11-01T00:00:00.000001100Z","eventName":"Fine","sourceIPAddress":"203.0.113.4","userIdentity":{"userName":"alice"}}"#;
    fs::write(sources.join("new.json"), new).unwrap();
    let selections = BTreeMap::from([(
        "new.json".into(),
        ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-source-v1".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: sha256(new),
        },
    )]);
    let uses = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json_source_parser(),
    };
    uses.ingest_local_batch_selected(
        &case.id,
        &sources,
        &["new.json".into()],
        false,
        &selections,
        &CancellationToken::new(),
    )
    .unwrap();
    assert!(engine.verify(&case.id).is_ok());
    let timeline = store.timeline(&case.id, 10).unwrap();
    assert_eq!(timeline.len(), 2);
    assert_eq!(timeline[0].at, "2026-11-01T00:00:00.000001100Z");
    let checked = uses
        .verify_parquet_rebuild(&case.id, &sources, &CancellationToken::new())
        .unwrap();
    assert_eq!(checked, 2);
    assert_precise_columns(&store, &case.id, &sha256(new));
    let entries = store.entries(&case.id).unwrap();
    let mut original = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::ParquetArtifactV3)
        .unwrap()
        .clone();

    let last = store.last_entry(&case.id).unwrap().unwrap();
    original.seq = last.seq + 1;
    original.prev = last.hash;
    // Change only the physical core's decoder id; signed pipeline bindings stay intact.
    let altered = original
        .payload
        .replacen("7061727365722d6a736f6e", "7061727365722d6576696c", 1);
    assert_ne!(altered, original.payload);
    original.payload = altered;
    original.hash = sha256(&original.canonical());
    original.sig = signer.sign(&original.hash).unwrap();
    store.append(&original).unwrap();
    assert!(engine.verify(&case.id).is_err());
    assert!(store.timeline(&case.id, 10).is_err());
}

fn assert_precise_columns(store: &LocalStore, id: &CaseId, source: &[u8; 32]) {
    use arrow::array::{Array, BooleanArray, TimestampMicrosecondArray, UInt8Array, UInt16Array};
    let catalog = irmind_app::artifact_catalog(&store.entries(id).unwrap()).unwrap();
    let hash = irmind_app::hex(source);
    let artifacts = catalog
        .active
        .iter()
        .filter(|artifact| {
            artifact
                .source_hashes()
                .iter()
                .any(|value| value.as_str() == hash)
        })
        .collect::<Vec<_>>();
    assert_eq!(artifacts.len(), 3);
    for artifact in artifacts {
        let path = store.parquet.case_dir(id).unwrap().join(artifact.path());
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            fs::File::open(path).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
        let mut rows = 0;
        for batch in reader {
            let batch = batch.unwrap();
            let micros = batch
                .column_by_name("event_time")
                .unwrap()
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            let nanos = batch
                .column_by_name("submicro_nanos")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt16Array>()
                .unwrap();
            let precision = batch
                .column_by_name("time_precision")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt8Array>()
                .unwrap();
            let inferred = batch
                .column_by_name("time_inferred")
                .unwrap()
                .as_any()
                .downcast_ref::<BooleanArray>()
                .unwrap();
            for row in 0..batch.num_rows() {
                assert!(!micros.is_null(row));
                assert_eq!(micros.value(row), 1_793_491_200_000_001);
                assert_eq!(nanos.value(row), 100);
                assert_eq!(
                    precision.value(row),
                    irmind_domain::TimePrecision::Nanosecond.code()
                );
                assert!(!inferred.value(row));
                rows += 1;
            }
        }
        assert!(rows > 0);
    }
}

#[test]
fn mapped_queries_share_numeric_time_and_signed_source_order() {
    let root = tempfile::tempdir().unwrap();
    let inputs = ordering_inputs(root.path());
    let (store, engine) = source_fixture(root.path(), 96);
    let case = engine.create_case("Timestamp order", "local only").unwrap();
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json_source_parser(),
    };
    cases
        .ingest_local_batch(
            &case.id,
            &inputs,
            &["coarse.json".into(), "new.json".into(), "a.json".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let rows = store.timeline(&case.id, 10).unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.event.as_str())
            .collect::<Vec<_>>(),
        [
            "Fine9 [nanosecond precision]",
            "FirstSource [nanosecond precision]",
            "Fine1 [nanosecond precision]",
            "Coarse [second precision]"
        ]
    );
    let narrow = irmind_domain::GraphQueryFilter::parse(
        Some("2026-11-01T00:00:00.000001100Z"),
        Some("2026-11-01T00:00:00.000001100Z"),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &narrow, 10)
            .unwrap()
            .len(),
        2
    );
    let timeline = store
        .entity_timeline(&case.id, "ip", "203.0.113.4", 10)
        .unwrap();
    assert!(timeline.find("Fine9").unwrap() < timeline.find("FirstSource").unwrap());
    let lookup = store.entity_lookup(&case.id, "ip", "203.0.113.4").unwrap();
    assert!(lookup.contains("observations=4"));
    assert!(lookup.contains("2026-11-01T00:00:00.000001900Z"));
    assert!(
        store
            .neighbors(&case.id, "ip", "203.0.113.4", 10)
            .unwrap()
            .contains("alice")
    );
    assert!(
        store
            .graph_path(&case.id, ("ip", "203.0.113.4"), ("user", "alice"))
            .unwrap()
            .contains("co-observed")
    );
    assert_eq!(
        cases
            .verify_parquet_rebuild(&case.id, &inputs, &CancellationToken::new())
            .unwrap(),
        3
    );
}

fn ordering_inputs(root: &Path) -> PathBuf {
    let inputs = root.join("inputs");
    fs::create_dir(&inputs).unwrap();
    let record = |time: &str, event: &str| {
        format!(
            r#"{{"eventTime":"{time}","eventName":"{event}","sourceIPAddress":"203.0.113.4","userIdentity":{{"userName":"alice"}}}}"#
        )
    };
    for (name, rows) in [
        ("coarse.json", record("2026-11-01T00:00:00Z", "Coarse")),
        (
            "new.json",
            format!(
                "{}\n{}",
                record("2026-11-01T00:00:00.000001100Z", "Fine1"),
                record("2026-11-01T00:00:00.000001900Z", "Fine9")
            ),
        ),
        (
            "a.json",
            record("2026-11-01T00:00:00.000001100Z", "FirstSource"),
        ),
    ] {
        fs::write(inputs.join(name), rows).unwrap();
    }
    inputs
}
