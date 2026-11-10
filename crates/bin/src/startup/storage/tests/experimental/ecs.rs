use super::*;
use irmind_app::EvidenceGraph;

#[test]
fn ecs_detects_decodes_maps_filters_and_rebuilds_original_fields() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = registry();
    let config = PersistentConfig {
        experimental_common_writer: Some(true),
        ..Default::default()
    };
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let bytes = br#"{"@timestamp":"2026-11-01T00:00:00.123456789Z","ecs":{"version":"9.5.0"},"event":{"category":["authentication"],"type":["start"],"outcome":"failure"},"host":{"name":"synthetic-host"},"user":{"name":"alice","domain":"CORP-A"},"source":{"ip":"203.0.113.77"},"message":"synthetic ECS test"}"#;
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "events.ndjson",
            sample: bytes,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .unwrap();
    assert_eq!(selected.selection.parser_version, "ecs-source-v1");
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic ECS source mapping", "local only")
        .unwrap();
    std::fs::write(root.path().join("events.ndjson"), bytes).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: selected.parser.as_ref(),
    };
    use_cases
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["events.ndjson".into()],
            false,
            &BTreeMap::from([("events.ndjson".into(), selected.selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    let failure = irmind_app::GraphQueryFilter::from_args(&BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_outcome".into(), "failure".into()),
    ]))
    .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &failure, 10)
            .unwrap()
            .len(),
        1
    );
    let success = irmind_app::GraphQueryFilter::from_args(&BTreeMap::from([(
        "event_outcome".into(),
        "success".into(),
    )]))
    .unwrap();
    assert!(
        store
            .timeline_filtered(&case.id, &success, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .entity_lookup(&case.id, "user", "alice")
            .unwrap()
            .contains("alice")
    );
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    engine.verify(&case.id).unwrap();
}

#[test]
#[ignore = "manual paired release-only 1 GiB ECS source-pipeline measurement"]
fn ecs_source_pipeline_one_gib_release() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires an optimized release build");
    }
    let source = tempfile::tempdir().unwrap();
    let (bytes, records, sample) = benchmark_source(source.path());
    for repetition in 1..=3 {
        for mapped in [false, true] {
            benchmark_ingest(source.path(), bytes, records, &sample, mapped, repetition);
        }
    }
    Ok(())
}
fn benchmark_source(root: &Path) -> (u64, u64, Vec<u8>) {
    use std::io::Write as _;
    let line = format!(
        "{{\"@timestamp\":\"2026-11-01T00:00:00.123456789Z\",\"ecs\":{{\"version\":\"9.5.0\"}},\"event\":{{\"category\":[\"authentication\"],\"type\":[\"start\"],\"outcome\":\"failure\"}},\"host\":{{\"name\":\"synthetic-host\"}},\"user\":{{\"name\":\"alice\",\"domain\":\"CORP-A\"}},\"source\":{{\"ip\":\"203.0.113.77\"}},\"message\":\"{}\"}}\n",
        "x".repeat(900)
    );
    let mut output =
        std::io::BufWriter::new(std::fs::File::create(root.join("events.ndjson")).unwrap());
    let mut bytes = 0;
    let mut records = 0;
    while bytes < 1024 * 1024 * 1024 {
        output.write_all(line.as_bytes()).unwrap();
        bytes += line.len() as u64;
        records += 1;
    }
    output.flush().unwrap();
    drop(output);
    let mut sample = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(
            std::fs::File::open(root.join("events.ndjson")).unwrap(),
            65_536,
        ),
        &mut sample,
    )
    .unwrap();
    (bytes, records, sample)
}
fn benchmark_ingest(
    source: &Path,
    bytes: u64,
    records: u64,
    sample: &[u8],
    mapped: bool,
    repetition: u32,
) {
    let data = tempfile::tempdir().unwrap();
    let (base, engine) = setup(data.path(), false);
    let registry = registry();
    let config = PersistentConfig {
        experimental_common_writer: Some(mapped),
        ..Default::default()
    };
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "events.ndjson",
            sample,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .unwrap();
    let mapped_store = super::super::super::experimental(data.path(), &config, &registry).unwrap();
    let store = mapped_store.as_ref().unwrap_or(base.as_ref());
    let case = engine
        .create_case("Synthetic ECS pipeline benchmark", "local only")
        .unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store,
        parser: selected.parser.as_ref(),
    };
    let started = std::time::Instant::now();
    use_cases
        .ingest_local_batch_selected(
            &case.id,
            source,
            &["events.ndjson".into()],
            false,
            &BTreeMap::from([("events.ndjson".into(), selected.selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    let seconds = started.elapsed().as_secs_f64();
    let entries = store.entries(&case.id).unwrap();
    let manifest = entries
        .iter()
        .find(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .unwrap();
    let manifest = irmind_domain::SourceManifestV2::decode(&manifest.payload).unwrap();
    assert_eq!(
        benchmark_event_count(data.path(), &case.id, &entries),
        records
    );
    assert_eq!(manifest.rejected_records, 0);
    if mapped {
        super::profile::run(
            &registry.mapping_catalog().unwrap(),
            &source.join("events.ndjson"),
            &manifest.source.sha256,
            ("parser-ecs", "ecs-source-v1"),
            "ecs",
            repetition,
            data.path(),
        );
    }
    engine.verify(&case.id).unwrap();
    println!(
        "ECS_SOURCE_BENCH repetition={repetition} mapped={mapped} bytes={bytes} records={records} seconds={seconds:.6} MiB_per_second={:.6} source_sha256={}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds,
        manifest.source.sha256.as_str()
    );
}

fn benchmark_event_count(
    root: &Path,
    case: &irmind_app::CaseId,
    entries: &[irmind_app::SignedEntry],
) -> u64 {
    let catalog = irmind_app::artifact_catalog(entries).unwrap();
    catalog
        .active
        .iter()
        .filter(|a| a.schema_version().starts_with("irmind-events-"))
        .map(|artifact| {
            let path = root
                .join("parquet")
                .join(case.as_str())
                .join(artifact.path());
            let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
                std::fs::File::open(path).unwrap(),
            )
            .unwrap();
            u64::try_from(reader.metadata().file_metadata().num_rows()).unwrap()
        })
        .sum()
}
