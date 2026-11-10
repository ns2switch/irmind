use super::*;
#[test]
#[ignore = "manual paired release-only 1 GiB EVTX source-pipeline measurement"]
fn evtx_source_pipeline_one_gib_release() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires an optimized release build");
    }
    let path = std::env::var_os("IRMIND_EVTX_SOURCE_BENCH_INPUT")
        .ok_or("missing synthetic EVTX benchmark input")?;
    let path = PathBuf::from(path);
    let bytes = std::fs::metadata(&path).unwrap().len();
    assert_eq!((bytes - 4096) % 65536, 0);
    let records = ((bytes - 4096) / 65536) * 17;
    let sources = tempfile::tempdir().unwrap();
    std::fs::copy(path, sources.path().join("events.evtx")).unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let registry = evtx_registry(runtime.path())
        .map_err(|_| "EVTX benchmark requires verified native isolation")?;
    for repetition in 1..=3 {
        for mapped in [false, true] {
            measure(
                &registry,
                sources.path(),
                bytes,
                records,
                mapped,
                repetition,
            );
        }
    }
    Ok(())
}
fn measure(
    registry: &ModuleRegistry,
    source: &Path,
    bytes: u64,
    records: u64,
    mapped: bool,
    repetition: u32,
) {
    use std::io::Read as _;
    let data = tempfile::tempdir().unwrap();
    let (base, engine) = setup(data.path(), false);
    let config = PersistentConfig {
        experimental_common_writer: Some(mapped),
        ..Default::default()
    };
    let parsers =
        crate::startup::storage::experimental_parsers(registry.parser_catalog(), &config, registry)
            .unwrap();
    let mut sample = Vec::new();
    std::fs::File::open(source.join("events.evtx"))
        .unwrap()
        .take(65536)
        .read_to_end(&mut sample)
        .unwrap();
    let selected = parsers
        .select_source(ParserSelectionRequest {
            source: "events.evtx",
            sample: &sample,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .unwrap();
    let common = crate::startup::storage::experimental(data.path(), &config, registry).unwrap();
    let store = common.as_ref().unwrap_or(base.as_ref());
    let case = engine
        .create_case("Synthetic EVTX mapping benchmark", "local only")
        .unwrap();
    let start = std::time::Instant::now();
    LargeCaseUseCases {
        engine: &engine,
        store,
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        source,
        &["events.evtx".into()],
        false,
        &BTreeMap::from([("events.evtx".into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
    let seconds = start.elapsed().as_secs_f64();
    let entries = store.entries(&case.id).unwrap();
    let manifest = entries
        .iter()
        .find(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .unwrap();
    let manifest = irmind_domain::SourceManifestV2::decode(&manifest.payload).unwrap();
    assert_eq!(event_count(data.path(), &case.id, &entries), records);
    assert_eq!(manifest.rejected_records, 0);
    if mapped {
        super::super::profile::run(
            &registry.mapping_catalog().unwrap(),
            &source.join("events.evtx"),
            &manifest.source.sha256,
            ("parser-evtx", "evtx-source-v1"),
            "evtx",
            repetition,
            data.path(),
        );
    }
    engine.verify(&case.id).unwrap();
    println!(
        "EVTX_SOURCE_BENCH repetition={repetition} mapped={mapped} bytes={bytes} records={records} seconds={seconds:.6} MiB_per_second={:.6} source_sha256={}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds,
        manifest.source.sha256.as_str()
    );
}

fn event_count(root: &Path, case: &irmind_app::CaseId, entries: &[irmind_app::SignedEntry]) -> u64 {
    let catalog = irmind_app::artifact_catalog(entries).unwrap();
    catalog
        .active
        .iter()
        .filter(|a| a.schema_version().starts_with("irmind-events-"))
        .map(|artifact| {
            let file = std::fs::File::open(
                root.join("parquet")
                    .join(case.as_str())
                    .join(artifact.path()),
            )
            .unwrap();
            let reader =
                parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
                    .unwrap();
            u64::try_from(reader.metadata().file_metadata().num_rows()).unwrap()
        })
        .sum()
}
