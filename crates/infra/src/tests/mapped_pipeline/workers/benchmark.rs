use super::*;
use std::time::Instant;

#[test]
#[ignore = "manual release-only single NDJSON source worker sweep"]
fn benchmark_single_ndjson_release() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires an optimized release build");
    }
    let gib = std::env::var("IRMIND_BENCH_NDJSON_GIB").map_or(1, |n| n.parse::<u64>().unwrap());
    assert!(matches!(gib, 1 | 4));
    let size = gib << 30;
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let name = "synthetic.ndjson";
    let records = write_ndjson(&sources.join(name), size);
    let ProfiledFixture {
        store,
        engine,
        catalog,
        profile,
        custody,
    } = profiled_fixture(&root.path().join("case"));
    let cap = std::env::var("IRMIND_BENCH_WORKERS")
        .ok()
        .map(|value| value.parse::<NonZeroU16>().unwrap());
    store.set_parallel_worker_limit(cap);
    let case = engine
        .create_case("Single synthetic NDJSON source", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let ingest = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    custody.reset();
    let started = Instant::now();
    ingest
        .ingest_local_batch(&case.id, &sources, &[name.into()], false, &cancel)
        .unwrap();
    let seconds = started.elapsed().as_secs_f64();
    report_phases(&profile);
    custody.report();
    let entries = store.entries(&case.id).unwrap();
    let index = irmind_app::artifact_catalog(&entries).unwrap();
    let rows = index
        .active
        .iter()
        .filter(|a| a.schema_version() == "irmind-events-v4")
        .map(|artifact| {
            let ParquetArtifact::V3(artifact) = artifact;
            artifact.pipeline().rows()
        })
        .sum::<u64>();
    assert_eq!(rows, records);
    assert!(ingest.verify_parquet(&case.id, &cancel).unwrap() > 0);
    println!(
        "NDJSON_WORKERS bytes={size} records={records} cap={} wall_seconds={seconds:.6} parquet_bytes={}",
        cap.map_or_else(|| "auto".into(), |n| n.to_string()),
        index.active.iter().map(ParquetArtifact::size).sum::<u64>(),
    );
    Ok(())
}

fn write_ndjson(path: &Path, size: u64) -> u64 {
    let lines: Vec<_> = (0..64).map(|i| {
        let mut line = format!(
            r#"{{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Synthetic{i:02}","sourceIPAddress":"203.0.113.77","message":"{}"}}"#,
            "synthetic ".repeat(150)
        );
        line.push('\n');
        line
    }).collect();
    let mut writer =
        std::io::BufWriter::with_capacity(1024 * 1024, fs::File::create(path).unwrap());
    let line_bytes = lines[0].len() as u64;
    let records = size / line_bytes;
    for i in 0..records {
        writer
            .write_all(lines[(i % 64) as usize].as_bytes())
            .unwrap();
    }
    writer
        .write_all(&vec![b' '; usize::try_from(size % line_bytes).unwrap()])
        .unwrap();
    writer.flush().unwrap();
    assert_eq!(fs::metadata(path).unwrap().len(), size);
    records
}

struct ProfiledFixture {
    store: Arc<LocalStore>,
    engine: Engine<'static>,
    catalog: Arc<MappingCatalog>,
    profile: Arc<crate::parquet_store::ParquetProfile>,
    custody: Arc<crate::tests::benchmark_custody::Timings>,
}
fn profiled_fixture(root: &Path) -> ProfiledFixture {
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(JsonCompatibilityMapping::new().unwrap())],
        )
        .unwrap(),
    );
    let profile = Arc::new(crate::parquet_store::ParquetProfile::default());
    let mut local = LocalStore::open_mapped(root, catalog.clone()).unwrap();
    local.parquet.attach_profile(profile.clone());
    let store = Arc::new(local);
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[88; 32]),
        actor: Actor::Analyst,
    });
    let mut ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(
            signer.clone(),
            Arc::new(LocalVerifier::from_signer(signer.as_ref())),
        ),
        Arc::new(MandatoryGuard::new().unwrap()),
    );
    let custody = crate::tests::benchmark_custody::attach(&mut ports);
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock)).unwrap();
    ProfiledFixture {
        store,
        engine,
        catalog,
        profile,
        custody,
    }
}
fn report_phases(profile: &crate::parquet_store::ParquetProfile) {
    let [hash, row, parquet, _, _] = profile.snapshot().map(|v| v.as_secs_f64());
    let [producer, consumer, writes, encode, sync, artifact_hash] =
        profile.concurrency_snapshot().map(|v| v.as_secs_f64());
    let mapping = profile.mapping_snapshot().map(|v| v.as_secs_f64());
    println!(
        "WORKER_PHASE hash_read_seconds={hash:.6} row_preparation_seconds={row:.6} canonical_write_seconds={parquet:.6} parquet_encode_and_io_seconds={encode:.6} file_write_seconds={writes:.6} file_sync_seconds={sync:.6} artifact_hash_seconds={artifact_hash:.6} producer_queue_wait_seconds={producer:.6} consumer_queue_wait_seconds={consumer:.6} validate_map_seconds={:.6} projection_seconds={:.6} input_commit_seconds={:.6}",
        mapping[0], mapping[1], mapping[2]
    );
    println!(
        "WORKER_PHASE_METHOD cumulative stage wall timers can overlap; file writes are included in canonical writes; queue waits are elapsed off-CPU waits, not decoding time"
    );
}
