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
    let (store, engine, catalog) = fixture(&root.path().join("case"));
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
    let started = Instant::now();
    ingest
        .ingest_local_batch(&case.id, &sources, &[name.into()], false, &cancel)
        .unwrap();
    let seconds = started.elapsed().as_secs_f64();
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
