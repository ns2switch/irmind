use super::*;
use flate2::{Compression, write::GzEncoder};
use irmind_app::{ExportVerifier as _, SourceDecoder as _};
use std::{
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

#[test]
fn gzip_is_reconstructed_sealed_and_verified_from_its_original_bytes() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let source = originals.join("source.gz");
    let mut gzip = GzEncoder::new(fs::File::create(&source).unwrap(), Compression::fast());
    gzip.write_all(fixture("fdr")).unwrap();
    drop(gzip.finish().unwrap());
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic FDR gzip", "local only")
        .unwrap();
    let count = ingest_with_context(&engine, &store, &case.id, &originals, "source.gz", None);
    assert_eq!(count, 11);
    let entries = store.entries(&case.id).unwrap();
    let source_manifest = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .map(|entry| SourceManifestV2::decode(&entry.payload).unwrap())
        .unwrap();
    let original_bytes = fs::read(&source).unwrap();
    assert_eq!(
        source_manifest.source.sha256.as_str(),
        irmind_app::hex(&irmind_app::sha256(&original_bytes))
    );
    assert_eq!(source_manifest.source.size, original_bytes.len() as u64);
    let parser = current_sources::parser("parser-fdr");
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    large
        .verify_parquet_rebuild(&case.id, &originals, &CancellationToken::new())
        .unwrap();
    engine.seal(&case.id).unwrap();
    let target = root.path().join("synthetic.irmind");
    let key = irmind_app::export_case(
        &engine,
        store.as_ref(),
        &case.id,
        &target,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        irmind_infra::LocalExportVerifier
            .verify_export_details(&target, Some(&key))
            .unwrap()
            .format_version,
        8
    );
    // A valid extra gzip member changes the signed original even if the first
    // member and the selected format are intact.
    fs::write(
        &source,
        [original_bytes.as_slice(), &original_bytes].concat(),
    )
    .unwrap();
    assert!(
        large
            .verify_parquet_rebuild(&case.id, &originals, &CancellationToken::new())
            .is_err()
    );
}

#[test]
#[ignore = "manual optimized paired 1 GiB FDR benchmark"]
fn one_gib_release_fdr_gzip_and_jsonl() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let root = tempfile::Builder::new()
        .prefix("irmind-fdr-bench-")
        .tempdir_in(bench_root)
        .unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let (_, row, _) = benchmark_lines("fdr");
    let records = (1_u64 << 30).div_ceil(row.len() as u64);
    let decoded_bytes = (row.len() as u64) * records;
    write_pair(&originals, &row, records);
    for name in ["source.ndjson", "source.gz"] {
        let store = Arc::new(current_sources::open(
            &root.path().join(format!("{name}.case-data")),
        ));
        let engine = engine(&store);
        let case = engine
            .create_case("Synthetic FDR benchmark", "local only")
            .unwrap();
        let start = Instant::now();
        assert_eq!(
            ingest_with_context(&engine, &store, &case.id, &originals, name, None),
            records
        );
        let seconds = start.elapsed().as_secs_f64();
        engine.verify(&case.id).unwrap();
        let mut file = fs::File::open(originals.join(name)).unwrap();
        let physical_bytes = file.metadata().unwrap().len();
        let start = Instant::now();
        let preflight = irmind_mod_parser_fdr::FdrSourceDecoder
            .normalized_source_budget(&mut file, &CancellationToken::new())
            .unwrap()
            .unwrap();
        let preflight_seconds = start.elapsed().as_secs_f64();
        assert_eq!(preflight.decoded_bytes(), decoded_bytes);
        let mib = f64::from(u32::try_from(decoded_bytes).unwrap()) / 1_048_576.0;
        println!(
            "FDR_PAIR encoding={name} physical_bytes={physical_bytes} decoded_bytes={decoded_bytes} records={records} seconds={seconds:.6} decoded_mib_per_second={:.3} separate_preflight_seconds={preflight_seconds:.6}",
            mib / seconds
        );
    }
    Ok(())
}

fn write_pair(originals: &Path, row: &[u8], records: u64) {
    let mut plain = BufWriter::new(fs::File::create(originals.join("source.ndjson")).unwrap());
    let compressed = BufWriter::new(fs::File::create(originals.join("source.gz")).unwrap());
    let mut gzip = GzEncoder::new(compressed, Compression::fast());
    for _ in 0..records {
        plain.write_all(row).unwrap();
        gzip.write_all(row).unwrap();
    }
    plain.flush().unwrap();
    gzip.finish().unwrap().flush().unwrap();
}
