#![forbid(unsafe_code)]
#![cfg(all(
    feature = "parser-m365",
    feature = "parser-okta",
    feature = "mapping-identity"
))]
#![allow(clippy::unwrap_used)]
#[path = "support/current_sources.rs"]
mod current_sources;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, Signer, modules::ParserSelectionRequest,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, SourceManifestV2};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use std::{collections::BTreeMap, fs, sync::Arc};
struct SyntheticSigner(SigningKey);
impl Signer for SyntheticSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.0.sign(bytes).to_bytes().to_vec())
    }
}
fn engine(store: &Arc<LocalStore>) -> Engine<'static> {
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[45; 32])));
    Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        )
        .with_source_evidence_reader(store.source_evidence_reader()),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
}
fn ingest_with_context(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &irmind_domain::CaseId,
    root: &std::path::Path,
    file: &str,
    cluster_context: Option<&irmind_domain::SourceClusterContext>,
) -> u64 {
    use std::io::Read as _;
    let mut sample = Vec::new();
    std::io::Read::take(fs::File::open(root.join(file)).unwrap(), 65536)
        .read_to_end(&mut sample)
        .unwrap();
    let catalog = current_sources::catalog();
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: file,
            sample: &sample,
            parser_override: None,
            forced: false,
            time_context: None,
            cluster_context,
        })
        .unwrap();
    LargeCaseUseCases {
        engine,
        store,
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        case,
        root,
        &[file.into()],
        false,
        &BTreeMap::from([(file.into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
    let entries = store.entries(case).unwrap();
    let manifest = entries
        .iter()
        .rev()
        .find(|e| e.kind == AuditEventKind::SourceManifestV2)
        .map(|e| SourceManifestV2::decode(&e.payload).unwrap())
        .unwrap();
    assert_eq!(manifest.rejected_records, 0);
    entries
        .iter()
        .rev()
        .find(|e| e.kind == AuditEventKind::SourceRecordSetV1)
        .map(|e| {
            irmind_domain::SourceRecordSetV1::decode(&e.payload)
                .unwrap()
                .records()
        })
        .unwrap()
}
fn fixture(parser: &str) -> &'static [u8] {
    match parser {
        #[cfg(feature = "parser-fdr")]
        "fdr" => include_bytes!("../../testkit/fixtures/parser-fdr/source/events.ndjson"),
        #[cfg(feature = "parser-defender")]
        "defender" => include_bytes!("../../testkit/fixtures/parser-defender/source/events.ndjson"),
        #[cfg(feature = "parser-email")]
        "email" => include_bytes!("../../testkit/fixtures/parser-email/source/multipart.eml"),
        "m365" => include_bytes!("../../testkit/fixtures/parser-m365/source/events.ndjson"),
        #[cfg(feature = "parser-guardduty")]
        "guardduty" => {
            include_bytes!("../../testkit/fixtures/parser-guardduty/source/events.ndjson")
        }
        #[cfg(feature = "parser-vpc-flow")]
        "vpc-flow" => include_bytes!("../../testkit/fixtures/parser-vpc-flow/source/custom.log"),
        #[cfg(feature = "parser-azure-flow")]
        "azure-vnet" => {
            include_bytes!("../../testkit/fixtures/parser-azure-flow/source/vnet.ndjson")
        }
        #[cfg(feature = "parser-azure-flow")]
        "azure-nsg" => include_bytes!("../../testkit/fixtures/parser-azure-flow/source/nsg.ndjson"),
        #[cfg(feature = "parser-gcp-flow")]
        "gcp-flow" => include_bytes!("../../testkit/fixtures/parser-gcp-flow/source/events.ndjson"),
        "okta" => include_bytes!("../../testkit/fixtures/parser-okta/source/events.ndjson"),
        _ => unreachable!(),
    }
}
#[test]
fn identity_failures_keep_roles_originals_and_signed_export() {
    use irmind_app::ExportVerifier;
    use irmind_domain::{CommonEventFilter, EventCategory, EventOutcome, GraphQueryFilter};
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic identity evidence", "Local only")
        .unwrap();
    for (name, count) in [
        #[cfg(feature = "parser-email")]
        ("email", 7),
        #[cfg(feature = "parser-defender")]
        ("defender", 9),
        #[cfg(feature = "parser-fdr")]
        ("fdr", 11),
        ("m365", 8),
        ("okta", 7),
        #[cfg(feature = "parser-guardduty")]
        ("guardduty", 2),
        #[cfg(feature = "parser-vpc-flow")]
        ("vpc-flow", 4),
        #[cfg(feature = "parser-azure-flow")]
        ("azure-vnet", 2),
        #[cfg(feature = "parser-azure-flow")]
        ("azure-nsg", 2),
        #[cfg(feature = "parser-gcp-flow")]
        ("gcp-flow", 3),
    ] {
        let file = format!("{name}.ndjson");
        fs::write(originals.join(&file), fixture(name)).unwrap();
        assert_eq!(
            ingest_with_context(&engine, store.as_ref(), &case.id, &originals, &file, None),
            count
        );
    }
    let filter = GraphQueryFilter::default().with_common(CommonEventFilter {
        category: Some(EventCategory::Authentication),
        outcome: Some(EventOutcome::Failure),
        ..Default::default()
    });
    assert_eq!(
        store
            .timeline_filtered(&case.id, &filter, 10)
            .unwrap()
            .len(),
        2 + usize::from(cfg!(feature = "parser-defender"))
            + usize::from(cfg!(feature = "parser-fdr"))
    );
    engine.verify(&case.id).unwrap();
    let parser = current_sources::parser("parser-m365");
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    }
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
}
#[test]
#[ignore = "manual optimized 1 GiB source ingestion benchmark"]
fn one_gib_release_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    for name in [
        "m365",
        "okta",
        #[cfg(feature = "parser-guardduty")]
        "guardduty",
        #[cfg(feature = "parser-vpc-flow")]
        "vpc-flow",
        #[cfg(feature = "parser-azure-flow")]
        "azure-vnet",
        #[cfg(feature = "parser-azure-flow")]
        "azure-nsg",
        #[cfg(feature = "parser-gcp-flow")]
        "gcp-flow",
    ] {
        benchmark_source(name);
    }
    Ok(())
}

#[cfg(feature = "parser-vpc-flow")]
#[test]
#[ignore = "manual optimized 1 GiB VPC flow ingestion benchmark"]
fn one_gib_release_vpc_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    benchmark_source("vpc-flow");
    Ok(())
}

#[cfg(all(feature = "parser-azure-flow", feature = "parser-gcp-flow"))]
#[test]
#[ignore = "manual optimized 1 GiB cloud JSON ingestion benchmark"]
fn one_gib_release_cloud_json_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    for name in ["azure-vnet", "azure-nsg", "gcp-flow"] {
        benchmark_source(name);
    }
    Ok(())
}
fn benchmark_source(name: &str) {
    use std::io::{BufWriter, Write};
    let bench_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let root = tempfile::Builder::new()
        .prefix("irmind-source-bench-")
        .tempdir_in(bench_root)
        .unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic identity benchmark", "Local only")
        .unwrap();
    let (header, line, per_record) = benchmark_lines(name);
    let mut writer = BufWriter::new(fs::File::create(originals.join("benchmark.ndjson")).unwrap());
    writer.write_all(&header).unwrap();
    let mut bytes = header.len() as u64;
    let mut count = 0u64;
    while bytes < 1024 * 1024 * 1024 {
        writer.write_all(&line).unwrap();
        bytes += line.len() as u64;
        count += per_record;
    }
    writer.flush().unwrap();
    drop(writer);
    let started = std::time::Instant::now();
    assert_eq!(
        ingest_with_context(
            &engine,
            store.as_ref(),
            &case.id,
            &originals,
            "benchmark.ndjson",
            None
        ),
        count
    );
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "IDENTITY_BENCH parser={name} bytes={bytes} records={count} seconds={seconds:.3} MiB_per_second={:.3}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds
    );
    engine.verify(&case.id).unwrap();
}

fn benchmark_lines(name: &str) -> (Vec<u8>, Vec<u8>, u64) {
    let mut lines = fixture(name).split(|b| *b == b'\n');
    let first = lines.next().unwrap();
    if name == "vpc-flow" {
        let mut header = first.to_vec();
        header.push(b'\n');
        let mut row = lines.next().unwrap().to_vec();
        row.push(b'\n');
        return (header, row, 1);
    }
    let mut value: serde_json::Value = serde_json::from_slice(first).unwrap();
    if !name.starts_with("azure-") && name != "gcp-flow" && name != "defender" && name != "fdr" {
        value["synthetic_padding"] = serde_json::json!("x".repeat(1024));
    }
    let mut row = serde_json::to_vec(&value).unwrap();
    row.push(b'\n');
    (
        Vec::new(),
        row,
        if name.starts_with("azure-") { 2 } else { 1 },
    )
}

#[cfg(feature = "parser-vpc-flow")]
#[test]
#[ignore = "manual optimized host-cardinality ingestion check"]
fn flow_host_partitions_preserve_overflow_values() {
    assert_host_partitions("vpc-flow");
}
#[cfg(feature = "parser-defender")]
#[test]
#[ignore = "manual optimized host-cardinality ingestion check"]
fn defender_host_partitions_preserve_overflow_values() {
    assert_host_partitions("defender");
}
#[cfg(any(
    feature = "parser-vpc-flow",
    feature = "parser-defender",
    feature = "parser-fdr"
))]
fn assert_host_partitions(parser: &str) {
    use irmind_domain::{ParquetArtifactV3, ScopePartitionKey, ScopePartitionValue};
    for hosts in [1usize, 64, 1024, 1025] {
        let root = tempfile::tempdir().unwrap();
        let originals = root.path().join("originals");
        fs::create_dir(&originals).unwrap();
        let store = Arc::new(current_sources::open(&root.path().join("data")));
        let engine = engine(&store);
        let case = engine
            .create_case("Synthetic host partitions", "Local only")
            .unwrap();
        let text = host_partition_input(parser, hosts);
        fs::write(originals.join("flows.log"), text).unwrap();
        assert_eq!(
            ingest_with_context(
                &engine,
                store.as_ref(),
                &case.id,
                &originals,
                "flows.log",
                None
            ),
            hosts as u64
        );
        let entries = store.entries(&case.id).unwrap();
        let mut ordinary = std::collections::BTreeSet::new();
        let mut overflow = std::collections::BTreeSet::new();
        for entry in entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::ParquetArtifactV3)
        {
            let artifact = ParquetArtifactV3::decode(&entry.payload).unwrap();
            for scope in &artifact.core().partition.scopes {
                if scope.key == ScopePartitionKey::Host {
                    assert_eq!(scope.cap, 64);
                    match &scope.value {
                        ScopePartitionValue::Ordinary(host) => {
                            ordinary.insert(host.clone());
                        }
                        ScopePartitionValue::Overflow(reason) => {
                            overflow.insert(reason.as_str());
                        }
                    }
                }
            }
        }
        assert_eq!(ordinary.len(), hosts.min(64));
        assert_eq!(overflow.contains("cardinality"), hosts > 64);
        let last = if parser == "fdr" {
            format!("{hosts:032x}")
        } else {
            format!("i-synthetic-{:04}", hosts - 1)
        };
        let result = store.text_search(&case.id, &last, 1).unwrap();
        assert!(result.contains("source="), "{result}");
        let source_hash = entries
            .iter()
            .find(|e| e.kind == AuditEventKind::SourceManifestV2)
            .map(|e| SourceManifestV2::decode(&e.payload).unwrap().source.sha256)
            .unwrap();
        assert!(
            store
                .raw_record(&case.id, source_hash.as_str(), hosts - 1)
                .unwrap()
                .contains(&last)
        );
        engine.verify(&case.id).unwrap();
        println!(
            "HOST_PARTITIONS parser={parser} hosts={hosts} ordinary={} overflow={}",
            ordinary.len(),
            overflow.len()
        );
    }
}

#[cfg(feature = "parser-vpc-flow")]
#[test]
fn compact_flow_artifact_bytes_are_independent_of_worker_limit() {
    assert_worker_artifacts("vpc-flow", 4);
}

#[cfg(feature = "parser-fdr")]
#[test]
fn fdr_artifact_bytes_are_independent_of_worker_limit() {
    assert_worker_artifacts("fdr", 11);
}

#[cfg(any(feature = "parser-vpc-flow", feature = "parser-fdr"))]
fn assert_worker_artifacts(parser: &str, expected_records: u64) {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("flows.log"), fixture(parser)).unwrap();
    let mut lines = std::str::from_utf8(fixture(parser)).unwrap().lines();
    let header = if parser == "vpc-flow" {
        format!("{}\n", lines.next().unwrap())
    } else {
        String::new()
    };
    let mut rows = lines.collect::<Vec<_>>();
    rows.reverse();
    fs::write(
        source.path().join("disordered.log"),
        format!("{header}{}\n", rows.join("\n")),
    )
    .unwrap();
    let mut expected = None;
    for cap in [1, 2, 4, 7] {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(current_sources::open(root.path()));
        store.set_parallel_worker_limit(std::num::NonZeroU16::new(cap));
        let engine = engine(&store);
        let case = engine
            .create_case("Synthetic worker equivalence", "Local only")
            .unwrap();
        for file in ["flows.log", "disordered.log"] {
            assert_eq!(
                ingest_with_context(&engine, store.as_ref(), &case.id, source.path(), file, None),
                expected_records
            );
        }
        let mut hashes = store
            .entries(&case.id)
            .unwrap()
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::ParquetArtifactV3)
            .map(|entry| {
                let artifact = irmind_domain::ParquetArtifactV3::decode(&entry.payload).unwrap();
                (
                    artifact.core().schema.as_str().to_owned(),
                    artifact.core().sha256.as_str().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        hashes.sort();
        assert!(!hashes.is_empty());
        if let Some(expected) = &expected {
            assert_eq!(&hashes, expected);
        } else {
            expected = Some(hashes);
        }
        engine.verify(&case.id).unwrap();
    }
}

#[cfg(feature = "parser-email")]
#[test]
#[ignore = "manual optimized 1 GiB email collection benchmark"]
fn one_gib_release_email_throughput() -> Result<(), &'static str> {
    use std::io::Write as _;
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    let bench_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let root = tempfile::Builder::new()
        .prefix("irmind-email-bench-")
        .tempdir_in(bench_root)
        .unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic email benchmark", "Local only")
        .unwrap();
    let mut bytes = 0_u64;
    let mut records = 0_u64;
    for index in 0..128 {
        let name = format!("synthetic-{index:03}.eml");
        let header = format!(
            "From: sender@example.invalid\r\nTo: analyst@example.invalid\r\nMessage-ID: <synthetic-{index}@example.invalid>\r\nDate: Tue, 17 Nov 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        );
        let mut file = fs::File::create(originals.join(&name)).unwrap();
        file.write_all(header.as_bytes()).unwrap();
        file.write_all(&vec![b'x'; 8 * 1024 * 1024]).unwrap();
        bytes += header.len() as u64 + 8 * 1024 * 1024;
    }
    let started = std::time::Instant::now();
    for index in 0..128 {
        records += ingest_with_context(
            &engine,
            store.as_ref(),
            &case.id,
            &originals,
            &format!("synthetic-{index:03}.eml"),
            None,
        );
    }
    let seconds = started.elapsed().as_secs_f64();
    assert_eq!(records, 128 * 33);
    println!(
        "EMAIL_BENCH bytes={bytes} records={records} files=128 seconds={seconds:.3} MiB_per_second={:.3}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds
    );
    // Reconstruction, seal and export are exercised by the mixed-source case test;
    // this measurement covers ingestion of a collection under the per-message cap.
    Ok(())
}

#[cfg(feature = "parser-defender")]
#[test]
#[ignore = "manual optimized 1 GiB Defender ingestion benchmark"]
fn one_gib_release_defender_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    benchmark_source("defender");
    Ok(())
}

#[cfg(any(
    feature = "parser-vpc-flow",
    feature = "parser-defender",
    feature = "parser-fdr"
))]
fn host_partition_input(parser: &str, hosts: usize) -> String {
    let mut text = String::new();
    if parser == "vpc-flow" {
        let mut lines = std::str::from_utf8(fixture("vpc-flow")).unwrap().lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();
        text.push_str(header);
        text.push('\n');
        for host in 0..hosts {
            text.push_str(&row.replace("i-synthetic-1", &format!("i-synthetic-{host:04}")));
            text.push('\n');
        }
    } else {
        let row = fixture(parser).split(|b| *b == b'\n').next().unwrap();
        let mut row: serde_json::Value = serde_json::from_slice(row).unwrap();
        for host in 0..hosts {
            if parser == "fdr" {
                row["aid"] = serde_json::json!(format!("{:032x}", host + 1));
            } else {
                row["DeviceId"] = serde_json::json!(format!("i-synthetic-{host:04}"));
            }
            text.push_str(&serde_json::to_string(&row).unwrap());
            text.push('\n');
        }
    }
    text
}

#[cfg(feature = "parser-fdr")]
#[test]
#[ignore = "manual optimized parser throughput benchmark"]
fn one_gib_release_fdr_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires --release");
    }
    benchmark_source("fdr");
    Ok(())
}

#[cfg(feature = "parser-fdr")]
#[test]
#[ignore = "manual optimized host-cardinality ingestion check"]
fn fdr_host_partitions_preserve_overflow_values() {
    assert_host_partitions("fdr");
}

#[cfg(feature = "parser-fdr")]
#[test]
#[ignore = "manual optimized compressed admission characterization"]
#[allow(clippy::too_many_lines)]
fn fdr_gzip_admission_characterization() -> Result<(), &'static str> {
    use std::io::Write;
    if cfg!(debug_assertions) {
        return Err("requires --release");
    }
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let row = fixture("fdr").split(|b| *b == b'\n').next().unwrap();
    let records = 150_000_u64;
    let mut writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for _ in 0..records {
        writer.write_all(row).unwrap();
        writer.write_all(b"\n").unwrap();
    }
    let gzip = writer.finish().unwrap();
    let physical = gzip.len() as u64;
    let decoded = (row.len() as u64 + 1) * records;
    fs::write(originals.join("source.gz"), &gzip).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic gzip admission", "local only")
        .unwrap();
    let catalog = current_sources::catalog();
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "source.gz",
            sample: &gzip[..gzip.len().min(65536)],
            parser_override: None,
            forced: false,
            time_context: None,
            cluster_context: None,
        })
        .unwrap();
    let result = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &originals,
        &["source.gz".into()],
        false,
        &BTreeMap::from([("source.gz".into(), selected.selection)]),
        &CancellationToken::new(),
    );
    println!(
        "FDR_GZIP_ADMISSION physical_bytes={physical} decoded_bytes={decoded} records={records} default_allowance={} result={result:?}",
        physical * 16 + 64 * 1024 * 1024
    );
    assert!(result.is_err());
    assert!(
        !store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|e| e.kind == AuditEventKind::ParquetArtifactV3)
    );
    let mut plain =
        std::io::BufWriter::new(fs::File::create(originals.join("source.ndjson")).unwrap());
    for _ in 0..records {
        plain.write_all(row).unwrap();
        plain.write_all(b"\n").unwrap();
    }
    plain.flush().unwrap();
    drop(plain);
    let plain_case = engine
        .create_case("Synthetic plain admission", "local only")
        .unwrap();
    let plain_accepted = ingest_with_context(
        &engine,
        store.as_ref(),
        &plain_case.id,
        &originals,
        "source.ndjson",
        None,
    );
    assert_eq!(plain_accepted, records);
    engine.verify(&plain_case.id).unwrap();
    println!("FDR_GZIP_CONTROL plain_bytes={decoded} records={plain_accepted} verification=passed");
    Ok(())
}
