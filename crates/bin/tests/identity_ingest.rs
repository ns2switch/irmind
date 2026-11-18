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
        2
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
    if !name.starts_with("azure-") && name != "gcp-flow" {
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
    use irmind_domain::{ParquetArtifactV3, ScopePartitionKey, ScopePartitionValue};
    for hosts in [1usize, 64, 1024, 1025] {
        let root = tempfile::tempdir().unwrap();
        let originals = root.path().join("originals");
        fs::create_dir(&originals).unwrap();
        let store = Arc::new(current_sources::open(&root.path().join("data")));
        let engine = engine(&store);
        let case = engine
            .create_case("Synthetic flow partitions", "Local only")
            .unwrap();
        let mut lines = std::str::from_utf8(fixture("vpc-flow")).unwrap().lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();
        let mut text = format!("{header}\n");
        for host in 0..hosts {
            text.push_str(&row.replace("i-synthetic-1", &format!("i-synthetic-{host:04}")));
            text.push('\n');
        }
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
        let last = format!("i-synthetic-{:04}", hosts - 1);
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
            "FLOW_PARTITIONS hosts={hosts} ordinary={} overflow={}",
            ordinary.len(),
            overflow.len()
        );
    }
}

#[cfg(feature = "parser-vpc-flow")]
#[test]
fn compact_flow_artifact_bytes_are_independent_of_worker_limit() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("flows.log"), fixture("vpc-flow")).unwrap();
    let mut lines = std::str::from_utf8(fixture("vpc-flow")).unwrap().lines();
    let header = lines.next().unwrap();
    let mut rows = lines.collect::<Vec<_>>();
    rows.reverse();
    fs::write(
        source.path().join("disordered.log"),
        format!("{header}\n{}\n", rows.join("\n")),
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
                4
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
