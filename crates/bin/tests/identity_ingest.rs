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
    for (name, count) in [("m365", 8), ("okta", 7)] {
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
    use std::io::{BufWriter, Write};
    if cfg!(debug_assertions) {
        return Err("Use --release for benchmarks");
    }
    for name in ["m365", "okta"] {
        let root = tempfile::tempdir().unwrap();
        let originals = root.path().join("originals");
        fs::create_dir(&originals).unwrap();
        let store = Arc::new(current_sources::open(&root.path().join("data")));
        let engine = engine(&store);
        let case = engine
            .create_case("Synthetic identity benchmark", "Local only")
            .unwrap();
        let row = fixture(name).split(|b| *b == b'\n').next().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(row).unwrap();
        value["synthetic_padding"] = serde_json::json!("x".repeat(1024));
        let mut line = serde_json::to_vec(&value).unwrap();
        line.push(b'\n');
        let mut writer =
            BufWriter::new(fs::File::create(originals.join("benchmark.ndjson")).unwrap());
        let mut bytes = 0u64;
        let mut count = 0u64;
        while bytes < 1024 * 1024 * 1024 {
            writer.write_all(&line).unwrap();
            bytes += line.len() as u64;
            count += 1;
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
    Ok(())
}
