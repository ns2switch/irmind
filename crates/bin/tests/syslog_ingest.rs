#![forbid(unsafe_code)]
#![cfg(feature = "parser-syslog")]
#![allow(clippy::unwrap_used)]

#[path = "support/current_sources.rs"]
mod current_sources;

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, LogParser as _, ParserSelection, Signer, StreamingEventParser,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, ParserSelectionMode};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use irmind_mod_parser_syslog::SyslogParser;
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
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[35; 32])));
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
            current_sources::event_parser(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
}

#[test]
fn detected_syslog_is_signed_queryable_and_reproducible_without_expected_answers() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let bytes = include_bytes!("../../testkit/fixtures/parser-syslog/source/events.log");
    fs::write(sources.join("events.log"), bytes).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let parser = Arc::new(SyslogParser);
    let source_parser = irmind_mod_parser_syslog::source_log_parser();
    let engine = engine(&store);
    let case = engine.create_case("Synthetic syslog", "local").unwrap();
    let selected = BTreeMap::from([(
        "events.log".to_owned(),
        ParserSelection {
            parser_id: "parser-syslog".into(),
            confidence: 95,
            mode: ParserSelectionMode::Automatic,
            parser_version: irmind_mod_parser_syslog::source_log_parser()
                .identity()
                .version
                .into(),
            timestamp_context: parser.timestamp_context().map(str::to_owned),
            format_sample_sha256: irmind_app::sha256(bytes),
        },
    )]);
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: source_parser.as_ref(),
    };
    cases
        .ingest_local_batch_selected(
            &case.id,
            &sources,
            &["events.log".into()],
            false,
            &selected,
            &CancellationToken::new(),
        )
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .unwrap();
    let manifest = irmind_domain::SourceManifestV2::decode(&entry.payload).unwrap();
    assert_eq!(manifest.parser_id, "parser-syslog");
    assert!(!manifest.source.copied);
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 3);
    assert!(
        store
            .entity_lookup(&case.id, "host", "synthetic-host")
            .unwrap()
            .contains("synthetic-host")
    );
    assert!(
        store
            .text_search(&case.id, "203.0.113.77", 10)
            .unwrap()
            .contains("sshd")
    );
    assert!(
        store
            .neighbors(&case.id, "host", "synthetic-host", 10)
            .unwrap()
            .contains("cron")
    );
    assert_eq!(
        cases
            .verify_parquet_rebuild(&case.id, &sources, &CancellationToken::new())
            .unwrap(),
        1
    );
    engine.verify(&case.id).unwrap();
    let expected = include_str!("../../testkit/fixtures/parser-syslog/private/ground-truth.json");
    assert!(!entries.iter().any(|entry| entry.payload.contains(expected)));
}

#[test]
#[ignore = "manual 1 GiB end-to-end parser benchmark"]
fn syslog_one_gib_ingestion_throughput() -> Result<(), &'static str> {
    use std::io::{Read as _, Write as _};
    if cfg!(debug_assertions) {
        return Err(
            "Run ingestion benchmarks with cargo test --release; unoptimized results are invalid",
        );
    }
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let mut output =
        std::io::BufWriter::new(fs::File::create(sources.join("benchmark.log")).unwrap());
    let line = format!(
        "<34>1 2026-11-01T00:02:03.123456Z synthetic-host sshd 321 AUTH - Synthetic {}\n",
        "x".repeat(950)
    );
    let target = 1024 * 1024 * 1024u64;
    let mut written = 0;
    while written < target {
        output.write_all(line.as_bytes()).unwrap();
        written += line.len() as u64;
    }
    output.flush().unwrap();
    drop(output);
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let parser = Arc::new(SyslogParser);
    let source_parser = irmind_mod_parser_syslog::source_log_parser();
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic syslog benchmark", "local")
        .unwrap();
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: source_parser.as_ref(),
    };
    let started = std::time::Instant::now();
    let mut sample = Vec::new();
    std::io::Read::take(
        fs::File::open(sources.join("benchmark.log")).unwrap(),
        65_536,
    )
    .read_to_end(&mut sample)
    .unwrap();
    let selected = BTreeMap::from([("benchmark.log".into(), selection(&parser, &sample))]);
    cases
        .ingest_local_batch_selected(
            &case.id,
            &sources,
            &["benchmark.log".into()],
            false,
            &selected,
            &CancellationToken::new(),
        )
        .unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "SYSLOG_BENCH bytes={written} seconds={elapsed:.3} MiB_per_second={:.3}",
        f64::from(u32::try_from(written).unwrap()) / 1_048_576.0 / elapsed
    );
    engine.verify(&case.id).unwrap();
    Ok(())
}

fn selection(parser: &SyslogParser, sample: &[u8]) -> ParserSelection {
    ParserSelection {
        parser_id: parser.identity().name.into(),
        parser_version: irmind_mod_parser_syslog::source_log_parser()
            .identity()
            .version
            .into(),
        confidence: parser.detect("synthetic.log", sample).unwrap().value(),
        mode: ParserSelectionMode::Automatic,
        timestamp_context: parser.timestamp_context().map(str::to_owned),
        format_sample_sha256: irmind_app::sha256(sample),
    }
}

#[test]
fn corrupt_gzip_never_commits_a_partial_custody_batch() {
    use std::io::Write as _;
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    // Use a public synthetic compressed seed; changing its trailer invalidates its CRC.
    let mut bytes = include_bytes!("../../../fuzz/seeds/parser_syslog/compressed.gz").to_vec();
    let last = bytes.len() - 8;
    bytes[last] ^= 1;
    fs::File::create(sources.join("broken.gz"))
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let parser = Arc::new(SyslogParser);
    let source_parser = irmind_mod_parser_syslog::source_log_parser();
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic corrupt gzip", "local")
        .unwrap();
    let before = store.entries(&case.id).unwrap().len();
    let cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: source_parser.as_ref(),
    };
    let chosen = BTreeMap::from([("broken.gz".into(), selection(&parser, &bytes))]);
    let ingested = cases
        .ingest_local_batch_selected(
            &case.id,
            &sources,
            &["broken.gz".into()],
            true,
            &chosen,
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(ingested.is_empty());
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(entries.len(), before + 1);
    assert_eq!(entries.last().unwrap().kind, AuditEventKind::ToolError);
    assert!(!entries.iter().any(|entry| matches!(
        entry.kind,
        AuditEventKind::SourceManifestV2 | AuditEventKind::ParquetArtifactV3
    )));
    assert!(
        irmind_app::EvidenceStore::evidence_hashes(store.as_ref(), &case.id)
            .unwrap()
            .is_empty()
    );
    engine.verify(&case.id).unwrap();
}

#[path = "syslog_ingest/time_context.rs"]
mod time_context;
