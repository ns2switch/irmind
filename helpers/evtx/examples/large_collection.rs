#![forbid(unsafe_code)]
//! Release-only signed ingestion of bounded, synthetic Security.evtx sources.
mod large_support;
use irmind_app::{
    AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, LogParser as _, ParserSelection, ParserSelectionMode, StreamingEventParser,
    sha256,
};
use irmind_domain::ExecutionMode;
use irmind_infra::{LocalStore, LocalVerifier, ParquetStore, SystemClock};
use irmind_mod_parser_evtx::EvtxParser;
use irmind_security::MandatoryGuard;
use std::{collections::BTreeMap, fs::File, io::Read as _, path::Path, sync::Arc, time::Instant};

fn selection(path: &Path, parser: &EvtxParser) -> Result<ParserSelection, large_support::Error> {
    let mut sample = vec![0; 65_536];
    File::open(path)?.read_exact(&mut sample)?;
    let confidence = parser
        .detect("synthetic.evtx", &sample)
        .ok_or("synthetic EVTX detection failed")?;
    Ok(ParserSelection {
        parser_id: "parser-evtx".into(),
        parser_version: parser.streaming_version().into(),
        confidence: confidence.value(),
        mode: ParserSelectionMode::Automatic,
        timestamp_context: None,
        format_sample_sha256: sha256(&sample),
    })
}

fn setup(
    root: &Path,
    parser: Arc<EvtxParser>,
) -> Result<(Engine<'static>, Arc<LocalStore>), large_support::Error> {
    let local = Arc::new(LocalStore::open(root)?);
    let signer = Arc::new(large_support::SyntheticSigner::new());
    let engine = Engine::new(
        EnginePorts::new(
            local.clone(),
            local.clone(),
            local.clone(),
            local.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new()?),
            parser,
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )?;
    Ok((engine, local))
}

fn ingest(
    root: &Path,
    names: &[String],
    bytes: u64,
    expected: u64,
) -> Result<(), large_support::Error> {
    let startup = Instant::now();
    let parser = Arc::new(EvtxParser::new(&large_support::helper()?, root));
    if let Some(reason) = parser.unavailable_reason() {
        return Err(reason.into());
    }
    let startup_seconds = startup.elapsed().as_secs_f64();
    let (engine, local) = setup(root, parser.clone())?;
    let case = engine.create_case(
        "Synthetic large Windows Security logs",
        "local evidence only",
    )?;
    let parquet = ParquetStore::open_precise(root)?;
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &parquet,
        parser: parser.as_ref(),
    };
    let sources = root.join("sources");
    let selections = names
        .iter()
        .map(|name| Ok((name.clone(), selection(&sources.join(name), &parser)?)))
        .collect::<Result<BTreeMap<_, _>, large_support::Error>>()?;
    println!(
        "{}",
        serde_json::json!({"phase":"ingest", "source_bytes":bytes, "files":names.len()})
    );
    let start = Instant::now();
    use_cases.ingest_local_batch_selected(
        &case.id,
        &sources,
        names,
        false,
        &selections,
        &CancellationToken::new(),
    )?;
    let seconds = start.elapsed().as_secs_f64();
    let caps = names
        .iter()
        .map(|name| {
            let size = std::fs::metadata(sources.join(name))?.len();
            Ok(
                serde_json::json!({"source_bytes":size, "expected_records":((size-4096)/65_536)*large_support::RECORDS_PER_CHUNK,
            "output_budget_bytes":(size.saturating_mul(32)+(1_u64<<20)).min(8_u64<<30)}),
            )
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let verify_start = Instant::now();
    engine.verify(&case.id)?;
    let artifacts = use_cases.verify_parquet(&case.id, &CancellationToken::new())?;
    let summary = local.graph_summary(&case.id)?;
    if !summary.starts_with(&format!("Parquet records={expected};")) {
        return Err("large EVTX collection did not ingest every expected record".into());
    }
    let verification_seconds = verify_start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({"phase":"complete", "profile":"release",
        "source_bytes":bytes, "files":names.len(), "records":expected, "artifacts":artifacts,
        "seconds":seconds, "mib_per_second":f64::from(u32::try_from(bytes)?)/1_048_576.0/seconds,
        "startup_seconds":startup_seconds, "verification_seconds":verification_seconds,
        "signed_entries":local.entries(&case.id)?.len(), "witness_runs":parser.witness_stats().attempts,
        "limits_reached":false, "record_limit_per_file":1_000_000,
        "per_file_budgets":caps, "decode_timeout_seconds":600,
        "scope":"source hashing, contained decoding, normalization, V2 Parquet and signed custody; final full verification timed separately"})
    );
    Ok(())
}

fn main() -> Result<(), large_support::Error> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires --release".into());
    }
    let mib = std::env::args()
        .nth(1)
        .ok_or("specify corpus MiB")?
        .parse::<u32>()?;
    if !matches!(mib, 1 | 16 | 100 | 1024) {
        return Err("supported corpora: 1, 16, 100 or 1024 MiB".into());
    }
    let root = tempfile::tempdir_in(std::env::current_dir()?)?;
    let probe = std::env::args().any(|arg| arg == "--record-limit-probe");
    let single = probe || std::env::args().any(|arg| arg == "--single-source");
    let (names, bytes, expected) = large_support::corpus(root.path(), mib, single)?;
    if probe {
        println!(
            "{}",
            large_support::check_record_limit(
                &root.path().join("sources").join(&names[0]),
                expected
            )?
        );
        return Ok(());
    }
    ingest(root.path(), &names, bytes, expected)
}
