#![forbid(unsafe_code)]
//! Release-only conversion of 300 distinct small synthetic EVTX sources.
#[path = "source_pipeline/mod.rs"]
mod source_pipeline;
use irmind_app::{
    CancellationToken, LargeCaseStore, MappedIngestRequest, PartitionLimits,
    mapped_ingest::CommittedArtifacts,
};
use irmind_domain::CaseId;
use irmind_mod_parser_evtx::EvtxParser;
use std::sync::Arc;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};
const FILES: u64 = 300;
fn helper() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .ok_or("missing release directory")?
        .join(if cfg!(windows) {
            "irmind-evtx.exe"
        } else {
            "irmind-evtx"
        }))
}
fn source(index: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes =
        include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx")
            .to_vec();
    let base = 4096;
    let end = base + usize::try_from(u32::from_le_bytes(bytes[base + 48..base + 52].try_into()?))?;
    let mut cursor = base + 512;
    while cursor < end {
        let size = usize::try_from(u32::from_le_bytes(
            bytes[cursor + 4..cursor + 8].try_into()?,
        ))?;
        let time = u64::from_le_bytes(bytes[cursor + 16..cursor + 24].try_into()?);
        bytes[cursor + 16..cursor + 24].copy_from_slice(&(time + index * 10_000_000).to_le_bytes());
        cursor += size;
    }
    let crc = evtx::checksum_ieee(&bytes[base + 512..end]);
    bytes[base + 52..base + 56].copy_from_slice(&crc.to_le_bytes());
    let crc =
        evtx::checksum_ieee(&[&bytes[base..base + 120], &bytes[base + 128..base + 512]].concat());
    bytes[base + 124..base + 128].copy_from_slice(&crc.to_le_bytes());
    Ok(bytes)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires --release".into());
    }
    let root = tempfile::tempdir_in(std::env::current_dir()?)?;
    let sources = root.path().join("sources");
    fs::create_dir(&sources)?;
    for index in 0..FILES {
        fs::write(
            sources.join(format!("synthetic-{index:03}.evtx")),
            source(index)?,
        )?;
    }
    let startup = Instant::now();
    let parser = Arc::new(EvtxParser::new(&helper()?, root.path()));
    if let Some(reason) = parser.unavailable_reason() {
        return Err(reason.into());
    }
    let startup_seconds = startup.elapsed().as_secs_f64();
    let first_stats = parser.witness_stats();
    let store = source_pipeline::store(root.path(), parser.clone())?;
    let selected = source_pipeline::selection(parser.clone());
    let id = CaseId::parse("88888888-8888-8888-8888-888888888888")
        .map_err(|_| "invalid synthetic case ID")?;
    let start = Instant::now();
    let mut hashes = BTreeSet::new();
    let (mut records, mut artifacts, mut source_bytes) = (0, 0, 0);
    for index in 0..FILES {
        let prepared = store
            .prepare_mapped_ingest(
                MappedIngestRequest {
                    case_id: &id,
                    source_root: &sources,
                    relative_paths: &[format!("synthetic-{index:03}.evtx")],
                    copy_original: false,
                    parser: &selected,
                    committed_artifacts: CommittedArtifacts::Slice(&[]),
                    limits: PartitionLimits::default(),
                },
                &CancellationToken::new(),
            )?
            .ok_or("mapped preparation unavailable")?;
        for source in &prepared.metadata().sources {
            hashes.insert(source.manifest.sha256.clone());
            records += source.report.accepted;
            source_bytes += source.manifest.size;
        }
        artifacts += prepared.metadata().projections.len();
    }
    let collection_seconds = start.elapsed().as_secs_f64();
    let stats = parser.witness_stats();
    if hashes.len() != 300 || records != 4200 {
        return Err("synthetic collection was not fully converted".into());
    }
    if cfg!(windows) && (first_stats.attempts != 1 || stats.attempts != 1) {
        return Err("witness unexpectedly repeated without a service or validation change".into());
    }
    println!(
        "{}",
        serde_json::json!({"profile":"release", "files":FILES,"source_bytes":source_bytes,
        "unique_source_hashes":hashes.len(),"records":records,"artifacts":artifacts,"startup_seconds":startup_seconds,
        "witness_runs":stats.attempts,"witness_seconds":stats.elapsed.as_secs_f64(),"collection_seconds":collection_seconds,
        "scope":"source hash and re-verification, contained decoding, source decoding, identified mapping and direct V3 Parquet; audit signing excluded"})
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}
