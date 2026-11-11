#![forbid(unsafe_code)]
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
    fs::{self, File},
    io::Write as _,
    path::Path,
    time::Instant,
};

fn corpus(path: &Path) -> std::io::Result<u64> {
    let bytes = include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx");
    let mut header = bytes[..4096].to_vec();
    let chunks = 16383u16;
    header[16..24].copy_from_slice(&(u64::from(chunks) - 1).to_le_bytes());
    header[24..32].copy_from_slice(&(u64::from(chunks) * 14 + 1).to_le_bytes());
    header[42..44].copy_from_slice(&chunks.to_le_bytes());
    let crc = evtx::checksum_ieee(&header[..120]);
    header[124..128].copy_from_slice(&crc.to_le_bytes());
    let mut out = std::io::BufWriter::new(File::create(path)?);
    out.write_all(&header)?;
    let mut chunk = bytes[4096..].to_vec();
    let end = usize::try_from(u32::from_le_bytes(
        chunk[48..52].try_into().map_err(std::io::Error::other)?,
    ))
    .map_err(std::io::Error::other)?;
    let base = u64::from_le_bytes(chunk[528..536].try_into().map_err(std::io::Error::other)?);
    let mut ordinal = 0u64;
    for _ in 0..chunks {
        let mut cursor = 512usize;
        while cursor < end {
            let size = usize::try_from(u32::from_le_bytes(
                chunk[cursor + 4..cursor + 8]
                    .try_into()
                    .map_err(std::io::Error::other)?,
            ))
            .map_err(std::io::Error::other)?;
            chunk[cursor + 16..cursor + 24].copy_from_slice(&(base + ordinal * 10).to_le_bytes());
            ordinal += 1;
            cursor += size;
        }
        let crc = evtx::checksum_ieee(&chunk[512..end]);
        chunk[52..56].copy_from_slice(&crc.to_le_bytes());
        let crc = evtx::checksum_ieee(&[&chunk[..120], &chunk[128..512]].concat());
        chunk[124..128].copy_from_slice(&crc.to_le_bytes());
        out.write_all(&chunk)?;
    }
    out.flush()?;
    Ok(4096 + u64::from(chunks) * 65536)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires --release".into());
    }
    let helper = std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .ok_or("missing release directory")?
        .join(if cfg!(windows) {
            "irmind-evtx.exe"
        } else {
            "irmind-evtx"
        });
    let root = tempfile::tempdir_in(std::env::current_dir()?)?;
    let sources = root.path().join("sources");
    fs::create_dir(&sources)?;
    let size = corpus(&sources.join("synthetic.evtx"))?;
    let parser = Arc::new(EvtxParser::new(&helper, root.path()));
    if let Some(reason) = parser.unavailable_reason() {
        return Err(reason.into());
    }
    let store = source_pipeline::store(root.path(), parser.clone())?;
    let selected = source_pipeline::selection(parser.clone());
    let id = CaseId::parse("88888888-8888-8888-8888-888888888888")
        .map_err(|_| std::io::Error::other("invalid synthetic case id"))?;
    let start = Instant::now();
    let prepared = store
        .prepare_mapped_ingest(
            MappedIngestRequest {
                case_id: &id,
                source_root: &sources,
                relative_paths: &["synthetic.evtx".into()],
                copy_original: false,
                parser: &selected,
                committed_artifacts: CommittedArtifacts::Slice(&[]),
                limits: PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )?
        .ok_or("mapped preparation unavailable")?;
    let seconds = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({"profile":"release","source_bytes":size,"seconds":seconds,"mib_per_second":f64::from(u32::try_from(size)?)/1_048_576.0/seconds,"records":prepared.metadata().sources.iter().map(|source| source.report.accepted).sum::<usize>(),"artifacts":prepared.metadata().projections.len(),"scope":"authenticated source hash, isolated decode, source decoding, identified mapping and direct V3 conversion; signing excluded","corpus":"repeated synthetic Security mapping chunks"})
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}
