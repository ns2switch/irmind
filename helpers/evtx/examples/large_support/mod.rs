use ed25519_dalek::{Signer as _, SigningKey};
mod limit;
use irmind_app::Signer;
use irmind_domain::Actor;
pub(super) use limit::check as check_record_limit;
use std::{
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
};
const FIXTURE: &[u8] = include_bytes!("Security.evtx");
pub(super) const RECORDS_PER_CHUNK: u64 = 64;
pub(super) type Error = Box<dyn std::error::Error>;

pub(super) struct SyntheticSigner(SigningKey);
impl SyntheticSigner {
    pub(super) fn new() -> Self {
        Self(SigningKey::from_bytes(&[19; 32]))
    }
}
impl Signer for SyntheticSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, irmind_app::AppError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

pub(super) fn helper() -> Result<PathBuf, Error> {
    if let Some(path) = std::env::var_os("IRMIND_EVTX_HELPER_TEST") {
        return Ok(PathBuf::from(path));
    }
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

fn chunk_header(chunk: &mut [u8], first: u64, last: u64, end: usize) {
    for (offset, value) in [(8, first), (16, last), (24, first), (32, last)] {
        chunk[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let crc = evtx::checksum_ieee(&chunk[512..end]);
    chunk[52..56].copy_from_slice(&crc.to_le_bytes());
    let crc = evtx::checksum_ieee(&[&chunk[..120], &chunk[128..512]].concat());
    chunk[124..128].copy_from_slice(&crc.to_le_bytes());
}

fn user_offsets(chunk: &[u8]) -> Vec<usize> {
    let user = "synthetic-user"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    chunk
        .windows(user.len())
        .enumerate()
        .filter_map(|(offset, value)| (value == user).then_some(offset))
        .collect()
}

fn users(chunk: &mut [u8], offsets: &[usize], index: u64) {
    let name = format!("synthetic-{:04}", index % 1024)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    for offset in offsets {
        chunk[*offset..*offset + name.len()].copy_from_slice(&name);
    }
}

fn record_layout(chunk: &[u8], end: usize) -> Result<Vec<(usize, usize)>, Error> {
    let (mut cursor, mut ordinal) = (512, 1);
    let mut layout = Vec::new();
    while cursor < end {
        let size = usize::try_from(u32::from_le_bytes(
            chunk[cursor + 4..cursor + 8].try_into()?,
        ))?;
        let id = format!("{ordinal:020}")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let position = chunk[cursor + 24..cursor + size - 4]
            .windows(id.len())
            .position(|value| value == id)
            .ok_or("missing synthetic XML record id")?;
        layout.push((cursor, cursor + 24 + position));
        cursor += size;
        ordinal += 1;
    }
    Ok(layout)
}

fn source(path: &Path, chunks: u16, first: u64, dense: bool) -> Result<u64, Error> {
    let fixture: &[u8] = if dense {
        include_bytes!("SecurityDense.evtx")
    } else {
        FIXTURE
    };
    let records_per_chunk = if dense { 128 } else { RECORDS_PER_CHUNK };
    let mut header = fixture[..4096].to_vec();
    header[16..24].copy_from_slice(&(u64::from(chunks) - 1).to_le_bytes());
    header[24..32].copy_from_slice(&(first + u64::from(chunks) * records_per_chunk).to_le_bytes());
    header[42..44].copy_from_slice(&chunks.to_le_bytes());
    let crc = evtx::checksum_ieee(&header[..120]);
    header[124..128].copy_from_slice(&crc.to_le_bytes());
    let mut output = io::BufWriter::new(File::create(path)?);
    output.write_all(&header)?;
    let mut chunk = fixture[4096..].to_vec();
    let offsets = user_offsets(&chunk);
    let end = usize::try_from(u32::from_le_bytes(chunk[48..52].try_into()?))?;
    let layout = record_layout(&chunk, end)?;
    let base = u64::from_le_bytes(chunk[528..536].try_into()?);
    let mut ordinal = first;
    let time_step = if dense { 1 } else { 1_000_000 };
    for _ in 0..chunks {
        let start = ordinal;
        users(&mut chunk, &offsets, ordinal / records_per_chunk);
        for &(cursor, xml_id) in &layout {
            chunk[cursor + 8..cursor + 16].copy_from_slice(&ordinal.to_le_bytes());
            chunk[cursor + 16..cursor + 24]
                .copy_from_slice(&(base + ordinal * time_step).to_le_bytes());
            let id = format!("{ordinal:020}")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            chunk[xml_id..xml_id + id.len()].copy_from_slice(&id);
            ordinal += 1;
        }
        chunk_header(&mut chunk, start, ordinal - 1, end);
        output.write_all(&chunk)?;
    }
    output.flush()?;
    Ok(4096 + u64::from(chunks) * 65_536)
}

pub(super) fn corpus(
    root: &Path,
    mib: u32,
    single: bool,
    dense: bool,
    over_limit: bool,
) -> Result<(Vec<String>, u64, u64), Error> {
    let sources = root.join("sources");
    fs::create_dir(&sources)?;
    let mut remaining = if dense && mib == 4096 {
        irmind_evtx::MAX_RECORDS / 128 + u64::from(over_limit)
    } else {
        (u64::from(mib) * 16).min(u64::from(u16::MAX))
    };
    let records_per_chunk = if dense { 128 } else { RECORDS_PER_CHUNK };
    let mut names = Vec::new();
    let (mut bytes, mut records) = (0, 0);
    while remaining > 0 {
        let chunks = u16::try_from(remaining.min(if single { u64::from(u16::MAX) } else { 4096 }))?;
        if chunks == 0 {
            break;
        }
        let name = format!("synthetic-security-{:03}.evtx", names.len());
        let size = source(&sources.join(&name), chunks, records + 1, dense)?;
        names.push(name);
        bytes += size;
        records += u64::from(chunks) * records_per_chunk;
        remaining -= u64::from(chunks);
    }
    Ok((names, bytes, records))
}

#[cfg(test)]
mod tests {
    #[test]
    fn corpus_has_valid_chunk_checksums_and_distinct_source_records() -> Result<(), super::Error> {
        let root = tempfile::tempdir()?;
        let (names, bytes, records) = super::corpus(root.path(), 1, false, false, false)?;
        assert_eq!(names.len(), 1);
        assert_eq!(bytes, 1_048_576 + 4096);
        assert_eq!(records, 16 * super::RECORDS_PER_CHUNK);
        let file = std::fs::File::open(root.path().join("sources").join(&names[0]))?;
        let mut output = Vec::new();
        irmind_evtx::decode(file, &mut output)?;
        let frames = std::str::from_utf8(&output)?
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()?;
        let ids = frames
            .iter()
            .filter_map(|row| row["record_id"].as_u64())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(u64::try_from(ids.len())?, records);
        assert_eq!(
            frames.last().ok_or("missing completion")?["accepted"],
            records
        );
        assert_eq!(frames.last().ok_or("missing completion")?["rejected"], 0);
        Ok(())
    }
}
