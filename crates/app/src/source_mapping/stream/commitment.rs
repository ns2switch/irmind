use super::{AppError, SourceMetadata, SourceRecordV1, invalid};
use irmind_domain::EvidenceHash;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

pub(super) fn spool_tuple(source: &SourceRecordV1) -> Vec<u8> {
    let mut digest = Sha256::new();
    source.feed_canonical(&mut |bytes| digest.update(bytes));
    let mut tuple = Vec::with_capacity(49);
    tuple.extend_from_slice(&source.origin().record().to_be_bytes());
    tuple.push(u8::from(source.origin().offset().is_some()));
    if let Some(offset) = source.origin().offset() {
        tuple.extend_from_slice(&offset.to_be_bytes());
    }
    tuple.extend_from_slice(&digest.finalize());
    tuple
}

pub(super) fn finish<S: Read + Seek>(
    spool: &mut S,
    count: u64,
    metadata: SourceMetadata<'_>,
    written: Sha256,
) -> Result<EvidenceHash, AppError> {
    spool.seek(SeekFrom::Start(0)).map_err(|_| invalid())?;
    let source = EvidenceHash::from_bytes(metadata.evidence_hash);
    let mut digest = Sha256::new();
    digest.update(b"irmind-source-records-commitment-v1\0");
    digest.update(count.to_be_bytes());
    let mut observed = Sha256::new();
    let mut spool = std::io::BufReader::with_capacity(64 * 1024, spool);
    let mut tuple = Vec::with_capacity(129);
    for _ in 0..count {
        if metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut header = [0u8; 9];
        spool.read_exact(&mut header).map_err(|_| invalid())?;
        observed.update(header);
        if header[8] > 1 {
            return Err(invalid());
        }
        tuple.clear();
        field(&mut tuple, source.as_str().as_bytes());
        tuple.extend_from_slice(&header);
        if header[8] == 1 {
            let mut offset = [0u8; 8];
            spool.read_exact(&mut offset).map_err(|_| invalid())?;
            observed.update(offset);
            tuple.extend_from_slice(&offset);
        }
        let mut record = [0u8; 32];
        spool.read_exact(&mut record).map_err(|_| invalid())?;
        observed.update(record);
        field(&mut tuple, &record);
        digest.update((tuple.len() as u64).to_be_bytes());
        digest.update(&tuple);
    }
    let mut extra = [0u8; 1];
    if spool.read(&mut extra).map_err(|_| invalid())? != 0
        || observed.finalize() != written.finalize()
    {
        return Err(invalid());
    }
    Ok(EvidenceHash::from_bytes(digest.finalize().into()))
}
fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}
