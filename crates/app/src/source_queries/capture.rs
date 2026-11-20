use super::{
    QUERY_CAPTURE_MAGIC, QUERY_MAX_BYTES, QUERY_MAX_PAGES, QUERY_MAX_RECORD_BYTES, QUERY_MAX_ROWS,
    canonical::checked_value,
};
use crate::CancellationToken;
use irmind_domain::{EvidenceHash, SourceDecoderIdentityV1};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use thiserror::Error;

const PAGE_DOMAIN: &[u8] = b"irmind-source-query-pages-v1\0";
const MAX_CHUNK: usize = 64 * 1024;

mod writer;
pub use writer::{CapturePageCompleteness, CapturePageMetadata, QueryCaptureWriter};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CaptureError {
    #[error("invalid source query capture framing or metadata")]
    InvalidFormat,
    #[error("source query capture exceeds its page, row, or byte limit")]
    Limit,
    #[error("source query capture page hash mismatch")]
    Integrity,
    #[error("source query capture could not be read")]
    Read,
    #[error("source query capture verification cancelled")]
    Cancelled,
}

/// Facts about a structurally valid capture. The signed result must authenticate
/// these facts before they are used as custody evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct QueryCaptureSummary {
    pub(super) capture_sha256: EvidenceHash,
    pub(super) bytes: u64,
    pub(super) page_count: u64,
    pub(super) page_commitment: EvidenceHash,
    pub(super) rows: u64,
    pub(super) plan: EvidenceHash,
    pub(super) decoder: SourceDecoderIdentityV1,
    pub(super) completeness_mask: u8,
}

// The member order in these fixed schemas is the canonical UTF-8 key order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    decoder: Decoder,
    pages: u64,
    plan: String,
    version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Decoder {
    id: String,
    version: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    columns: Vec<CaptureColumn>,
    completeness: u8,
    encoding: String,
    ordinal: u64,
    rows: u64,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub native_type: String,
}

/// Validate the capture's exact framing and page hashes with bounded memory.
/// Body bytes remain opaque, including any values that look like instructions.
/// The reader is for retained captures. Cancellation is checked between reads;
/// the caller owns the deadline of an underlying blocking reader.
pub fn verify_query_capture(
    input: impl Read,
    cancel: &CancellationToken,
) -> Result<QueryCaptureSummary, CaptureError> {
    let mut input = CaptureReader {
        input,
        cancel,
        bytes: 0,
        digest: Sha256::new(),
    };
    let mut magic = [0u8; QUERY_CAPTURE_MAGIC.len()];
    input.read_exact(&mut magic)?;
    if magic != QUERY_CAPTURE_MAGIC {
        return Err(CaptureError::InvalidFormat);
    }
    let descriptor: Descriptor = input.metadata()?;
    let plan = EvidenceHash::parse(&descriptor.plan).map_err(|_| CaptureError::InvalidFormat)?;
    let decoder =
        SourceDecoderIdentityV1::try_new(&descriptor.decoder.id, &descriptor.decoder.version)
            .map_err(|_| CaptureError::InvalidFormat)?;
    let page_count = input.count()?;
    if descriptor.version != 1 || descriptor.pages != page_count {
        return Err(CaptureError::InvalidFormat);
    }
    if page_count > QUERY_MAX_PAGES {
        return Err(CaptureError::Limit);
    }

    let mut pages = Sha256::new();
    pages.update(PAGE_DOMAIN);
    pages.update(page_count.to_be_bytes());
    let mut rows = 0;
    let mut completeness_mask = 0;
    let mut buffer = vec![0; MAX_CHUNK];
    for ordinal in 0..page_count {
        let page: Page = input.metadata()?;
        if page.ordinal != ordinal || page.completeness > 4 {
            return Err(CaptureError::InvalidFormat);
        }
        EvidenceHash::parse(&page.sha256).map_err(|_| CaptureError::InvalidFormat)?;
        let mut expected_hash = [0; 32];
        hex::decode_to_slice(&page.sha256, &mut expected_hash)
            .map_err(|_| CaptureError::InvalidFormat)?;
        rows = checked_total(rows, page.rows, QUERY_MAX_ROWS)?;
        let body_bytes = input.count()?;
        let body_hash = input.hash_body(body_bytes, &mut buffer)?;
        if body_hash != expected_hash {
            return Err(CaptureError::Integrity);
        }
        pages.update(ordinal.to_be_bytes());
        pages.update(body_hash);
        pages.update(body_bytes.to_be_bytes());
        pages.update(page.rows.to_be_bytes());
        pages.update([page.completeness]);
        completeness_mask |= 1 << page.completeness;
    }
    if input.read(&mut [0])? != 0 {
        return Err(CaptureError::InvalidFormat);
    }
    Ok(QueryCaptureSummary {
        capture_sha256: EvidenceHash::from_bytes(input.digest.finalize().into()),
        bytes: input.bytes,
        page_count,
        page_commitment: EvidenceHash::from_bytes(pages.finalize().into()),
        rows,
        plan,
        decoder,
        completeness_mask,
    })
}

struct CaptureReader<'a, R> {
    input: R,
    cancel: &'a CancellationToken,
    bytes: u64,
    digest: Sha256,
}

impl<R: Read> CaptureReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, CaptureError> {
        loop {
            if self.cancel.is_cancelled() {
                return Err(CaptureError::Cancelled);
            }
            match self.input.read(bytes) {
                Ok(count) if count <= bytes.len() => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                _ => return Err(CaptureError::Read),
            }
        }
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> Result<(), CaptureError> {
        let total = checked_total(self.bytes, bytes.len() as u64, QUERY_MAX_BYTES)?;
        while !bytes.is_empty() {
            let chunk = bytes.len().min(MAX_CHUNK);
            let count = self.read(&mut bytes[..chunk])?;
            if count == 0 {
                return Err(CaptureError::InvalidFormat);
            }
            self.digest.update(&bytes[..count]);
            bytes = &mut bytes[count..];
        }
        self.bytes = total;
        Ok(())
    }

    fn count(&mut self) -> Result<u64, CaptureError> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn metadata<T: DeserializeOwned + Serialize>(&mut self) -> Result<T, CaptureError> {
        let size = usize::try_from(self.count()?).map_err(|_| CaptureError::Limit)?;
        if size > QUERY_MAX_RECORD_BYTES {
            return Err(CaptureError::Limit);
        }
        let mut bytes = vec![0; size];
        self.read_exact(&mut bytes)?;
        // Read the bounded JSON grammar first for depth, node and duplicate
        // member checks, before decoding to the exact wire-schema types.
        let value = checked_value(&bytes).map_err(|_| CaptureError::InvalidFormat)?;
        let value: T = serde_json::from_value(value).map_err(|_| CaptureError::InvalidFormat)?;
        if serde_json::to_vec(&value).map_err(|_| CaptureError::InvalidFormat)? != bytes {
            return Err(CaptureError::InvalidFormat);
        }
        Ok(value)
    }

    fn hash_body(&mut self, size: u64, buffer: &mut [u8]) -> Result<[u8; 32], CaptureError> {
        checked_total(self.bytes, size, QUERY_MAX_BYTES)?;
        let mut remaining = usize::try_from(size).map_err(|_| CaptureError::Limit)?;
        let mut hash = Sha256::new();
        while remaining != 0 {
            let count = remaining.min(buffer.len());
            self.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            remaining -= count;
        }
        Ok(hash.finalize().into())
    }
}

fn checked_total(current: u64, amount: u64, max: u64) -> Result<u64, CaptureError> {
    current
        .checked_add(amount)
        .filter(|&total| total <= max)
        .ok_or(CaptureError::Limit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
