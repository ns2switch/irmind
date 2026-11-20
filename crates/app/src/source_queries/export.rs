//! The mandatory V9 tail. Capture trust comes from the caller's authenticated
//! principal-chain result inventory.
use super::{QUERY_CASE_MAX_BYTES, SourceQueryError, SourceQueryResultV1, verify_query_capture};
use crate::{AppError, CancellationToken};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

const DESCRIPTOR_BYTES: u64 = 256;
const CHUNK_BYTES: u64 = 512 * 1024;

// Fields are in canonical UTF-8 key order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    bytes: u64,
    capture_sha256: String,
    chunks: u64,
}

/// Verify capture frames against the exact signed principal-chain inventory, in
/// SHA-256 order. Bodies are never assembled into an in-memory capture.
pub fn verify_query_capture_section(
    mut input: impl Read,
    expected: &[&SourceQueryResultV1],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let invalid = || AppError::InvalidChain(0);
    let count = read_length(&mut input).map_err(|_| invalid())?;
    if count != expected.len() as u64 {
        return Err(invalid());
    }
    let mut previous = None;
    let mut total = 0_u64;
    for receipt in expected {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (hash, bytes) = receipt.capture_identity();
        let length = read_length(&mut input).map_err(|_| invalid())?;
        if length == 0 || length > DESCRIPTOR_BYTES {
            return Err(invalid());
        }
        let mut raw = vec![0; length as usize];
        input.read_exact(&mut raw).map_err(|_| invalid())?;
        let descriptor: Descriptor = serde_json::from_slice(&raw).map_err(|_| invalid())?;
        if previous.is_some_and(|prior| prior >= hash)
            || descriptor.capture_sha256 != hash
            || descriptor.bytes != bytes
            || descriptor.chunks == 0
            || descriptor.chunks > bytes
            || descriptor.chunks.saturating_mul(CHUNK_BYTES) < bytes
            || serde_json::to_vec(&descriptor).map_err(|_| invalid())? != raw
        {
            return Err(invalid());
        }
        previous = Some(hash);
        total = total.checked_add(bytes).ok_or_else(invalid)?;
        if total > QUERY_CASE_MAX_BYTES {
            return Err(SourceQueryError::Limit.into());
        }
        let capture = verify_query_capture(
            CaptureChunks {
                input: &mut input,
                bytes,
                chunks: descriptor.chunks,
                current: 0,
            },
            cancel,
        )
        .map_err(|error| match error {
            super::CaptureError::Cancelled => AppError::Cancelled,
            _ => invalid(),
        })?;
        receipt.verify_capture(&capture)?;
    }
    if input.read(&mut [0]).map_err(|_| invalid())? != 0 {
        return Err(AppError::Storage("export has trailing bytes".into()));
    }
    Ok(())
}

struct CaptureChunks<'a, R> {
    input: &'a mut R,
    bytes: u64,
    chunks: u64,
    current: u64,
}

impl<R: Read> Read for CaptureChunks<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || (self.bytes == 0 && self.chunks == 0 && self.current == 0) {
            return Ok(0);
        }
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        if self.current == 0 {
            self.chunks = self.chunks.checked_sub(1).ok_or_else(invalid)?;
            let size = read_length(self.input)?;
            if size == 0 || size > CHUNK_BYTES || size > self.bytes {
                return Err(invalid());
            }
            self.current = size;
        }
        let count = buffer.len().min(self.current as usize);
        self.input.read_exact(&mut buffer[..count])?;
        self.current -= count as u64;
        self.bytes -= count as u64;
        Ok(count)
    }
}

fn read_length(input: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TAIL: &str = include_str!(
        "../../../../docs/development/source-query-format-vectors/v9-populated-tail.hex"
    );
    const RESULT: &[u8] =
        include_bytes!("../../../../docs/development/source-query-format-vectors/result.json");

    #[test]
    fn approved_v9_tail_verifies_against_the_result_receipt() {
        let bytes = hex::decode(TAIL.trim()).unwrap();
        let result = SourceQueryResultV1::decode(RESULT).unwrap();
        let cancel = CancellationToken::new();
        verify_query_capture_section(bytes.as_slice(), &[&result], &cancel).unwrap();
        assert!(verify_query_capture_section(bytes.as_slice(), &[], &cancel).is_err());
        assert!(verify_query_capture_section(&[0; 8][..], &[&result], &cancel).is_err());
    }

    #[test]
    fn v9_tail_rejects_changed_lengths_bytes_truncation_or_surplus() {
        let bytes = hex::decode(TAIL.trim()).unwrap();
        let result = SourceQueryResultV1::decode(RESULT).unwrap();
        let cancel = CancellationToken::new();
        let verify = |input: &[u8]| verify_query_capture_section(input, &[&result], &cancel);
        let descriptor_size = read_length(&mut &bytes[8..]).unwrap() as usize;
        let body_header = 16 + descriptor_size;
        let mut excessive = bytes.clone();
        excessive[body_header..body_header + 8].copy_from_slice(&(CHUNK_BYTES + 1).to_be_bytes());
        assert!(verify(&excessive).is_err());
        assert!(verify(&bytes[..bytes.len() - 1]).is_err());
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify(&changed).is_err());
        let mut trailing = bytes;
        trailing.extend_from_slice(&[0; 8]);
        assert!(verify(&trailing).is_err());
    }
}
