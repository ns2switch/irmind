//! The mandatory V9 tail. Capture trust comes from the caller's authenticated
//! principal-chain result inventory.
use super::{QUERY_CASE_MAX_BYTES, SourceQueryError, SourceQueryResultV1, verify_query_capture};
use crate::{AppError, CancellationToken};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

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

/// Write the exact verified principal-chain capture inventory. The caller
/// discards the incomplete package on any error. The signature and inventory
/// linkage are authenticated before calling this framing routine.
pub fn write_query_capture_section<R: Read>(
    mut output: impl Write,
    captures: &mut [(&SourceQueryResultV1, R)],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    output
        .write_all(&(captures.len() as u64).to_be_bytes())
        .map_err(|error| export_io(&error))?;
    let mut previous = None;
    let mut total = 0_u64;
    for (receipt, input) in captures {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (hash, bytes) = receipt.capture_identity();
        check_inventory(hash, bytes, &mut previous, &mut total)?;
        let descriptor = serde_json::to_vec(&Descriptor {
            bytes,
            capture_sha256: hash.into(),
            chunks: bytes.div_ceil(CHUNK_BYTES),
        })
        .map_err(|_| AppError::InvalidChain(0))?;
        output
            .write_all(&(descriptor.len() as u64).to_be_bytes())
            .map_err(|error| export_io(&error))?;
        output
            .write_all(&descriptor)
            .map_err(|error| export_io(&error))?;
        let verified = verify_query_capture(
            ExportChunks {
                input,
                output: &mut output,
                bytes,
                current: 0,
            },
            cancel,
        )
        .map_err(|error| capture_error(&error))?;
        receipt.verify_capture(&verified)?;
    }
    Ok(())
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
        let mut raw = vec![0; usize::try_from(length).map_err(|_| invalid())?];
        input.read_exact(&mut raw).map_err(|_| invalid())?;
        let descriptor: Descriptor = serde_json::from_slice(&raw).map_err(|_| invalid())?;
        if descriptor.capture_sha256 != hash
            || descriptor.bytes != bytes
            || descriptor.chunks == 0
            || descriptor.chunks > bytes
            || descriptor.chunks.saturating_mul(CHUNK_BYTES) < bytes
            || serde_json::to_vec(&descriptor).map_err(|_| invalid())? != raw
        {
            return Err(invalid());
        }
        check_inventory(hash, bytes, &mut previous, &mut total)?;
        let capture = verify_query_capture(
            CaptureChunks {
                input: &mut input,
                bytes,
                chunks: descriptor.chunks,
                current: 0,
            },
            cancel,
        )
        .map_err(|error| capture_error(&error))?;
        receipt.verify_capture(&capture)?;
    }
    if input.read(&mut [0]).map_err(|_| invalid())? != 0 {
        return Err(AppError::Storage("export has trailing bytes".into()));
    }
    Ok(())
}

fn check_inventory<'a>(
    hash: &'a str,
    bytes: u64,
    previous: &mut Option<&'a str>,
    total: &mut u64,
) -> Result<(), AppError> {
    if previous.is_some_and(|prior| prior >= hash) {
        return Err(AppError::InvalidChain(0));
    }
    *previous = Some(hash);
    *total = total.checked_add(bytes).ok_or(SourceQueryError::Limit)?;
    if *total > QUERY_CASE_MAX_BYTES {
        return Err(SourceQueryError::Limit.into());
    }
    Ok(())
}

fn capture_error(error: &super::CaptureError) -> AppError {
    match error {
        super::CaptureError::Cancelled => AppError::Cancelled,
        _ => AppError::InvalidChain(0),
    }
}

fn export_io(error: &io::Error) -> AppError {
    AppError::Storage(error.to_string())
}

struct ExportChunks<'a, R, W> {
    input: &'a mut R,
    output: &'a mut W,
    bytes: u64,
    current: u64,
}

impl<R: Read, W: Write> Read for ExportChunks<'_, R, W> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes == 0 {
            return self.input.read(buffer);
        }
        if self.current == 0 {
            self.current = self.bytes.min(CHUNK_BYTES);
            self.output.write_all(&self.current.to_be_bytes())?;
        }
        let count = bounded_count(buffer, self.current)?;
        self.input.read_exact(&mut buffer[..count])?;
        self.output.write_all(&buffer[..count])?;
        self.current -= count as u64;
        self.bytes -= count as u64;
        Ok(count)
    }
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
        let count = bounded_count(buffer, self.current)?;
        self.input.read_exact(&mut buffer[..count])?;
        self.current -= count as u64;
        self.bytes -= count as u64;
        Ok(count)
    }
}

fn bounded_count(buffer: &[u8], current: u64) -> io::Result<usize> {
    usize::try_from(current)
        .map(|remaining| buffer.len().min(remaining))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
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
    fn v9_writer_reproduces_the_approved_tail_without_buffering_the_capture() {
        let expected = hex::decode(TAIL.trim()).unwrap();
        let receipt = SourceQueryResultV1::decode(RESULT).unwrap();
        let capture = hex::decode(
            include_str!("../../../../docs/development/source-query-format-vectors/capture.hex")
                .trim(),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let mut written = Vec::new();
        write_query_capture_section(&mut written, &mut [(&receipt, capture.as_slice())], &cancel)
            .unwrap();
        assert_eq!(written, expected);
        let mut with_extra_byte = capture;
        with_extra_byte.push(0);
        assert!(
            write_query_capture_section(
                Vec::new(),
                &mut [(&receipt, with_extra_byte.as_slice())],
                &cancel,
            )
            .is_err()
        );
    }

    #[test]
    fn v9_tail_rejects_changed_lengths_bytes_truncation_or_surplus() {
        let bytes = hex::decode(TAIL.trim()).unwrap();
        let result = SourceQueryResultV1::decode(RESULT).unwrap();
        let cancel = CancellationToken::new();
        let verify = |input: &[u8]| verify_query_capture_section(input, &[&result], &cancel);
        let descriptor_size = usize::try_from(read_length(&mut &bytes[8..]).unwrap()).unwrap();
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
