use super::{
    super::{SourceQueryError, SourceQueryPageDecoder, page::QueryPageSequence},
    CaptureColumn, CaptureError, Decoder, Descriptor, EvidenceHash, MAX_CHUNK, Page,
    QUERY_CAPTURE_MAGIC, QUERY_MAX_BYTES, QUERY_MAX_PAGES, QUERY_MAX_RECORD_BYTES, QUERY_MAX_ROWS,
    Read, Seek, SeekFrom, SourceDecoderIdentityV1, Write, checked_total, checked_value, io,
};
use crate::CancellationToken;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CapturePageCompleteness {
    Complete = 0,
    ProviderPartial = 1,
    LocalLimit = 2,
    Cancelled = 3,
    Rejected = 4,
}

pub struct CapturePageMetadata {
    pub columns: Vec<CaptureColumn>,
    pub completeness: CapturePageCompleteness,
    pub rows: u64,
}

struct StagedPage {
    start: u64,
    bytes: u64,
    digest: [u8; 32],
    metadata_bytes: usize,
    metadata_digest: [u8; 32],
}

/// Build a capture without buffering service responses in memory. The caller
/// supplies a private case spool which is discarded after finishing or on error.
pub struct QueryCaptureWriter<S> {
    spool: S,
    plan: EvidenceHash,
    decoder: SourceDecoderIdentityV1,
    pages: Vec<StagedPage>,
    rows: u64,
    staged_bytes: u64,
    page_bytes: u64,
    admit_bytes: u64,
    admit_rows: u64,
    sequence: QueryPageSequence,
}

impl<S: Read + Write + Seek> QueryCaptureWriter<S> {
    pub fn new(
        spool: S,
        plan: EvidenceHash,
        decoder: SourceDecoderIdentityV1,
        admit_bytes: u64,
        admit_rows: u64,
    ) -> Result<Self, CaptureError> {
        if !(1..=QUERY_MAX_BYTES).contains(&admit_bytes)
            || !(1..=QUERY_MAX_ROWS).contains(&admit_rows)
        {
            return Err(CaptureError::Limit);
        }
        Ok(Self {
            spool,
            plan,
            decoder,
            pages: Vec::new(),
            rows: 0,
            staged_bytes: 0,
            page_bytes: 0,
            admit_bytes,
            admit_rows,
            sequence: QueryPageSequence::default(),
        })
    }

    /// Check the exact decoder version and provider schema before adding the page.
    /// The input is already bounded by the held reservation; framing overhead is
    /// checked by `stage_page` before any copy into the capture staging file.
    pub fn stage_inspected_page(
        &mut self,
        page: &mut (impl Read + Seek),
        decoder: &dyn SourceQueryPageDecoder,
        next_token: Option<&str>,
        acquisition_rows: u64,
        cancel: &CancellationToken,
    ) -> Result<Option<String>, crate::AppError> {
        let identity = decoder.identity();
        if identity.name != self.decoder.id() || identity.version != self.decoder.version() {
            return Err(SourceQueryError::Invalid.into());
        }
        let inspection = decoder.inspect_page(
            page,
            self.pages.len() as u64,
            self.sequence.schema(),
            cancel,
        )?;
        if inspection.next_token.as_deref() != next_token {
            return Err(SourceQueryError::Unresolved.into());
        }
        let next = inspection.next_token.clone();
        let mut sequence = self.sequence.clone();
        let remaining = acquisition_rows
            .min(self.admit_rows)
            .checked_sub(self.rows)
            .ok_or(SourceQueryError::Limit)?;
        let metadata = sequence.accept(inspection, remaining)?;
        page.rewind().map_err(read_error)?;
        self.stage_page(metadata, page, cancel)?;
        self.sequence = sequence;
        Ok(next)
    }

    pub fn inspected_counts(&self) -> (u64, u64, bool) {
        self.sequence.counts()
    }

    /// Upper bound for the next body, before provider metadata framing.
    pub const fn remaining_capture_bytes(&self) -> u64 {
        self.admit_bytes.saturating_sub(self.page_bytes)
    }

    pub fn stage_page(
        &mut self,
        page: CapturePageMetadata,
        mut input: impl Read,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        if cancel.is_cancelled() {
            return Err(CaptureError::Cancelled);
        }
        let ordinal = self.pages.len() as u64;
        let pages = checked_total(ordinal, 1, QUERY_MAX_PAGES)?;
        let rows = checked_total(self.rows, page.rows, self.admit_rows)?;
        let descriptor = self.descriptor(pages)?;
        let fixed_bytes = (QUERY_CAPTURE_MAGIC.len() + 16 + descriptor.len()) as u64;
        let mut meta = Page {
            columns: page.columns,
            completeness: page.completeness as u8,
            encoding: "identity".into(),
            ordinal,
            rows: page.rows,
            sha256: "0".repeat(64),
        };
        let metadata_bytes = encode(&meta)?.len();
        let required = checked_total(
            self.page_bytes,
            (metadata_bytes + 16) as u64,
            self.admit_bytes,
        )?;
        let maximum = self.admit_bytes - checked_total(fixed_bytes, required, self.admit_bytes)?;
        let start = self.staged_bytes;
        self.spool
            .seek(SeekFrom::Start(start))
            .map_err(read_error)?;
        let (bytes, digest) = stage_body(&mut input, &mut self.spool, maximum, cancel)?;
        meta.sha256 = hex::encode(digest);
        let metadata = encode(&meta)?;
        self.spool.write_all(&metadata).map_err(read_error)?;
        self.rows = rows;
        self.staged_bytes = start + bytes + metadata.len() as u64;
        self.page_bytes = checked_total(required, bytes, self.admit_bytes)?;
        self.pages.push(StagedPage {
            start,
            bytes,
            digest,
            metadata_bytes: metadata.len(),
            metadata_digest: Sha256::digest(metadata).into(),
        });
        Ok(())
    }

    /// Write the committed page prefix and return the exact frame length.
    /// A failed output must be discarded. Provider page bodies remain opaque.
    pub fn finish(
        mut self,
        mut output: impl Write,
        cancel: &CancellationToken,
    ) -> Result<u64, CaptureError> {
        if cancel.is_cancelled() {
            return Err(CaptureError::Cancelled);
        }
        let count = self.pages.len() as u64;
        let descriptor = self.descriptor(count)?;
        let fixed = (QUERY_CAPTURE_MAGIC.len() + 16 + descriptor.len()) as u64;
        let total = checked_total(fixed, self.page_bytes, self.admit_bytes)?;
        self.spool.flush().map_err(read_error)?;
        output.write_all(QUERY_CAPTURE_MAGIC).map_err(read_error)?;
        write_metadata(&mut output, &descriptor)?;
        output.write_all(&count.to_be_bytes()).map_err(read_error)?;
        for page in self.pages {
            if cancel.is_cancelled() {
                return Err(CaptureError::Cancelled);
            }
            self.spool
                .seek(SeekFrom::Start(page.start + page.bytes))
                .map_err(read_error)?;
            let mut metadata = vec![0; page.metadata_bytes];
            self.spool.read_exact(&mut metadata).map_err(read_error)?;
            let digest: [u8; 32] = Sha256::digest(&metadata).into();
            if digest != page.metadata_digest {
                return Err(CaptureError::Integrity);
            }
            write_metadata(&mut output, &metadata)?;
            output
                .write_all(&page.bytes.to_be_bytes())
                .map_err(read_error)?;
            self.spool
                .seek(SeekFrom::Start(page.start))
                .map_err(read_error)?;
            let mut bounded = (&mut self.spool).take(page.bytes);
            let (written, digest) = stage_body(&mut bounded, &mut output, page.bytes, cancel)?;
            if written != page.bytes || digest != page.digest {
                return Err(CaptureError::Integrity);
            }
        }
        output.flush().map_err(read_error)?;
        Ok(total)
    }

    fn descriptor(&self, pages: u64) -> Result<Vec<u8>, CaptureError> {
        encode(&Descriptor {
            decoder: Decoder {
                id: self.decoder.id().into(),
                version: self.decoder.version().into(),
            },
            pages,
            plan: self.plan.as_str().into(),
            version: 1,
        })
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, CaptureError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CaptureError::InvalidFormat)?;
    if bytes.len() > QUERY_MAX_RECORD_BYTES {
        return Err(CaptureError::Limit);
    }
    checked_value(&bytes).map_err(|_| CaptureError::InvalidFormat)?;
    Ok(bytes)
}

fn write_metadata(output: &mut impl Write, data: &[u8]) -> Result<(), CaptureError> {
    output
        .write_all(&(data.len() as u64).to_be_bytes())
        .map_err(read_error)?;
    output.write_all(data).map_err(read_error)
}

fn stage_body(
    input: &mut impl Read,
    output: &mut impl Write,
    limit: u64,
    cancel: &CancellationToken,
) -> Result<(u64, [u8; 32]), CaptureError> {
    let mut buffer = vec![0_u8; MAX_CHUNK];
    let mut digest = Sha256::new();
    let mut bytes = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(CaptureError::Cancelled);
        }
        let probe = (limit - bytes + 1).min(MAX_CHUNK as u64);
        let requested = usize::try_from(probe).map_err(|_| CaptureError::Limit)?;
        let count = match input.read(&mut buffer[..requested]) {
            Ok(count) if count <= requested => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(CaptureError::Read),
        };
        if count == 0 {
            return Ok((bytes, digest.finalize().into()));
        }
        bytes = checked_total(bytes, count as u64, limit)?;
        digest.update(&buffer[..count]);
        output.write_all(&buffer[..count]).map_err(read_error)?;
    }
}

fn read_error(_: io::Error) -> CaptureError {
    CaptureError::Read
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const DESCRIPTOR: &[u8] = include_bytes!(
        "../../../../../docs/development/source-query-format-vectors/capture-descriptor.json"
    );
    const PAGES: &[u8] = include_bytes!(
        "../../../../../docs/development/source-query-format-vectors/page-metadata.json"
    );

    fn writer(limit: u64) -> QueryCaptureWriter<Cursor<Vec<u8>>> {
        let descriptor: Descriptor = serde_json::from_slice(DESCRIPTOR).unwrap();
        let plan = EvidenceHash::parse(&descriptor.plan).unwrap();
        let decoder =
            SourceDecoderIdentityV1::try_new(&descriptor.decoder.id, &descriptor.decoder.version)
                .unwrap();
        QueryCaptureWriter::new(Cursor::new(Vec::new()), plan, decoder, limit, 10).unwrap()
    }

    fn page(metadata: Page) -> CapturePageMetadata {
        CapturePageMetadata {
            columns: metadata.columns,
            completeness: CapturePageCompleteness::Complete,
            rows: metadata.rows,
        }
    }

    #[test]
    fn streaming_capture_writes_the_exact_approved_bytes() {
        let expected = hex::decode(
            include_str!("../../../../../docs/development/source-query-format-vectors/capture.hex")
                .trim(),
        )
        .unwrap();
        let mut capture = writer(expected.len() as u64);
        let cancel = CancellationToken::new();
        let metadata: Vec<Page> = serde_json::from_slice(PAGES).unwrap();
        let bodies = [
            include_bytes!(
                "../../../../../docs/development/source-query-format-vectors/page-0.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../../docs/development/source-query-format-vectors/page-1.json"
            )
            .as_slice(),
        ];
        for (meta, body) in metadata.into_iter().zip(bodies) {
            capture.stage_page(page(meta), body, &cancel).unwrap();
        }
        let mut bytes = Vec::new();
        assert_eq!(
            capture.finish(&mut bytes, &cancel).unwrap(),
            expected.len() as u64
        );
        assert_eq!(bytes, expected);
        super::super::verify_query_capture(bytes.as_slice(), &cancel).unwrap();
    }

    #[test]
    fn capture_staging_honors_limits_cancellation_and_integrity() {
        let mut capture = writer(512);
        let cancel = CancellationToken::new();
        let columns = || CapturePageMetadata {
            columns: vec![],
            completeness: CapturePageCompleteness::Complete,
            rows: 1,
        };
        assert_eq!(
            capture.stage_page(columns(), [1; 512].as_slice(), &cancel),
            Err(CaptureError::Limit)
        );
        capture
            .stage_page(columns(), [1; 16].as_slice(), &cancel)
            .unwrap();
        capture.spool.get_mut()[0] ^= 1;
        assert_eq!(
            capture.finish(Vec::new(), &cancel),
            Err(CaptureError::Integrity)
        );
        cancel.cancel();
        assert_eq!(
            writer(512).stage_page(columns(), [1].as_slice(), &cancel),
            Err(CaptureError::Cancelled)
        );
    }
}
