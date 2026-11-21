use super::{QueryCapturePage, QueryPageInput, SourceQueryError, read_query_capture_pages};
use crate::source_mapping::{SourceInput, SourceMetadata};
use crate::{AppError, ParseReport, ParserIdentity};
use irmind_domain::{
    DecodeAnnotationsV1, EventOrigin, EvidenceHash, IndexedTime, Provenance, SourceFormatV1,
    SourceKind, SourceRecordV1, SourceValue, Tainted,
};
use serde_json::Value;
use std::io::{BufReader, Read, SeekFrom};

/// Rebuild the shared record provenance from authenticated capture metadata.
/// Decoders supply provider-specific page validation and fields.
pub fn decode_query_capture(
    input: SourceInput<'_>,
    identity: ParserIdentity<'_>,
    format: SourceFormatV1,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    mut visit: impl FnMut(
        QueryCapturePage<'_>,
        &mut dyn Read,
        &mut QueryCaptureRows<'_, '_>,
    ) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let meta = input.metadata;
    if meta.source.kind() != SourceKind::ToolResult || meta.source.acquisition().is_none() {
        return Err(SourceQueryError::Scope.into());
    }
    let mut rows = QueryCaptureRows {
        meta,
        identity,
        hash: EvidenceHash::from_bytes(meta.evidence_hash),
        format,
        ordinal: 0,
        report: ParseReport {
            accepted: 0,
            rejected: 0,
            samples: Vec::new(),
        },
        emit,
    };
    let summary = read_query_capture_pages(input.reader, meta.cancel, |page, reader| {
        visit(page, reader, &mut rows)
    })?;
    if summary.identity().0 != &rows.hash {
        return Err(SourceQueryError::Invalid.into());
    }
    Ok(rows.report)
}

pub struct QueryCaptureRows<'a, 'b> {
    meta: SourceMetadata<'a>,
    identity: ParserIdentity<'b>,
    hash: EvidenceHash,
    format: SourceFormatV1,
    ordinal: u64,
    report: ParseReport,
    emit: &'b mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
}

impl QueryCaptureRows<'_, '_> {
    /// Every returned row owns an ordinal, including a rejected row.
    pub fn row(
        &mut self,
        decode: impl FnOnce() -> Option<(IndexedTime, SourceValue)>,
    ) -> Result<(), AppError> {
        if self.meta.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let ordinal = self.ordinal;
        self.ordinal = ordinal.checked_add(1).ok_or(SourceQueryError::Limit)?;
        let origin = EventOrigin::try_new(
            self.hash.clone(),
            ordinal,
            None,
            self.identity.name,
            self.identity.version,
        )
        .map_err(|_| SourceQueryError::Invalid)?;
        let record = decode().and_then(|(time, fields)| {
            SourceRecordV1::try_from_source(
                origin,
                self.meta.source.clone(),
                Some(time),
                self.format.clone(),
                fields,
                DecodeAnnotationsV1::default(),
            )
            .ok()
        });
        if let Some(record) = record {
            (self.emit)(Tainted::from_external(
                record,
                Provenance::new(
                    self.meta.evidence_hash,
                    Some(ordinal),
                    SourceKind::ToolResult,
                ),
            ))?;
            self.report.accepted += 1;
        } else {
            self.report.rejected += 1;
        }
        Ok(())
    }
}

/// Read a bounded provider page from the seekable case spool.
pub fn read_query_json_page(input: &mut dyn QueryPageInput, limit: u64) -> Result<Value, AppError> {
    let size = input
        .seek(SeekFrom::End(0))
        .map_err(|_| SourceQueryError::Invalid)?;
    if size > limit {
        return Err(SourceQueryError::Limit.into());
    }
    input.rewind().map_err(|_| SourceQueryError::Invalid)?;
    serde_json::from_reader(BufReader::new(input.take(size)))
        .map_err(|_| SourceQueryError::Invalid.into())
}
