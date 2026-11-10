//! Original OCSF fields and timestamps only; class interpretation is a mapping.
mod fields;
mod json;
mod parquet;
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{SourceFileInput, SourceInput, SourceMetadata, SourceRecordV1},
};
use irmind_domain::{ParserLocation, Provenance, Tainted};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};
pub struct OcsfSourceDecoder;
pub(super) const VERSION: &str = "ocsf-source-v1";
impl SourceDecoder for OcsfSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-ocsf",
            version: VERSION,
        }
    }
    fn needs_random_access(&self, _: &str, sample: &[u8]) -> bool {
        sample.starts_with(b"PAR1")
    }
    fn decode_reader(
        &self,
        mut input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        json::decode(&mut input, emit)
    }
    fn decode_local_file(
        &self,
        mut input: SourceFileInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        input.file.seek(SeekFrom::Start(0)).map_err(|_| invalid())?;
        let mut magic = [0; 4];
        let count = input.file.read(&mut magic).map_err(|_| invalid())?;
        input.file.seek(SeekFrom::Start(0)).map_err(|_| invalid())?;
        if count == 4 && &magic == b"PAR1" {
            parquet::decode(&mut input, emit)
        } else {
            self.decode_reader(
                SourceInput {
                    metadata: input.metadata,
                    reader: input.file,
                },
                emit,
            )
        }
    }
}
struct State<'a> {
    metadata: SourceMetadata<'a>,
    report: ParseReport,
    seen: u64,
    encoding: &'static str,
}
impl<'a> State<'a> {
    fn new(metadata: SourceMetadata<'a>, encoding: &'static str) -> Self {
        Self {
            metadata,
            report: ParseReport {
                accepted: 0,
                rejected: 0,
                samples: vec![],
            },
            seen: 0,
            encoding,
        }
    }
    fn record(
        &mut self,
        bytes: &[u8],
        offset: Option<u64>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        self.accept(
            bytes,
            |state| {
                fields::decode(
                    bytes,
                    state.metadata,
                    state.report.accepted as u64,
                    state.seen - 1,
                    offset,
                    state.encoding,
                )
            },
            offset,
            emit,
        )
    }
    fn record_fields(
        &mut self,
        values: Result<irmind_domain::SourceValue, AppError>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        let sample = format!(
            "Parquet record {}: unsupported value or source limit",
            self.seen
        );
        self.accept(
            sample.as_bytes(),
            |state| {
                values.and_then(|fields| {
                    fields::build(
                        fields,
                        state.metadata,
                        state.report.accepted as u64,
                        state.seen - 1,
                        None,
                        state.encoding,
                    )
                })
            },
            None,
            emit,
        )
    }
    fn accept(
        &mut self,
        bytes: &[u8],
        build: impl FnOnce(&Self) -> Result<SourceRecordV1, AppError>,
        offset: Option<u64>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if self.seen >= 10_000_000 {
            return Err(limit());
        }
        self.seen += 1;
        let source = build(self);
        match source {
            Ok(source) => {
                let mut provenance = Provenance::new(
                    self.metadata.evidence_hash,
                    Some(self.report.accepted as u64),
                    self.metadata.source.kind(),
                );
                if let Some(offset) = offset {
                    provenance = provenance.with_parser_location(
                        ParserLocation::new(
                            self.metadata.source.reference(),
                            "parser-ocsf",
                            offset,
                        )
                        .map_err(|_| invalid())?,
                    );
                }
                emit(Tainted::from_external(source, provenance))?;
                self.report.accepted += 1;
            }
            Err(_) => self.reject(bytes),
        }
        Ok(())
    }
    fn reject(&mut self, bytes: &[u8]) {
        self.report.rejected += 1;
        if self.report.samples.len() < 3 {
            self.report.samples.push(
                String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                    .chars()
                    .flat_map(char::escape_default)
                    .take(256)
                    .collect(),
            );
        }
    }
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
fn limit() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceLimit)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(Arc::new(OcsfSourceDecoder))
            .with_detector(|source, sample| crate::OcsfParser.detect(source, sample)),
    )
}
