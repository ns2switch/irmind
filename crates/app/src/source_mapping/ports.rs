use super::{MappingError, MappingManifest, MappingOutput, SourceRecordV1, SourceReferenceV1};
use crate::{AppError, CancellationToken, ParseReport, ParserIdentity, ParserTimeContext};
use irmind_domain::Tainted;
use std::{fs::File, io::Read};

#[derive(Clone, Copy)]
pub struct SourceMetadata<'a> {
    pub source: &'a SourceReferenceV1,
    pub evidence_hash: [u8; 32],
    pub time_context: Option<&'a ParserTimeContext>,
    pub cancel: &'a CancellationToken,
}

pub struct SourceInput<'a> {
    pub metadata: SourceMetadata<'a>,
    pub reader: &'a mut dyn Read,
}
pub struct SourceFileInput<'a> {
    pub metadata: SourceMetadata<'a>,
    pub file: &'a mut File,
}

/// Format decoding only. The caller authenticates the same opened bytes before
/// committing. Implementations retain their own stricter resource limits.
pub trait SourceDecoder: Send + Sync {
    fn identity(&self) -> ParserIdentity<'_>;
    fn source_parallelism(&self) -> crate::SourceParallelism {
        crate::SourceParallelism::Concurrent
    }
    fn needs_random_access(&self, _source: &str, _sample: &[u8]) -> bool {
        false
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError>;

    fn decode_local_file(
        &self,
        input: SourceFileInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_reader(
            SourceInput {
                metadata: input.metadata,
                reader: input.file,
            },
            emit,
        )
    }
}

/// A bounded pure function. Modules receive no I/O, secret, clock or tool ports.
pub trait SourceMapper: Send + Sync {
    fn manifest(&self) -> &MappingManifest;
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError>;
}
