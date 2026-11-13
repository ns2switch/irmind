use super::{MappingError, MappingManifest, MappingOutput, SourceRecordV1, SourceReferenceV1};
use crate::{AppError, CancellationToken, ParseReport, ParserIdentity, ParserTimeContext};
use irmind_domain::Tainted;
use std::{fs::File, io::Read};

#[derive(Clone, Copy)]
pub struct SourceMetadata<'a> {
    pub source: &'a SourceReferenceV1,
    pub evidence_hash: [u8; 32],
    pub time_context: Option<&'a ParserTimeContext>,
    pub cluster_context: Option<&'a crate::SourceClusterContext>,
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

/// The existing input modes carry the same authenticated source metadata.
pub enum DecodeInput<'a> {
    Reader(SourceInput<'a>),
    File(SourceFileInput<'a>),
}

impl<'a> DecodeInput<'a> {
    pub fn into_reader(self) -> SourceInput<'a> {
        match self {
            Self::Reader(input) => input,
            Self::File(input) => SourceInput {
                metadata: input.metadata,
                reader: input.file,
            },
        }
    }
}

/// Scheduling allowance only. The source worker counts toward this budget.
#[derive(Clone, Copy)]
pub struct DecodeBudget {
    workers: std::num::NonZeroUsize,
    queued_bytes: usize,
}

impl DecodeBudget {
    pub const fn sequential() -> Self {
        Self {
            workers: std::num::NonZeroUsize::MIN,
            queued_bytes: 0,
        }
    }

    pub const fn new(workers: std::num::NonZeroUsize, queued_bytes: usize) -> Self {
        Self {
            workers,
            queued_bytes,
        }
    }

    pub const fn workers(self) -> usize {
        self.workers.get()
    }

    pub const fn queued_bytes(self) -> usize {
        self.queued_bytes
    }
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

    /// Formats that can decode independent frames may use the assigned slots.
    /// The default preserves the decoder's existing sequential behavior.
    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        _budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        match input {
            DecodeInput::Reader(input) => self.decode_reader(input, emit),
            DecodeInput::File(input) => self.decode_local_file(input, emit),
        }
    }

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
