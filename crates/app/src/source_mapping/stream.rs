//! Streaming input accounting uses a caller-owned private tuple spool, not a decoded cache.
mod commitment;
mod prepared;
mod replay;
mod validation;
use super::{
    MappingCatalog, MappingDiagnostic, MappingIdentityV1, MappingOutput, SourceMetadata,
    SourceRecordV1,
};
use crate::{AppError, ParseReport, ParserIdentity};
use irmind_domain::{
    EvidenceHash, MappingCountsV1, MappingRouteV1, SourceDecoderIdentityV1, SourceFormatIdentityV1,
    SourceRecordSetV1, Tainted,
};
pub use prepared::{PreparedSourceRecord, SourceRecordPreparer};
pub use replay::SourceRecordReplay;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, Write},
};

pub struct MappedSourceRecord {
    pub identity: Option<MappingIdentityV1>,
    pub output: Tainted<MappingOutput>,
}

#[derive(Default)]
struct Counts {
    accepted: u64,
    unclassified: u64,
    unsupported: u64,
    missing: u64,
}
impl Counts {
    fn add(&mut self, output: &MappingOutput) {
        self.accepted += 1;
        let codes = output.diagnostics();
        self.unclassified += u64::from(!codes.is_empty());
        self.unsupported += u64::from(codes.contains(&MappingDiagnostic::UnsupportedValue));
        self.missing += u64::from(codes.contains(&MappingDiagnostic::MissingRequiredValue));
    }
    fn finish(self) -> Result<MappingCountsV1, AppError> {
        MappingCountsV1::try_new(
            self.accepted,
            self.unclassified,
            self.unsupported,
            self.missing,
        )
        .map_err(|_| invalid())
    }
}

#[derive(Clone, Copy)]
enum OffsetState {
    Initial,
    Unavailable,
    Known(u64),
}

pub struct SourceRecordAccumulator<'a> {
    metadata: SourceMetadata<'a>,
    identity: SourceDecoderIdentityV1,
    catalog: &'a MappingCatalog,
    source_size: u64,
    source_hash: EvidenceHash,
    records: u64,
    previous: Option<u64>,
    offset: OffsetState,
    formats: BTreeSet<SourceFormatIdentityV1>,
    routes: BTreeMap<Option<MappingIdentityV1>, Counts>,
    spool_hash: Sha256,
}
impl<'a> SourceRecordAccumulator<'a> {
    pub fn new(
        metadata: SourceMetadata<'a>,
        identity: ParserIdentity<'_>,
        source_size: u64,
        catalog: &'a MappingCatalog,
    ) -> Result<Self, AppError> {
        catalog
            .decoder(identity.name, identity.version)
            .map_err(super::MappingError::into_app)?;
        Ok(Self {
            metadata,
            identity: SourceDecoderIdentityV1::try_new(identity.name, identity.version)
                .map_err(|_| invalid())?,
            catalog,
            source_size,
            source_hash: EvidenceHash::from_bytes(metadata.evidence_hash),
            records: 0,
            previous: None,
            offset: OffsetState::Initial,
            formats: BTreeSet::new(),
            routes: BTreeMap::new(),
            spool_hash: Sha256::new(),
        })
    }
    pub fn accept(
        &mut self,
        record: &Tainted<SourceRecordV1>,
        spool: &mut dyn Write,
    ) -> Result<MappedSourceRecord, AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut result = Err(invalid());
        record.inspect(|source| {
            result = self.accept_one(source, record, spool);
        });
        result
    }
    fn accept_one(
        &mut self,
        source: &SourceRecordV1,
        tainted: &Tainted<SourceRecordV1>,
        spool: &mut dyn Write,
    ) -> Result<MappedSourceRecord, AppError> {
        self.validate(source, tainted.provenance())?;
        let format =
            SourceFormatIdentityV1::try_new(source.format().id(), source.format().version())
                .map_err(|_| invalid())?;
        if self.formats.len() == 128 && !self.formats.contains(&format) {
            return Err(invalid());
        }
        let (identity, output) = self
            .catalog
            .map(source)
            .map_err(super::MappingError::into_app)?;
        let bytes = commitment::spool_tuple(source);
        self.append_mapping(source, format, identity.as_ref(), &output, &bytes, spool)?;
        Ok(MappedSourceRecord {
            identity,
            output: Tainted::from_external(output, tainted.provenance().clone()),
        })
    }

    fn append_mapping(
        &mut self,
        source: &SourceRecordV1,
        format: SourceFormatIdentityV1,
        identity: Option<&MappingIdentityV1>,
        output: &MappingOutput,
        bytes: &[u8],
        spool: &mut dyn Write,
    ) -> Result<(), AppError> {
        spool.write_all(bytes).map_err(|_| invalid())?;
        self.spool_hash.update(bytes);
        self.records += 1;
        self.previous = Some(source.origin().record());
        self.offset = source
            .origin()
            .offset()
            .map_or(OffsetState::Unavailable, OffsetState::Known);
        self.formats.insert(format);
        self.routes
            .entry(identity.cloned())
            .or_default()
            .add(output);
        Ok(())
    }
    pub fn finish<S: Read + Seek>(
        self,
        spool: &mut S,
        report: &ParseReport,
    ) -> Result<DecodedSourceCommitmentV1, AppError> {
        if self.records == 0
            || self.records != report.accepted as u64
            || report.samples.len() > 3
            || report.samples.iter().any(|s| s.len() > 256)
            || (report.rejected == 0 && !report.samples.is_empty())
        {
            return Err(invalid());
        }
        let hash = commitment::finish(spool, self.records, self.metadata, self.spool_hash)?;
        let source = self.source_hash;
        let routes = self
            .routes
            .into_iter()
            .map(|(mapping, counts)| {
                MappingRouteV1::try_new(source.clone(), mapping, counts.finish()?)
                    .map_err(|_| invalid())
            })
            .collect::<Result<_, _>>()?;
        Ok(DecodedSourceCommitmentV1 {
            source,
            source_size: self.source_size,
            rejected: report.rejected,
            samples: report.samples.clone(),
            reference: self.metadata.source.clone(),
            time_context: super::time::domain_time_context(self.metadata.time_context)?,
            cluster_context: self.metadata.cluster_context.cloned(),
            decoder: self.identity,
            formats: self.formats.into_iter().collect(),
            records: self.records,
            commitment: hash,
            routes,
        })
    }
}

/// Input commitments and execution counters only. Original source fields are not cached.
#[derive(Clone)]
pub struct DecodedSourceCommitmentV1 {
    source: EvidenceHash,
    source_size: u64,
    rejected: u64,
    samples: Vec<String>,
    reference: super::SourceReferenceV1,
    time_context: Option<irmind_domain::SourceTimeContextV1>,
    cluster_context: Option<crate::SourceClusterContext>,
    decoder: SourceDecoderIdentityV1,
    formats: Vec<SourceFormatIdentityV1>,
    records: u64,
    commitment: EvidenceHash,
    routes: Vec<MappingRouteV1>,
}
impl DecodedSourceCommitmentV1 {
    pub fn bind_manifest(
        &self,
        manifest: &irmind_domain::SourceManifestV2,
    ) -> Result<SourceRecordSetV1, AppError> {
        if manifest.cluster_context != self.cluster_context
            || manifest.source.size != self.source_size
            || manifest.rejected_records != self.rejected
            || manifest.rejected_sample != self.samples
            || manifest.source.sha256 != self.source
            || manifest.parser_id != self.decoder.id()
            || manifest.parser_version != self.decoder.version()
        {
            return Err(invalid());
        }
        SourceRecordSetV1::from_manifest_with_time(
            manifest,
            self.reference.clone(),
            self.formats.clone(),
            self.records,
            self.commitment.clone(),
            self.time_context,
        )
        .map_err(|_| invalid())
    }
    pub const fn commitment(&self) -> &EvidenceHash {
        &self.commitment
    }
    pub const fn records(&self) -> u64 {
        self.records
    }
    pub fn routes(&self) -> &[MappingRouteV1] {
        &self.routes
    }
}
fn invalid() -> AppError {
    super::MappingError::InvalidOutput.into_app()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
