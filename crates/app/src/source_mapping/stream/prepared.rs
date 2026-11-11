//! Pure preparation grants no authority; ordered accounting remains in the accumulator.
use super::{
    AppError, EvidenceHash, MappedSourceRecord, MappingCatalog, SourceDecoderIdentityV1,
    SourceFormatIdentityV1, SourceMetadata, SourceRecordAccumulator, SourceRecordV1, Tainted,
    commitment, invalid, validation,
};
use std::io::Write;

#[derive(Clone)]
pub struct SourceRecordPreparer<'a> {
    metadata: SourceMetadata<'a>,
    identity: SourceDecoderIdentityV1,
    catalog: &'a MappingCatalog,
    source_size: u64,
    source_hash: EvidenceHash,
}

/// Private construction binds the original tainted input, mapping and tuple.
pub struct PreparedSourceRecord<'a> {
    catalog: &'a MappingCatalog,
    source: Tainted<SourceRecordV1>,
    mapped: MappedSourceRecord,
    tuple: Vec<u8>,
    format: SourceFormatIdentityV1,
}
impl PreparedSourceRecord<'_> {
    pub const fn mapped(&self) -> &MappedSourceRecord {
        &self.mapped
    }
}
impl<'a> SourceRecordPreparer<'a> {
    pub fn prepare(
        &self,
        record: Tainted<SourceRecordV1>,
    ) -> Result<PreparedSourceRecord<'a>, AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut result = Err(invalid());
        record.inspect(|source| {
            result = (|| {
                validation::validate_binding(
                    &validation::Binding {
                        metadata: self.metadata,
                        identity: &self.identity,
                        hash: &self.source_hash,
                        size: self.source_size,
                    },
                    source,
                    record.provenance(),
                )?;
                let format = SourceFormatIdentityV1::try_new(
                    source.format().id(),
                    source.format().version(),
                )
                .map_err(|_| invalid())?;
                let (identity, output) = self
                    .catalog
                    .map(source)
                    .map_err(super::super::MappingError::into_app)?;
                Ok((identity, output, commitment::spool_tuple(source), format))
            })();
        });
        let (identity, output, tuple, format) = result?;
        let provenance = record.provenance().clone();
        Ok(PreparedSourceRecord {
            catalog: self.catalog,
            source: record,
            mapped: MappedSourceRecord {
                identity,
                output: Tainted::from_external(output, provenance),
            },
            tuple,
            format,
        })
    }
}

impl<'a> SourceRecordAccumulator<'a> {
    /// The returned pure utility borrows only the frozen catalog and source metadata.
    pub fn preparer(&self) -> SourceRecordPreparer<'a> {
        SourceRecordPreparer {
            metadata: self.metadata,
            identity: self.identity.clone(),
            catalog: self.catalog,
            source_size: self.source_size,
            source_hash: self.source_hash.clone(),
        }
    }

    pub fn accept_prepared(
        &mut self,
        prepared: PreparedSourceRecord<'_>,
        spool: &mut dyn Write,
    ) -> Result<MappedSourceRecord, AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if !std::ptr::eq(self.catalog, prepared.catalog) {
            return Err(invalid());
        }
        let mut result = Err(invalid());
        prepared.source.inspect(|source| {
            result = self.validate(source, prepared.source.provenance());
        });
        result?;
        if self.formats.len() == 128 && !self.formats.contains(&prepared.format) {
            return Err(invalid());
        }
        let mut result = Err(invalid());
        prepared.source.inspect(|source| {
            prepared.mapped.output.inspect(|output| {
                result = self.append_mapping(
                    source,
                    prepared.format,
                    prepared.mapped.identity.as_ref(),
                    output,
                    &prepared.tuple,
                    spool,
                );
            });
        });
        result?;
        Ok(prepared.mapped)
    }
}
