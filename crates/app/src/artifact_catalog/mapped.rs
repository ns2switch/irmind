use super::{AppError, ArtifactCatalogBuilder, SignedEntry};
use irmind_domain::{
    AuditEventKind as K, MappingProfileRecordV1, MappingRunV1, ParquetArtifactV3, ParquetLayoutV1,
    SourceRecordSetV1,
};

impl ArtifactCatalogBuilder {
    pub(super) fn accept_mapped(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        let bad = || AppError::InvalidChain(entry.seq);
        if entry.evidence.is_some() {
            return Err(bad());
        }
        let result = match entry.kind {
            K::SourceRecordSetV1 => self.mapped.input(
                SourceRecordSetV1::decode(&entry.payload)
                    .map_err(|e| decode_error(&e, entry.seq))?,
            ),
            K::MappingProfileV1 => {
                match MappingProfileRecordV1::decode(&entry.payload)
                    .map_err(|e| decode_error(&e, entry.seq))?
                {
                    MappingProfileRecordV1::Snapshot(snapshot) => {
                        // Metadata interpretation is bounded and never executes a native mapper.
                        crate::source_mapping::MappingManifest::from_snapshot(&snapshot)
                            .map_err(|_| bad())?;
                        self.mapped.snapshot(snapshot)
                    }
                    MappingProfileRecordV1::Profile(profile) => self.mapped.profile(profile),
                }
            }
            K::ParquetArtifactV3 => {
                let artifact = ParquetArtifactV3::decode(&entry.payload)
                    .map_err(|e| decode_error(&e, entry.seq))?;
                let path = artifact.core().path.clone();
                self.mapped.artifact(artifact).map_err(|_| bad())?;
                self.artifact_order.push(path);
                Ok(())
            }
            K::MappingRunV1 => self.mapped.mapping_run(
                &MappingRunV1::decode(&entry.payload).map_err(|e| decode_error(&e, entry.seq))?,
            ),
            K::ParquetLayoutV1 => self.mapped.layout(
                &ParquetLayoutV1::decode(&entry.payload)
                    .map_err(|e| decode_error(&e, entry.seq))?,
            ),
            _ => return Err(bad()),
        };
        result.map_err(|_| bad())
    }
}

fn decode_error(error: &irmind_domain::DomainError, seq: u64) -> AppError {
    if error == &irmind_domain::DomainError::UnsupportedContract {
        AppError::Fixed(crate::FixedAppError::RetiredCaseFormat)
    } else {
        AppError::InvalidChain(seq)
    }
}
