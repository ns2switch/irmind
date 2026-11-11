//! Cloud acquisitions use the same direct writer and signed group assembler as local files.
use super::{
    AppError, CancellationToken, CaseId, EvidenceHash, LargeCaseUseCases, SourceManifestV1,
    invalid_manifest,
};
use crate::{ParserSelection, PreparedMappedGroup, PreparedMappedIngest};
use std::collections::BTreeMap;

struct ObjectAcquisition<'a> {
    inner: &'a mut dyn PreparedMappedIngest,
    metadata: PreparedMappedGroup,
}
impl PreparedMappedIngest for ObjectAcquisition<'_> {
    fn metadata(&self) -> &PreparedMappedGroup {
        &self.metadata
    }
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError> {
        self.inner.publish(cancel)
    }
    fn retain_committed(&mut self) {
        self.inner.retain_committed();
    }
}
impl LargeCaseUseCases<'_, '_> {
    pub(crate) fn sign_mapped_object(
        &self,
        id: &CaseId,
        manifest: SourceManifestV1,
        selection: &ParserSelection,
        prepared: &mut dyn PreparedMappedIngest,
        cancel: &CancellationToken,
    ) -> Result<EvidenceHash, AppError> {
        let mut metadata = prepared.metadata().clone();
        let [source] = metadata.sources.as_mut_slice() else {
            return Err(invalid_manifest());
        };
        if source.manifest.sha256 != manifest.sha256
            || source.manifest.size != manifest.size
            || source.manifest.copied != manifest.copied
        {
            return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
        }
        let hash = manifest.sha256.clone();
        let path = manifest.source.clone();
        source.manifest = manifest;
        let index = super::super::read_manifest_index(&self.engine.audit_log.entries(id)?)?;
        let artifacts = index
            .artifacts
            .into_iter()
            .map(|a| (a.path().to_owned(), a))
            .collect::<BTreeMap<_, _>>();
        let selections = BTreeMap::from([(path.clone(), selection.clone())]);
        let mut acquisition = ObjectAcquisition {
            inner: prepared,
            metadata,
        };
        self.commit_direct(
            &super::commit::CommitContext {
                id,
                selections: &selections,
                known_artifacts: &artifacts,
                cancel,
            },
            &[path],
            &mut acquisition,
            &[],
        )?;
        Ok(hash)
    }
}
