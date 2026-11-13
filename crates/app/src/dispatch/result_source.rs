//! Provider response bytes stay signed evidence; identified decoding/mapping adds queryable events.
use crate::{
    AppError, AuthorizedCall, CancellationToken, CaseId, Engine, LargeCaseUseCases,
    ParserSelection, SourceDecoder, SourceManifestV1, SourceParser, Tool,
    source_mapping::{SourceDecoderSelection, SourceInput, SourceMetadata},
};
use irmind_domain::{
    EvidenceHash, ParserSelectionMode, SiemAggregation, SiemQuery, SourceReferenceV1,
};
use std::{io::Write as _, sync::Arc};
impl Engine<'_> {
    pub(super) fn index_remote_result(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if !matches!(call.tool(), Tool::SiemSearch | Tool::SiemGetAlert) {
            return Ok(());
        }
        if call.tool() == &Tool::SiemSearch
            && SiemQuery::parse(call.proposal_args())
                .is_some_and(|q| q.aggregation() != SiemAggregation::Events)
        {
            return Ok(());
        }
        let Some(decoder) = call
            .arg("source")
            .and_then(|source| self.result_decoders.get(source))
        else {
            return Ok(());
        };
        let store = self.large_case_store.as_ref().ok_or(AppError::RemoteTool)?;
        let hash = EvidenceHash::from_bytes(crate::sha256(raw));
        let logical = format!("siem/{}/{}.json", decoder.identity().name, hash.as_str());
        let index = crate::large_case::read_manifest_index(&self.audit_log.entries(id)?)?;
        if index
            .sources
            .iter()
            .any(|source| source.source == logical && source.sha256 == hash)
        {
            return Ok(());
        }
        if !has_events(decoder.as_ref(), raw, &logical, cancel)? {
            return Ok(());
        }
        let mut spool = store.create_object_spool(id, raw.len() as u64)?;
        spool.write_all(raw).map_err(|_| {
            AppError::Storage("cannot write remote result inside the case spool".into())
        })?;
        spool
            .as_file()
            .sync_all()
            .map_err(|_| AppError::Storage("cannot sync remote result spool".into()))?;
        let root = spool.path().parent().ok_or(AppError::RemoteTool)?;
        let path = spool
            .path()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(AppError::RemoteTool)?
            .to_owned();
        let selection = SourceDecoderSelection::new(Arc::clone(decoder));
        let routed = SourceParser::new(&selection, &logical);
        let mut prepared = store
            .prepare_mapped_ingest(
                crate::MappedIngestRequest {
                    case_id: id,
                    source_root: root,
                    relative_paths: &[path],
                    copy_original: true,
                    parser: &routed,
                    committed_artifacts: crate::mapped_ingest::CommittedArtifacts::Slice(
                        &index.artifacts,
                    ),
                    limits: crate::PartitionLimits::default(),
                },
                cancel,
            )?
            .ok_or(AppError::RemoteTool)?;
        let parser = parser_selection(decoder.as_ref(), raw);
        LargeCaseUseCases {
            engine: self,
            store: store.as_ref(),
            parser: &routed,
        }
        .sign_mapped_object(
            id,
            manifest(&logical, raw, hash),
            &parser,
            prepared.as_mut(),
            cancel,
        )?;
        Ok(())
    }
}
fn has_events(
    decoder: &dyn SourceDecoder,
    raw: &[u8],
    logical: &str,
    cancel: &CancellationToken,
) -> Result<bool, AppError> {
    let source = SourceReferenceV1::file(logical).map_err(|_| AppError::RemoteTool)?;
    let report = decoder.decode_reader(
        SourceInput {
            reader: &mut &raw[..],
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: crate::sha256(raw),
                time_context: None,
                cluster_context: None,
                cancel,
            },
        },
        &mut |_| Ok(()),
    )?;
    if report.accepted == 0 && report.rejected != 0 {
        return Err(AppError::Fixed(crate::FixedAppError::SourceFormat));
    }
    Ok(report.accepted != 0)
}

fn parser_selection(decoder: &dyn SourceDecoder, raw: &[u8]) -> ParserSelection {
    ParserSelection {
        parser_id: decoder.identity().name.into(),
        parser_version: decoder.identity().version.into(),
        confidence: 100,
        mode: ParserSelectionMode::Automatic,
        timestamp_context: None,
        cluster_context: None,
        format_sample_sha256: crate::sha256(&raw[..raw.len().min(65_536)]),
    }
}

fn manifest(logical: &str, raw: &[u8], hash: EvidenceHash) -> SourceManifestV1 {
    SourceManifestV1 {
        source: logical.into(),
        size: raw.len() as u64,
        modified_unix_seconds: None,
        version: None,
        provider_checksum: None,
        sha256: hash,
        copied: true,
    }
}
