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
    pub(crate) fn index_remote_result(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        self.index_identified_result(id, call.tool(), call.proposal_args(), raw, cancel)
            .map(|_| ())
    }
    pub(crate) fn index_child_remote_result(
        &self,
        id: &CaseId,
        call: &crate::subagents::BranchToolCall,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Option<crate::subagents::SubagentDigest>, AppError> {
        let tool = Tool::parse(&call.tool).map_err(|_| AppError::RemoteTool)?;
        let hash = if matches!(tool, Tool::SiemSearch | Tool::SiemGetAlert) {
            self.index_identified_result(id, &tool, &call.arguments, raw, cancel)?
        } else if matches!(
            tool,
            Tool::CloudAuditEvents
                | Tool::CloudIdentity
                | Tool::EdrHostInfo
                | Tool::EdrProcessTree
                | Tool::EdrDetections
        ) {
            let Some(catalog) = &self.parser_catalog else {
                return Ok(None);
            };
            let logical = format!("remote/{}.json", crate::hex(&crate::sha256(raw)));
            let selected = match catalog.select_source(crate::modules::ParserSelectionRequest {
                source: &logical,
                sample: &raw[..raw.len().min(65536)],
                parser_override: None,
                forced: false,
                time_context: None,
                cluster_context: None,
            }) {
                Ok(selected) => selected,
                Err(
                    AppError::ParserSelection { .. }
                    | AppError::ParserTimeContextRequired { .. }
                    | AppError::ParserClusterContextRequired { .. },
                ) => return Ok(None),
                Err(error) => return Err(error),
            };
            self.index_decoded_result(
                id,
                &logical,
                selected.parser.as_ref(),
                &selected.selection,
                raw,
                cancel,
            )?
        } else {
            None
        };
        hash.map(|hash| {
            crate::subagents::SubagentDigest::parse(hash.as_str()).map_err(|_| AppError::RemoteTool)
        })
        .transpose()
    }

    fn index_identified_result(
        &self,
        id: &CaseId,
        tool: &Tool,
        args: &std::collections::BTreeMap<String, String>,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Option<EvidenceHash>, AppError> {
        if !matches!(tool, Tool::SiemSearch | Tool::SiemGetAlert) {
            return Ok(None);
        }
        if tool == &Tool::SiemSearch
            && SiemQuery::parse(args).is_some_and(|q| q.aggregation() != SiemAggregation::Events)
        {
            return Ok(None);
        }
        let Some(decoder) = args
            .get("source")
            .and_then(|source| self.result_decoders.get(source))
        else {
            return Ok(None);
        };
        let hash = EvidenceHash::from_bytes(crate::sha256(raw));
        let logical = format!("siem/{}/{}.json", decoder.identity().name, hash.as_str());
        if !has_events(decoder.as_ref(), raw, &logical, cancel)? {
            return Ok(None);
        }
        let selection = SourceDecoderSelection::new(Arc::clone(decoder));
        self.index_decoded_result(
            id,
            &logical,
            &selection,
            &parser_selection(decoder.as_ref(), raw),
            raw,
            cancel,
        )
    }

    fn index_decoded_result(
        &self,
        id: &CaseId,
        logical: &str,
        selection: &dyn crate::StreamingEventParser,
        parser: &ParserSelection,
        raw: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Option<EvidenceHash>, AppError> {
        let store = self.large_case_store.as_ref().ok_or(AppError::RemoteTool)?;
        let hash = EvidenceHash::from_bytes(crate::sha256(raw));
        let index = crate::large_case::read_manifest_index(&self.audit_log.entries(id)?)?;
        if index.sources.iter().any(|source| source.sha256 == hash) {
            return Ok(Some(hash));
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
        let routed = SourceParser::new(selection, logical);
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
        let [source] = prepared.metadata().sources.as_slice() else {
            return Err(AppError::RemoteTool);
        };
        if source.report.accepted == 0 {
            return Ok(None);
        }
        LargeCaseUseCases {
            engine: self,
            store: store.as_ref(),
            parser: &routed,
        }
        .sign_mapped_object(
            id,
            manifest(logical, raw, hash.clone()),
            parser,
            prepared.as_mut(),
            cancel,
        )?;
        Ok(Some(hash))
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
