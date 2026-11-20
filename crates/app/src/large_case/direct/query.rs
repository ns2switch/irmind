use super::commit::{CommitContext, publish_mapped_files};
use crate::source_queries::{
    SourceQueryError, SourceQueryJournal, SourceQueryResultV1, SourceQuerySettlementV1,
    verify_query_capture,
};
use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine, LargeCaseUseCases,
    MappedIngestRequest, PartitionLimits, SourceParser, StreamingEventParser,
    mapped_ingest::CommittedArtifacts,
};
use irmind_domain::EvidenceHash;
use std::collections::BTreeMap;

impl Engine<'_> {
    /// Publish a capture after the adapter's terminal observation is durable.
    /// The derived source and retention settlement share one atomic append.
    pub fn publish_source_query_capture(
        &self,
        case: &CaseId,
        result_payload: &str,
        settlement_payload: &str,
        spool: &tempfile::NamedTempFile,
        decoder: &dyn StreamingEventParser,
        cancel: &CancellationToken,
    ) -> Result<EvidenceHash, AppError> {
        self.require_attended_analyst("publish source query capture")?;
        let _lock = self.repo.lock_case(case)?;
        self.verify_unlocked_cancelable(case, cancel)?;
        if self.repo.get_case(case)?.sealed {
            return Err(AppError::Sealed);
        }
        let result = SourceQueryResultV1::decode(result_payload.as_bytes())?;
        SourceQuerySettlementV1::decode(settlement_payload.as_bytes())?;
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let entries = self.audit_log.entries(case)?;
        let agent = self
            .skills
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?
            .agent
            .clone();
        let mut query_signer = self.local_handle();
        query_signer.signer = agent;
        let first = query_signer.signed_entry_after(
            case,
            entries.last(),
            AuditOrigin::Agent,
            AuditEventKind::SourceQueryResultV1,
            result_payload,
            None,
        )?;
        // Authenticate the expected settlement and reserved bytes before
        // preparing temporary Parquet files.
        let terminal = query_signer.signed_entry_after(
            case,
            Some(&first),
            AuditOrigin::Agent,
            AuditEventKind::SourceQuerySettlementV1,
            settlement_payload,
            None,
        )?;
        let mut candidate = entries.clone();
        candidate.extend([first.clone(), terminal]);
        SourceQueryJournal::replay(&candidate, &operations, self.verifier.as_ref(), cancel)?;
        self.publish_query_group(
            &QueryPublication {
                case,
                result: &result,
                settlement: settlement_payload,
                spool,
                decoder,
                cancel,
                query_signer: &query_signer,
            },
            entries,
            first,
        )
    }

    fn publish_query_group(
        &self,
        publication: &QueryPublication<'_>,
        mut entries: Vec<crate::SignedEntry>,
        result_entry: crate::SignedEntry,
    ) -> Result<EvidenceHash, AppError> {
        let QueryPublication {
            case,
            result,
            settlement,
            decoder,
            cancel,
            query_signer,
            ..
        } = *publication;
        let store = self
            .large_case_store
            .as_deref()
            .ok_or(SourceQueryError::Unavailable)?;
        let index = crate::large_case::read_manifest_index(&entries)?;
        let artifacts = index
            .artifacts
            .into_iter()
            .map(|a| (a.path().to_owned(), a))
            .collect::<BTreeMap<_, _>>();
        let logical = result.capture_path();
        let parser = SourceParser::new(decoder, &logical);
        let mut prepared = publication.prepare(store, &parser, &artifacts)?;
        let (sources, events, outputs) = LargeCaseUseCases {
            engine: self,
            store,
            parser: &parser,
        }
        .direct_events(
            &CommitContext {
                id: case,
                selections: &BTreeMap::new(),
                known_artifacts: &artifacts,
                cancel,
            },
            std::slice::from_ref(&logical),
            prepared.metadata(),
            &[],
        )?;
        let [source] = sources.as_slice() else {
            return Err(SourceQueryError::Invalid.into());
        };
        let hash = &source.source.sha256;
        let start = entries.len();
        entries.push(result_entry);
        for (origin, kind, payload) in events {
            let entry =
                self.signed_entry_after(case, entries.last(), origin, kind, &payload, None)?;
            entries.push(entry);
        }
        entries.push(query_signer.signed_entry_after(
            case,
            entries.last(),
            AuditOrigin::Agent,
            AuditEventKind::SourceQuerySettlementV1,
            settlement,
            None,
        )?);
        self.verify_source_query_journal(&entries, cancel, false)?;
        publish_mapped_files(store, case, prepared.as_mut(), &outputs, cancel)?;
        let capture = store.open_source_query_capture(case, hash, source.source.size, cancel)?;
        result.verify_capture(&verify_query_capture(capture, cancel)?)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.audit_log.append_batch(&entries[start..])?;
        prepared.retain_committed();
        Ok(hash.clone())
    }
}

struct QueryPublication<'a> {
    case: &'a CaseId,
    result: &'a SourceQueryResultV1,
    settlement: &'a str,
    spool: &'a tempfile::NamedTempFile,
    decoder: &'a dyn StreamingEventParser,
    cancel: &'a CancellationToken,
    query_signer: &'a Engine<'static>,
}

impl QueryPublication<'_> {
    fn prepare(
        &self,
        store: &dyn crate::LargeCaseStore,
        parser: &dyn StreamingEventParser,
        artifacts: &BTreeMap<String, irmind_domain::ParquetArtifact>,
    ) -> Result<Box<dyn crate::PreparedMappedIngest>, AppError> {
        let path = self.spool.path();
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SourceQueryError::Invalid)?;
        store.prepare_source_query_capture(
            &MappedIngestRequest {
                case_id: self.case,
                source_root: path.parent().ok_or(SourceQueryError::Invalid)?,
                relative_paths: &[filename.into()],
                copy_original: true,
                parser,
                committed_artifacts: CommittedArtifacts::Indexed(artifacts),
                limits: PartitionLimits::default(),
            },
            self.result,
            self.cancel,
        )
    }
}
