//! Versioned object reads use the same private spool and validated decoder pipeline.
use super::{
    AppError, AuthorizedCall, CancellationToken, CaseId, ChildReadResponse, Engine, ReadEffect,
    StartedSubagentPlan, SubagentTaskSpec, Tool, invalid,
};
use crate::subagents::{
    ReservationAction, ReservationPurpose, ReservationTransition, SubagentCheckpointV1,
    SubagentDigest, SubagentRecord, SubagentReservationV1, SubagentResources,
    TaskDispatchAttribution,
};
use crate::{AuditEventKind, LargeCaseUseCases, ObjectEntry};

#[derive(serde::Deserialize)]
struct Listing {
    source: String,
    objects: Vec<ObjectEntry>,
    truncated: bool,
}

impl Engine<'_> {
    pub(in crate::subagents::broker::runner) fn reserve_child_bytes(
        batch: &mut super::super::AgentBatch<'_>,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        call: &crate::subagents::BranchToolCall,
        ordinal: u64,
        checkpoint: &SubagentCheckpointV1,
    ) -> Result<Option<SubagentReservationV1>, AppError> {
        if call.tool != Tool::ObjectRead.as_str() {
            return Ok(None);
        }
        let bytes = call
            .arguments
            .get("max_bytes")
            .and_then(|value| value.parse().ok())
            .ok_or_else(invalid)?;
        let reservation = SubagentReservationV1::prepare(
            &started.plan,
            Some(task.task_id),
            ordinal,
            ReservationAction::ReserveRequest,
            ReservationPurpose::Cloud,
            ReservationTransition {
                amount: SubagentResources {
                    cloud_bytes: bytes,
                    ..SubagentResources::default()
                },
                parent_operation: Some(started.allocation.operation_id),
                cause_sha256: checkpoint.identity().map_err(|_| invalid())?,
                accounting_audit_sha256: None,
            },
        )
        .map_err(|_| invalid())?;
        batch.push(&reservation)?;
        Ok(Some(reservation))
    }
    pub(in crate::subagents::broker::runner) fn child_listed_object(
        &self,
        case: &CaseId,
        task: &SubagentTaskSpec,
        call: &AuthorizedCall,
    ) -> Result<ObjectEntry, AppError> {
        let actor = self.skills.as_ref().ok_or_else(invalid)?.agent.actor();
        let uri = format!(
            "{}://{}/{}",
            call.arg("scheme").ok_or_else(invalid)?,
            call.arg("container").ok_or_else(invalid)?,
            call.arg("key").ok_or_else(invalid)?
        );
        let max: u64 = call
            .arg("max_bytes")
            .and_then(|value| value.parse().ok())
            .ok_or_else(invalid)?;
        for entry in self
            .audit_log
            .entries(case)?
            .iter()
            .rev()
            .filter(|entry| entry.kind == AuditEventKind::ToolResult && entry.actor == actor)
            .take(10_000)
        {
            let Ok(attribution) = serde_json::from_str::<TaskDispatchAttribution>(&entry.payload)
            else {
                continue;
            };
            if attribution.task_id != task.task_id || attribution.tool != Tool::ObjectList.as_str()
            {
                continue;
            }
            let raw = self
                .evidence_store
                .get_evidence(case, entry.evidence.as_deref().ok_or_else(invalid)?)?;
            if raw.len() > 5_000_000 {
                return Err(invalid());
            }
            let listing: Listing = serde_json::from_slice(&raw).map_err(|_| invalid())?;
            if listing.truncated
                || listing.objects.len() > 1000
                || Some(listing.source.as_str()) != call.arg("source")
            {
                continue;
            }
            if let Some(item) = listing.objects.into_iter().find(|item| {
                item.uri == uri
                    && item.size <= max
                    && call
                        .arg("version")
                        .is_none_or(|version| item.version.as_deref() == Some(version))
                    && call.arg("etag").is_none_or(|etag| {
                        item.provider_checksum.as_deref() == Some(&format!("etag:{etag}"))
                    })
            }) {
                return Ok(item);
            }
        }
        Err(AppError::Policy("The task must list the exact object and version itself before reading it; another task's listing is not a capability.".into()))
    }
    pub(super) async fn run_child_object(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ChildReadResponse, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let listed = self.child_listed_object(&case, task, call)?;
        if effect.cloud.is_none() {
            return Err(invalid());
        }
        let signal = cancel.child_token();
        let remaining = task.deadline_at.saturating_sub(self.clock.now()?).min(600);
        let response = tokio::select! { biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            value = tokio::time::timeout(std::time::Duration::from_secs(remaining), self.download_listed_object(&case, call, listed, &signal)) => value.unwrap_or(Err(AppError::Cancelled)),
        };
        signal.cancel();
        let (spool, manifest) = response?;
        self.sign_child_object(started, task, effect, &spool, &manifest, cancel)
    }

    fn sign_child_object(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        spool: &tempfile::NamedTempFile,
        manifest: &irmind_domain::SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<ChildReadResponse, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        let _lock = self.repo.lock_case(&case)?;
        let mut local = self.local_handle();
        local.signer = self.skills.as_ref().ok_or_else(invalid)?.agent.clone();
        let prior = super::super::AgentBatch::new(self, &case, self.verifier.as_ref())?;
        let view = prior
            .journal
            .task_view(started, task.task_id, &self.policy)
            .map_err(|_| invalid())?;
        if cancel.is_cancelled() || self.clock.now()? >= task.deadline_at {
            return Err(AppError::Cancelled);
        }
        let hash = local.publish_child_object(&case, spool, manifest, cancel)?;
        let mut batch = super::super::AgentBatch::new(self, &case, self.verifier.as_ref())?;
        batch.push_evidenced_payload(
            AuditEventKind::ToolResult,
            &effect.attribution(task)?,
            false,
            Some(hash.as_str()),
        )?;
        batch.publish(cancel)?;
        Ok(ChildReadResponse::Remote {
            result: crate::subagents::TaskEvidenceResult::Text(format!(
                "Versioned object verified and indexed; sha256={}",
                hash.as_str()
            )),
            admitted: if view.sources().contains(hash.as_str()) {
                vec![]
            } else {
                vec![SubagentDigest::parse(hash.as_str()).map_err(|_| invalid())?]
            },
        })
    }
    fn publish_child_object(
        &self,
        case: &CaseId,
        spool: &tempfile::NamedTempFile,
        manifest: &irmind_domain::SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<irmind_domain::EvidenceHash, AppError> {
        let root = spool.path().parent().ok_or_else(invalid)?;
        let relative = spool
            .path()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(invalid)?
            .to_owned();
        let catalog = self.parser_catalog.as_ref().ok_or_else(invalid)?;
        let (parser, selection) = crate::dispatch::object_read::select_object_parser(
            catalog,
            root,
            &relative,
            &manifest.source,
        )?;
        let index = crate::large_case::read_manifest_index(&self.audit_log.entries(case)?)?;
        let existing = index
            .sources
            .iter()
            .any(|source| source.sha256 == manifest.sha256);
        let hash = manifest.sha256.clone();
        if !existing {
            let store = self.large_case_store.as_ref().ok_or_else(invalid)?;
            let routed = crate::SourceParser::new(parser.as_ref(), &manifest.source);
            let mut prepared = store
                .prepare_mapped_ingest(
                    crate::MappedIngestRequest {
                        case_id: case,
                        source_root: root,
                        relative_paths: &[relative],
                        copy_original: manifest.copied,
                        parser: &routed,
                        committed_artifacts: crate::mapped_ingest::CommittedArtifacts::Slice(
                            &index.artifacts,
                        ),
                        limits: crate::PartitionLimits::default(),
                    },
                    cancel,
                )?
                .ok_or_else(invalid)?;
            LargeCaseUseCases {
                engine: self,
                store: store.as_ref(),
                parser: &routed,
            }
            .sign_mapped_object(
                case,
                manifest.clone(),
                &selection,
                prepared.as_mut(),
                cancel,
            )?;
        } else if !index.sources.iter().any(|source| {
            source.source == manifest.source
                && source.size == manifest.size
                && source.sha256 == manifest.sha256
                && source.version == manifest.version
                && source.provider_checksum == manifest.provider_checksum
                && source.modified_unix_seconds == manifest.modified_unix_seconds
                && (!manifest.copied || source.copied)
        }) {
            return Err(AppError::EvidenceMismatch(hash.as_str().into()));
        }
        Ok(hash)
    }
}
