use crate::WorkspaceIo;
use irmind_app::{
    AppError, AuditEventKind, CancellationToken, CaseId, Engine, LargeCaseUseCases, LlmPort,
    SealPreview, Severity, SourceCheckMode,
};
use std::path::Path;

pub(crate) mod folder;
pub(crate) mod ingest;

pub(crate) fn is_local_evidence_question(input: &str) -> bool {
    let normalized = input
        .trim()
        .trim_matches(['?', '¿', '.', '!', '¡'])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    matches!(
        normalized.as_str(),
        "/evidence"
            | "what have we ingested"
            | "what has been ingested"
            | "what evidence was ingested"
            | "what evidence is in this case"
            | "what sources are in this case"
            | "show case evidence"
            | "qué hemos ingerido"
            | "que hemos ingerido"
            | "qué se ha ingerido"
            | "que se ha ingerido"
            | "qué evidencia hay en el caso"
            | "qué fuentes hay en el caso"
            | "muestra la evidencia del caso"
    )
}

/// Presentation controller shared by keyboard actions and `TestBackend` tests.
#[derive(Clone, Copy)]
pub(crate) struct CaseWorkflow<'a, 'ports> {
    pub engine: &'a Engine<'ports>,
    pub model: Option<&'a dyn LlmPort>,
    pub io_ops: &'a dyn WorkspaceIo,
}

impl CaseWorkflow<'_, '_> {
    pub(crate) fn create_case(
        &self,
        title: &str,
        severity: Severity,
        scope: &str,
    ) -> Result<CaseId, AppError> {
        Ok(self
            .engine
            .create_case_with_severity(title, severity, scope)?
            .id)
    }

    pub(crate) fn investigate(
        &self,
        id: &CaseId,
        alert: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if is_local_evidence_question(alert) {
            return self.engine.case_evidence_status(id, cancel);
        }
        let model = self.model.ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::NoLLMSelected,
            ))
        })?;
        self.engine
            .investigate_with_cancel(id, alert, model, cancel)
    }

    pub(crate) fn investigate_with_progress(
        &self,
        id: &CaseId,
        alert: &str,
        cancel: &CancellationToken,
        on_text: &(dyn Fn(irmind_app::ModelProgress) + Send + Sync),
    ) -> Result<String, AppError> {
        if is_local_evidence_question(alert) {
            return self.engine.case_evidence_status(id, cancel);
        }
        let model = self
            .model
            .ok_or(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::NoLLMSelected,
            )))?;
        self.engine
            .investigate_with_progress(id, alert, model, cancel, on_text)
    }

    pub(crate) fn approve(
        &self,
        id: &CaseId,
        request_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.engine.approve_with_cancel(id, request_id, cancel)
    }

    pub(crate) fn verify(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if self.requires_source_root(id)? {
            return Err(AppError::Policy(self.with_orphan_cleanup_notice(
                id,
                "select the original source root with /verify <path>".into(),
            )));
        }
        self.engine.verify_cancelable(id, cancel)
    }

    pub(crate) fn verify_summary(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if self.requires_source_root(id)? {
            return self
                .verify_with_query_notices(
                    id,
                    cancel,
                    "select the original source root with /verify <path>",
                )
                .and_then(|message| Err(AppError::Policy(message)));
        }
        let notices = self
            .engine
            .verify_with_mapping_and_query_notices(id, cancel)?;
        Ok(self.with_verification_notices(
            id,
            format!("Verified {} audit entries", notices.count),
            &notices,
        ))
    }

    fn verify_with_query_notices(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
        message: &str,
    ) -> Result<String, AppError> {
        let notices = self
            .engine
            .verify_with_mapping_and_query_notices(id, cancel)?;
        Ok(self.with_verification_notices(id, message.into(), &notices))
    }

    fn with_verification_notices(
        &self,
        id: &CaseId,
        mut message: String,
        notices: &irmind_app::VerifiedCaseNotices,
    ) -> String {
        use std::fmt::Write as _;
        let folder = &notices.folder_outcomes;
        if folder.skipped + folder.failed + folder.matched + folder.mismatched != 0 {
            let _ = write!(message, "\nFolder outcomes: {}", folder.summary());
            if folder.mismatched != 0 {
                message.push_str("\nWARNING: SHA-256 mismatch. Inspect the affected originals.");
            }
            for notice in folder.limitations.iter().take(50) {
                let (path, reason) = notice.description();
                let _ = write!(
                    message,
                    "\n{} · {reason} · {} · audit #{}",
                    crate::case::escape_display(path),
                    notice.fingerprint_display(),
                    notice.sequence
                );
            }
        }
        if notices.provisional_mappings != 0 {
            let _ = write!(
                message,
                "\nNative mappings: {} provisional development identities. Rebuild with the creating build.",
                notices.provisional_mappings
            );
        }
        if notices.release_mappings != 0 {
            let _ = write!(
                message,
                "\nNative mappings: {} release-profile identities",
                notices.release_mappings
            );
        }
        for run in &notices.sigma_runs {
            let counts = &run.coverage;
            let _ = write!(
                message,
                "\nSigma {} · source-class plan · {} rules with all, {} with some, {} with no eligible classes · {} eligible and {} skipped pairs",
                run.receipt.as_str(),
                counts.all_rules,
                counts.some_rules,
                counts.no_rules,
                counts.eligible_pairs,
                counts.skipped_pairs,
            );
            for (class, missing, incompatible) in &run.skipped_classes {
                let _ = write!(
                    message,
                    "\n  {class} · {missing} missing bindings, {incompatible} incompatible types"
                );
            }
            if counts.skipped_pairs != 0 || counts.no_rules != 0 {
                message.push_str(
                    "\nActivity covered by skipped rules or source classes remains undetermined.",
                );
            }
            if run.unavailable_rows != 0 {
                let _ = write!(
                    message,
                    "\n  {} rows with unavailable exact fields · {} rules with indeterminate rows. Unexpected values may indicate source manipulation.",
                    run.unavailable_rows, run.indeterminate_rules
                );
            }
            if run.stopped_early {
                message.push_str(
                    "\nThe Sigma scan stopped early. The source-class counts describe the plan.",
                );
            }
        }
        for notice in &notices.query_limits {
            let _ = write!(
                message,
                "\n{} — {}",
                notice.capture_sha256(),
                notice.message()
            );
        }
        self.with_orphan_cleanup_notice(id, message)
    }

    pub(crate) fn verify_with_source_root(
        &self,
        id: &CaseId,
        root: &Path,
        mode: SourceCheckMode,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or(AppError::Policy("large-case storage is unavailable".into()))?;
        let large = LargeCaseUseCases {
            engine: self.engine,
            store,
            parser,
        };
        let report = large.verify_sources(id, root, mode, cancel)?;
        if !report.missing_or_changed.is_empty() {
            return Err(AppError::Policy(self.with_orphan_cleanup_notice(
                id,
                format!(
                    "{} original sources are missing or changed",
                    report.missing_or_changed.len()
                ),
            )));
        }
        self.verify_with_query_notices(
            id,
            cancel,
            &format!(
                "Verified {} of {} original sources; {} were not sampled",
                report.checked, report.total, report.unchecked
            ),
        )
    }

    pub(crate) fn with_orphan_cleanup_notice(&self, id: &CaseId, mut message: String) -> String {
        if let Some(notice) = self.engine.orphan_cleanup_notice(id) {
            message.push('\n');
            message.push_str("Warning: ");
            message.push_str(&notice);
        }
        message
    }

    fn requires_source_root(&self, id: &CaseId) -> Result<bool, AppError> {
        let entries = self.engine.audit_log.entries(id)?;
        let mut captures = std::collections::BTreeSet::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceQueryResultV1)
        {
            let receipt =
                irmind_app::source_queries::SourceQueryResultV1::decode(entry.payload.as_bytes())?;
            captures.insert(receipt.capture_identity().0.to_owned());
        }
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        {
            let manifest = irmind_app::SourceManifestV2::decode(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            if !captures.contains(manifest.source.sha256.as_str()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn verify_parquet_rebuild(
        &self,
        id: &CaseId,
        root: &Path,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let (store, parser) = self
            .io_ops
            .large_case_store()
            .zip(self.io_ops.streaming_parser())
            .ok_or(AppError::Policy("large-case storage is unavailable".into()))?;
        LargeCaseUseCases {
            engine: self.engine,
            store,
            parser,
        }
        .verify_parquet_rebuild(id, root, cancel)
    }

    pub(crate) fn has_source_manifests(&self, id: &CaseId) -> Result<bool, AppError> {
        Ok(self
            .engine
            .audit_log
            .entries(id)?
            .iter()
            .any(|entry| entry.kind == AuditEventKind::SourceManifestV2))
    }

    pub(crate) fn verify_graph(
        &self,
        id: &CaseId,
        _cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        if self.has_source_manifests(id)? {
            return Err(AppError::Policy(
                "use /verify-graph <source-root> to rebuild and compare Parquet".into(),
            ));
        }
        Err(AppError::Policy(
            "no signed Parquet artifacts in this case".into(),
        ))
    }

    pub(crate) fn seal(&self, id: &CaseId) -> Result<(), AppError> {
        self.engine.seal(id)
    }

    pub(crate) fn prepare_seal(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<SealPreview, AppError> {
        self.engine.prepare_seal_cancelable(id, cancel)
    }

    pub(crate) fn seal_prepared(&self, preview: &SealPreview) -> Result<(), AppError> {
        self.engine.seal_prepared(preview)
    }

    pub(crate) fn export(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.export_with_options(id, path, None, false, cancel)
    }

    pub(crate) fn export_with_options(
        &self,
        id: &CaseId,
        path: &Path,
        source_root: Option<&Path>,
        include_originals: bool,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if self.has_source_manifests(id)? {
            let exporter = self
                .io_ops
                .large_case_exporter()
                .ok_or(AppError::Policy("large-case export is unavailable".into()))?;
            irmind_app::export_case_with_originals(
                self.engine,
                exporter,
                id,
                path,
                source_root,
                include_originals,
                cancel,
            )
        } else {
            if include_originals {
                return Err(AppError::Policy(
                    "this case already uses the copied-evidence export format".into(),
                ));
            }
            irmind_app::export_case(self.engine, self.io_ops.case_exporter(), id, path, cancel)
        }
    }
}
