use crate::*;

mod audit;
mod cases;
mod investigation;
mod model_request;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseCreatedEvent {
    version: u8,
    title: String,
    #[serde(default)]
    severity: Option<String>,
    scope: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeChangedEvent {
    version: u8,
    previous_scope: String,
    new_scope: String,
}

pub fn verify_case_metadata(
    title: &str,
    severity: Severity,
    scope: &str,
    entries: &[SignedEntry],
) -> Result<(), AppError> {
    let first = entries.first().ok_or(AppError::InvalidChain(0))?;
    if first.kind != irmind_domain::AuditEventKind::CaseCreated || first.actor != Actor::Analyst {
        return Err(AppError::InvalidChain(first.seq));
    }
    if !first.payload.starts_with('{') {
        return Err(AppError::Fixed(crate::FixedAppError::RetiredCaseFormat));
    }
    let created: CaseCreatedEvent =
        serde_json::from_str(&first.payload).map_err(|_| AppError::InvalidChain(first.seq))?;
    if created.version != 3 {
        return Err(AppError::Fixed(crate::FixedAppError::RetiredCaseFormat));
    }
    if created.title != title || created.severity.as_deref() != Some(severity.as_str()) {
        return Err(AppError::InvalidChain(first.seq));
    }
    let mut current = created.scope;
    CaseScope::parse(&current).map_err(|_| AppError::InvalidChain(first.seq))?;
    for entry in entries.iter().skip(1) {
        if entry.kind != irmind_domain::AuditEventKind::CaseScopeChanged {
            crate::source_scopes::verify_entry(entry, &current)?;
            continue;
        }
        let change: ScopeChangedEvent =
            serde_json::from_str(&entry.payload).map_err(|_| AppError::InvalidChain(entry.seq))?;
        if entry.actor != Actor::Analyst
            || change.version != 1
            || change.previous_scope != current
            || CaseScope::parse(&change.new_scope).is_err()
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        current = change.new_scope;
    }
    if current != scope {
        return Err(AppError::InvalidChain(
            entries.last().map_or(0, |entry| entry.seq),
        ));
    }
    Ok(())
}

type ObjectProgressMap = Arc<
    std::sync::Mutex<std::collections::HashMap<CaseId, (u64, Arc<std::sync::atomic::AtomicU64>)>>,
>;

pub struct Engine<'a> {
    pub repo: Arc<dyn Repository>,
    pub evidence_store: Arc<dyn EvidenceStore>,
    pub graph: Arc<dyn EvidenceGraph>,
    pub audit_log: Arc<dyn AuditLog>,
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
    pub guard: Arc<dyn ContentGuard>,
    pub clock: Arc<dyn Clock>,
    pub mode: ExecutionMode,
    pub policy: PolicyRules,
    pub(crate) policy_fingerprint: String,
    pub(crate) module_fingerprint: String,
    pub(crate) source_scopes: BTreeMap<String, crate::SiemSourceScope>,
    pub(crate) threat_intel: Option<&'a dyn ThreatIntelPort>,
    pub(crate) siems: Vec<&'a dyn SiemPort>,
    pub(crate) result_decoders: BTreeMap<String, Arc<dyn crate::SourceDecoder>>,
    pub(crate) cloud_audits: Vec<&'a dyn CloudAuditPort>,
    pub(crate) edrs: Vec<&'a dyn EdrPort>,
    pub(crate) internal_intel: Vec<&'a dyn InternalIntelPort>,
    pub(crate) object_sources: Vec<&'a dyn ObjectSource>,
    pub(crate) large_case_store: Option<Arc<dyn LargeCaseStore>>,
    pub(crate) streaming_parser: Option<Arc<dyn StreamingEventParser>>,
    pub(crate) parser_catalog: Option<crate::modules::ParserCatalog>,
    pub(crate) pricing: Option<ModelPricing>,
    pub(crate) verified_cases: Arc<
        std::sync::Mutex<
            std::collections::HashMap<CaseId, crate::custody::incremental::VerifiedCheckpoint>,
        >,
    >,
    pub(crate) object_progress: ObjectProgressMap,
    pub(crate) skills: Option<Arc<crate::SkillServices>>,
}

pub struct EnginePorts {
    pub repo: Arc<dyn Repository>,
    pub evidence_store: Arc<dyn EvidenceStore>,
    pub graph: Arc<dyn EvidenceGraph>,
    pub audit_log: Arc<dyn AuditLog>,
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
    pub guard: Arc<dyn ContentGuard>,
}

pub struct CryptoPorts {
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
}

impl CryptoPorts {
    pub fn new(signer: Arc<dyn Signer>, verifier: Arc<dyn Verifier>) -> Self {
        Self { signer, verifier }
    }
}

impl EnginePorts {
    pub fn new(
        repo: Arc<dyn Repository>,
        evidence_store: Arc<dyn EvidenceStore>,
        graph: Arc<dyn EvidenceGraph>,
        audit_log: Arc<dyn AuditLog>,
        crypto: CryptoPorts,
        guard: Arc<dyn ContentGuard>,
    ) -> Self {
        Self {
            repo,
            evidence_store,
            graph,
            audit_log,
            signer: crypto.signer,
            verifier: crypto.verifier,
            guard,
        }
    }
}

impl<'a> Engine<'a> {
    pub(crate) fn local_handle(&self) -> Engine<'static> {
        Engine {
            repo: Arc::clone(&self.repo),
            evidence_store: Arc::clone(&self.evidence_store),
            graph: Arc::clone(&self.graph),
            audit_log: Arc::clone(&self.audit_log),
            signer: Arc::clone(&self.signer),
            verifier: Arc::clone(&self.verifier),
            guard: Arc::clone(&self.guard),
            clock: Arc::clone(&self.clock),
            mode: self.mode,
            policy: self.policy.clone(),
            policy_fingerprint: self.policy_fingerprint.clone(),
            module_fingerprint: self.module_fingerprint.clone(),
            source_scopes: self.source_scopes.clone(),
            threat_intel: None,
            siems: Vec::new(),
            result_decoders: self.result_decoders.clone(),
            cloud_audits: Vec::new(),
            edrs: Vec::new(),
            internal_intel: Vec::new(),
            object_sources: Vec::new(),
            large_case_store: self.large_case_store.clone(),
            streaming_parser: self.streaming_parser.clone(),
            parser_catalog: self.parser_catalog.clone(),
            pricing: self.pricing,
            verified_cases: Arc::clone(&self.verified_cases),
            object_progress: Arc::clone(&self.object_progress),
            skills: self.skills.clone(),
        }
    }

    pub(crate) async fn blocking_local<T, F>(&self, task: F) -> Result<T, AppError>
    where
        T: Send + 'static,
        F: FnOnce(Engine<'static>) -> Result<T, AppError> + Send + 'static,
    {
        let local = self.local_handle();
        tokio::task::spawn_blocking(move || task(local))
            .await
            .map_err(|error| AppError::Storage(format!("local task failed: {error}")))?
    }

    pub(crate) async fn audit_local(
        &self,
        id: &CaseId,
        origin: AuditOrigin,
        kind: AuditEventKind,
        payload: &str,
        evidence: Option<&str>,
    ) -> Result<(), AppError> {
        let id = id.clone();
        let payload = payload.to_owned();
        let evidence = evidence.map(str::to_owned);
        self.blocking_local(move |local| {
            local.audit(&id, origin, kind, &payload, evidence.as_deref())
        })
        .await
    }

    pub(crate) async fn screen_and_audit_local(
        &self,
        id: &CaseId,
        text: &str,
        source: &str,
        evidence: Option<&str>,
    ) -> Result<Screened, AppError> {
        let id = id.clone();
        let text = text.to_owned();
        let source = source.to_owned();
        let evidence = evidence.map(str::to_owned);
        self.blocking_local(move |local| {
            local.screen_and_audit(&id, &text, &source, evidence.as_deref())
        })
        .await
    }

    #[must_use]
    pub fn with_threat_intel(mut self, port: &'a dyn ThreatIntelPort) -> Self {
        self.threat_intel = Some(port);
        self
    }

    pub fn with_siem(mut self, port: &'a dyn SiemPort) -> Result<Self, AppError> {
        if self
            .siems
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateSIEMSource,
            ));
        }
        self.source_scopes.insert(
            port.source_id().into(),
            crate::SiemSourceScope::event_account(port.source_id(), "siem")?,
        );
        self.siems.push(port);
        Ok(self)
    }

    pub fn with_cloud_audit(mut self, port: &'a dyn CloudAuditPort) -> Result<Self, AppError> {
        if self
            .cloud_audits
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateCloudAuditSource,
            ));
        }
        self.cloud_audits.push(port);
        Ok(self)
    }

    pub fn with_edr(mut self, port: &'a dyn EdrPort) -> Result<Self, AppError> {
        if self
            .edrs
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateEDRSource,
            ));
        }
        self.edrs.push(port);
        Ok(self)
    }

    pub fn with_internal_intel(
        mut self,
        port: &'a dyn InternalIntelPort,
    ) -> Result<Self, AppError> {
        if self
            .internal_intel
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateInternalIntelligenceSource,
            ));
        }
        self.internal_intel.push(port);
        Ok(self)
    }

    pub fn with_object_source(mut self, port: &'a dyn ObjectSource) -> Result<Self, AppError> {
        if self
            .object_sources
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Policy("duplicate object source".into()));
        }
        self.object_sources.push(port);
        Ok(self)
    }

    #[must_use]
    pub fn with_large_case_pipeline(
        mut self,
        store: Arc<dyn LargeCaseStore>,
        parser: Arc<dyn StreamingEventParser>,
    ) -> Self {
        self.large_case_store = Some(store);
        self.streaming_parser = Some(parser);
        self
    }

    #[must_use]
    pub fn with_parser_catalog(mut self, catalog: crate::modules::ParserCatalog) -> Self {
        self.parser_catalog = Some(catalog);
        self
    }
}

impl Engine<'_> {
    pub(crate) fn available_tools(&self) -> Vec<tool_catalog::ToolSpec> {
        let mut tools: Vec<_> = tool_catalog::catalog()
            .into_iter()
            .filter(|spec| match spec.name {
                "siem_search" | "siem_get_alert" => !self.siems.is_empty(),
                "cloud_audit_events" | "cloud_identity" => !self.cloud_audits.is_empty(),
                "edr_host_info" => self
                    .edrs
                    .iter()
                    .any(|port| port.supports(&Tool::EdrHostInfo)),
                "edr_process_tree" => self
                    .edrs
                    .iter()
                    .any(|port| port.supports(&Tool::EdrProcessTree)),
                "edr_detections" => self
                    .edrs
                    .iter()
                    .any(|port| port.supports(&Tool::EdrDetections)),
                "ti_lookup_internal" => !self.internal_intel.is_empty(),
                "ti_lookup_external" => self.threat_intel.is_some(),
                "skill_read" => self.skills.is_some(),
                "object_list" => !self.object_sources.is_empty(),
                "object_read" => !self.object_sources.is_empty() && self.large_case_store.is_some(),
                _ => true,
            })
            .collect();
        if let Some(spec) = tools
            .iter_mut()
            .find(|spec| spec.name == "edr_process_tree")
        {
            let hints: Vec<_> = self
                .edrs
                .iter()
                .filter_map(|port| {
                    port.process_tree_hint()
                        .map(|hint| format!("{}: {hint}", port.source_id()))
                })
                .collect();
            if !hints.is_empty() {
                spec.parameters["properties"]["process_id"]["description"] =
                    serde_json::Value::String(hints.join("; "));
            }
        }
        tools
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod format_tests {
    use super::*;
    #[test]
    fn metadata_gate_rejects_retired_case_creation_payloads_without_interpreting_them() {
        let mut first = SignedEntry {
            seq: 1,
            case_id: "22222222-2222-2222-2222-222222222222".into(),
            at: 0,
            actor: Actor::Analyst,
            origin: "analyst".into(),
            kind: AuditEventKind::CaseCreated,
            payload: r#"{"version":3,"title":"Synthetic","severity":"medium","scope":"local"}"#
                .into(),
            evidence: None,
            prev: [0; 32],
            hash: [0; 32],
            sig: vec![],
            public_key: vec![],
        };
        assert!(
            verify_case_metadata("Synthetic", Severity::Medium, "local", &[first.clone()]).is_ok()
        );
        for retired in [
            r#"{"version":2,"title":"Synthetic","severity":"medium","scope":"local"}"#,
            "title=Synthetic;scope=local",
        ] {
            first.payload = retired.into();
            assert!(matches!(
                verify_case_metadata("Synthetic", Severity::Medium, "local", &[first.clone()]),
                Err(AppError::Fixed(FixedAppError::RetiredCaseFormat))
            ));
        }
    }
}
