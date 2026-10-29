use super::{CaseCreatedEvent, ScopeChangedEvent};
use crate::{
    Actor, AppError, Arc, Case, CaseId, CaseMutation, CaseScope, Clock, Engine, EnginePorts,
    ExecutionMode, ModelPricing, PolicyRules, Severity, startup_check,
};

impl<'a> Engine<'a> {
    pub fn open_case_verified(
        &self,
        id: &CaseId,
        cancel: &crate::CancellationToken,
    ) -> Result<Case, AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        self.repo.get_case(id)
    }

    pub fn new(
        ports: EnginePorts,
        mode: ExecutionMode,
        clock: Arc<dyn Clock>,
    ) -> Result<Engine<'a>, AppError> {
        startup_check(ports.guard.as_ref())?;
        if matches!(ports.signer.actor(), Actor::Agent(_)) && mode == ExecutionMode::Attended {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyAgentCannotRunInAttendedMode,
            ));
        }
        let engine = Engine {
            repo: ports.repo,
            evidence_store: ports.evidence_store,
            graph: ports.graph,
            audit_log: ports.audit_log,
            signer: ports.signer,
            verifier: ports.verifier,
            guard: ports.guard,
            parser: ports.parser,
            clock,
            mode,
            policy: PolicyRules::default(),
            policy_fingerprint: "builtin-v1".into(),
            module_fingerprint: "none".into(),
            threat_intel: None,
            siems: Vec::new(),
            cloud_audits: Vec::new(),
            edrs: Vec::new(),
            internal_intel: Vec::new(),
            object_sources: Vec::new(),
            pricing: None,
            verified_cases: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        };
        engine.verify_global_operations()?;
        Ok(engine)
    }

    #[must_use]
    pub fn with_pricing(mut self, pricing: ModelPricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    pub fn with_policy(
        mut self,
        policy: PolicyRules,
        fingerprint: String,
    ) -> Result<Self, AppError> {
        policy
            .validate()
            .map_err(|_| AppError::Fixed(crate::FixedAppError::PolicyInvalidPolicyLimits))?;
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidPolicyFingerprint,
            ));
        }
        self.policy = policy;
        self.policy_fingerprint = fingerprint;
        Ok(self)
    }

    pub fn with_module_fingerprint(mut self, fingerprint: String) -> Result<Self, AppError> {
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidModuleFingerprint,
            ));
        }
        self.module_fingerprint = fingerprint;
        Ok(self)
    }

    pub fn create_case(&self, title: &str, scope: &str) -> Result<Case, AppError> {
        self.create_case_with_severity(title, Severity::Medium, scope)
    }

    pub fn create_case_with_severity(
        &self,
        title: &str,
        severity: Severity,
        scope: &str,
    ) -> Result<Case, AppError> {
        self.require_attended_analyst("create case")?;
        if title.trim().is_empty()
            || title.len() > 200
            || scope.trim().is_empty()
            || scope.len() > 1000
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyTitleOrScopeIsInvalid,
            ));
        }
        let parsed_scope = CaseScope::parse(scope)
            .map_err(|_| AppError::Fixed(crate::FixedAppError::PolicyInvalidStructuredScope))?;
        self.validate_policy_ceiling(&parsed_scope)?;
        let id = CaseId::parse(&uuid::Uuid::new_v4().to_string())
            .map_err(|_| AppError::InvalidCaseId)?;
        let _case_lock = self.repo.lock_case(&id)?;
        let case = Case {
            id,
            title: title.to_owned(),
            severity,
            scope: scope.to_owned(),
            sealed: false,
        };
        let entry = self.signed_entry(
            &case.id,
            crate::AuditOrigin::System,
            irmind_domain::AuditEventKind::CaseCreated,
            &serde_json::to_string(&CaseCreatedEvent {
                version: 3,
                title: title.to_owned(),
                severity: Some(severity.as_str().to_owned()),
                scope: scope.to_owned(),
            })
            .map_err(|error| AppError::Storage(error.to_string()))?,
            None,
        )?;
        self.audit_log
            .transact(&entry, CaseMutation::Create(case.clone()))?;
        Ok(case)
    }

    pub fn change_scope(&self, id: &CaseId, new_scope: &str) -> Result<(), AppError> {
        self.require_attended_analyst("change case scope")?;
        if new_scope.trim().is_empty() || new_scope.len() > 1000 {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidCaseScope,
            ));
        }
        let parsed_scope = CaseScope::parse(new_scope)
            .map_err(|_| AppError::Fixed(crate::FixedAppError::PolicyInvalidCaseScope))?;
        self.validate_policy_ceiling(&parsed_scope)?;
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        if case.scope == new_scope {
            return Ok(());
        }
        let payload = serde_json::to_string(&ScopeChangedEvent {
            version: 1,
            previous_scope: case.scope,
            new_scope: new_scope.to_owned(),
        })
        .map_err(|error| AppError::Storage(error.to_string()))?;
        let entry = self.signed_entry(
            id,
            crate::AuditOrigin::Analyst,
            irmind_domain::AuditEventKind::CaseScopeChanged,
            &payload,
            None,
        )?;
        self.audit_log.transact(
            &entry,
            CaseMutation::Scope {
                id: id.clone(),
                new_scope: new_scope.to_owned(),
            },
        )
    }

    pub fn case_scope_exceeds_policy(&self, case: &Case) -> Result<bool, AppError> {
        let Some(ceiling) = &self.policy.scope else {
            return Ok(false);
        };
        let scope = CaseScope::parse(&case.scope)
            .map_err(|_| AppError::Fixed(crate::FixedAppError::PolicyInvalidCaseScope))?;
        Ok(!scope.is_within(ceiling))
    }

    fn validate_policy_ceiling(&self, scope: &CaseScope) -> Result<(), AppError> {
        if self
            .policy
            .scope
            .as_ref()
            .is_some_and(|ceiling| !scope.is_within(ceiling))
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyScopeExceedsOrganizationCeiling,
            ));
        }
        Ok(())
    }
}
