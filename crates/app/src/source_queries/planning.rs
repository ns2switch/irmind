use super::{
    CompiledSourceQueryV1, QueryTime, SourceQueryError, SourceQueryPlanV1, SourceQueryV1,
    admission::{ActiveSourceAdoption, active_source_adoption, adopted_threshold},
    ports::QuerySourceBinding,
};
use crate::{
    AppError, AuditEventKind, AuthorizedCall, CancellationToken, CaseId, CaseScope, Engine,
    ParserIdentity, Tool,
};
use std::time::Duration;

pub struct PreparedSourceQuery {
    pub plan_id: String,
    pub canonical_plan: String,
    pub needs_analyst_approval: bool,
}

pub(super) struct PlanInput<'a> {
    pub case: &'a CaseId,
    pub query: SourceQueryV1,
    pub compiled: CompiledSourceQueryV1,
    pub binding: &'a QuerySourceBinding,
    pub adoption: &'a ActiveSourceAdoption<'a>,
    pub decoder: ParserIdentity<'a>,
    pub scope_proof: String,
    pub revision: u64,
    pub attempt: u64,
    pub at: QueryTime,
}

impl Engine<'_> {
    /// Prepare an exact query plan in an attended case after validating the
    /// current signed adoption and case scope. Preflight cannot obtain a lease.
    pub async fn plan_source_query(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<PreparedSourceQuery, AppError> {
        self.require_attended_analyst("plan source query")?;
        if call.tool() != &Tool::SourceQuery {
            return Err(SourceQueryError::Scope.into());
        }
        let case = call.case_id();
        let query = SourceQueryV1::from_proposal(call.proposal_args())?;
        let ports = self
            .source_queries
            .as_ref()
            .ok_or(SourceQueryError::Unavailable)?;
        let binding = ports.binding(query.source())?;
        let decoder = ports.page_decoder(&binding.source)?.identity();
        let executor = ports.executor_for(&binding.source)?;
        if executor.descriptor().version != binding.source.module_version() {
            return Err(SourceQueryError::Unavailable.into());
        }
        let compiled = executor.compile(&binding.source, &query)?;
        let operations = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&operations)?;
        let adoption = active_source_adoption(&binding.source, &operations)?;
        adoption.check_limits(binding)?;
        let (scope, revision) = {
            let _case_lock = self.repo.lock_case(case)?;
            self.query_preflight_state(call, binding, &query, &operations, cancel)?
        };
        let preflight = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = tokio::time::timeout(
                Duration::from_secs(binding.limits.deadline_seconds),
                executor.preflight(call, &compiled, cancel),
            ) => result.map_err(|_| SourceQueryError::Unresolved)??,
        };
        let _case_lock = self.repo.lock_case(case)?;
        let _global_lock = self.audit_log.lock_global_operations()?;
        let current = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&current)?;
        if active_source_adoption(&binding.source, &current)?
            .operation
            .hash
            != adoption.operation.hash
            || self.query_preflight_state(call, binding, &query, &current, cancel)?
                != (scope.clone(), revision)
        {
            return Err(SourceQueryError::Approval.into());
        }
        let last = self
            .audit_log
            .last_entry(case)?
            .ok_or(AppError::InvalidChain(0))?;
        let plan = SourceQueryPlanV1::prepare(
            PlanInput {
                case,
                query,
                compiled,
                binding,
                adoption: &adoption,
                decoder,
                scope_proof: scope,
                revision,
                attempt: last.seq.checked_add(1).ok_or(SourceQueryError::Limit)?,
                at: self.query_now()?,
            },
            preflight,
        )?;
        let threshold = adopted_threshold(&plan, adoption.operation, self.verifier.as_ref())?;
        let entry =
            self.sign_query_frame(case, Some(&last), AuditEventKind::SourceQueryPlanV1, &plan)?;
        self.audit_log.append(&entry)?;
        Ok(PreparedSourceQuery {
            plan_id: plan.content_id()?,
            canonical_plan: entry.payload,
            // Query-specific consent is layered on the normal engine policy.
            needs_analyst_approval: plan.requires_approval(threshold, false),
        })
    }

    fn query_preflight_state(
        &self,
        call: &AuthorizedCall,
        binding: &QuerySourceBinding,
        query: &SourceQueryV1,
        operations: &[crate::SignedOperation],
        cancel: &CancellationToken,
    ) -> Result<(String, u64), AppError> {
        let scope = self.live_query_scope(call, binding, query, cancel)?;
        let entries = self.audit_log.entries(call.case_id())?;
        self.check_live_query_allocation(&entries)?;
        let journal = super::SourceQueryJournal::replay(
            &entries,
            operations,
            self.verifier.as_ref(),
            cancel,
        )?;
        let revision = journal
            .broker
            .preflight_revision(&binding.source, &binding.limits)?;
        Ok((scope, revision))
    }

    fn live_query_scope(
        &self,
        call: &AuthorizedCall,
        binding: &QuerySourceBinding,
        query: &SourceQueryV1,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let id = call.case_id();
        self.verify_unlocked_cancelable(id, cancel)?;
        let case = self.repo.get_case(id)?;
        if case.sealed {
            return Err(AppError::Sealed);
        }
        let policy = self.policy_for_case_unlocked(id)?;
        policy
            .permits(&Tool::SourceQuery, self.completed_calls_unlocked(id)?)
            .map_err(|reason| AppError::Policy(reason.into()))?;
        let proposal = crate::ProposedCall {
            tool: Tool::SourceQuery,
            args: call.proposal_args().clone(),
        };
        let proposed = crate::Tainted::from_external(
            proposal,
            crate::Provenance::new([0; 32], None, crate::SourceKind::ModelProposal),
        );
        match irmind_domain::evaluate_tainted_with_rules(
            &case,
            proposed,
            call.decision_seq(),
            self.mode,
            self.turn_has_detections(id)?,
            self.clock.now()?,
            &policy,
        ) {
            crate::Decision::Allow(_) => {}
            crate::Decision::Deny(reason) => return Err(AppError::Policy(reason.into())),
            crate::Decision::NeedsApproval(_) => return Err(SourceQueryError::Approval.into()),
        }
        let scope = CaseScope::parse(&case.scope).map_err(|_| SourceQueryError::Scope)?;
        let ceiling = self.policy.scope.as_ref().ok_or(SourceQueryError::Scope)?;
        if !scope.is_within(ceiling)
            || !binding.source.admits(query, &scope)
            || !binding.source.admits(query, ceiling)
        {
            return Err(SourceQueryError::Scope.into());
        }
        let entries = self.audit_log.entries(id)?;
        let proof = entries
            .iter()
            .rev()
            .find(|entry| {
                matches!(
                    entry.kind,
                    AuditEventKind::CaseCreated | AuditEventKind::CaseScopeChanged
                )
            })
            .ok_or(AppError::InvalidChain(0))?;
        Ok(crate::hex(&proof.hash))
    }

    pub(super) fn query_now(&self) -> Result<QueryTime, AppError> {
        let index =
            irmind_domain::IndexedTime::from_epoch_decimal(&self.clock.now()?.to_string(), false)
                .map_err(|_| SourceQueryError::Invalid)?;
        Ok(QueryTime::parse(&index.to_rfc3339())?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::source_queries::{QueryPreflightV1, SourceQueryLimits, canonical_query_json};
    use irmind_domain::{EvidenceHash, MappingIdentityV1};

    #[test]
    fn the_preflight_commitment_is_bound_to_the_compiler_and_signed_adoption() {
        let wire: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../docs/development/source-query-format-vectors/plan.json"
        ))
        .unwrap();
        let operation = serde_json::from_slice(include_bytes!(
            "../../../../docs/development/source-query-format-vectors/signed-configuration.json"
        ))
        .unwrap();
        let binding = QuerySourceBinding {
            source: serde_json::from_value(wire["source"].clone()).unwrap(),
            limits: serde_json::from_value::<SourceQueryLimits>(wire["limits"].clone()).unwrap(),
            mapping: MappingIdentityV1::try_new(
                "synthetic-query-map",
                "1",
                irmind_domain::COMMON_EVENT_V1,
                EvidenceHash::from_bytes([8; 32]),
            )
            .unwrap(),
        };
        let adoption =
            active_source_adoption(&binding.source, std::slice::from_ref(&operation)).unwrap();
        let case = CaseId::parse(wire["case_id"].as_str().unwrap()).unwrap();
        let input = || PlanInput {
            case: &case,
            query: serde_json::from_value(wire["query"].clone()).unwrap(),
            compiled: serde_json::from_value(wire["compiled"].clone()).unwrap(),
            binding: &binding,
            adoption: &adoption,
            decoder: ParserIdentity {
                name: "query-athena-cloudtrail",
                version: "1",
            },
            revision: 1,
            attempt: 1,
            scope_proof: "a".repeat(64),
            at: QueryTime::parse(wire["at"].as_str().unwrap()).unwrap(),
        };
        let mut preflight: QueryPreflightV1 =
            serde_json::from_value(wire["preflight"].clone()).unwrap();
        assert!(SourceQueryPlanV1::prepare(input(), preflight.clone()).is_err());
        preflight.plan_digest = crate::hex(&crate::sha256(
            &canonical_query_json(&input().compiled).unwrap(),
        ));
        let plan = SourceQueryPlanV1::prepare(input(), preflight).unwrap();
        let canonical = canonical_query_json(&plan).unwrap();
        assert_eq!(
            SourceQueryPlanV1::decode(&canonical)
                .unwrap()
                .content_id()
                .unwrap(),
            plan.content_id().unwrap()
        );
        assert_eq!(plan.adoption(), crate::hex(&operation.hash));
    }
}
