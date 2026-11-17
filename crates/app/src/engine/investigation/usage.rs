use crate::{AppError, CaseId, Engine, ModelUsage, UsageEvent, summarize_usage};

impl Engine<'_> {
    pub(in crate::engine) async fn used_model_tokens(&self, id: &CaseId) -> Result<u64, AppError> {
        let id_owned = id.clone();
        let spent = self
            .blocking_local(move |local| summarize_usage(&local.audit_log.entries(&id_owned)?))
            .await?;
        let owned = id.clone();
        let reserved = self
            .blocking_local(move |local| local.subagent_holds_unlocked(&owned))
            .await?;
        let used_tokens = spent
            .input_tokens
            .checked_add(spent.output_tokens)
            .and_then(|tokens| tokens.checked_add(reserved.tokens))
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyModelTokenCountOverflow,
            ))?;
        Ok(used_tokens)
    }

    pub(in crate::engine) async fn record_model_usage(
        &self,
        id: &CaseId,
        usage: Option<ModelUsage>,
        used_tokens: u64,
        token_limit: u64,
    ) -> Result<(), AppError> {
        if let Some(usage) = usage {
            usage.validate()?;
            usage
                .input_tokens
                .checked_add(usage.output_tokens)
                .and_then(|n| n.checked_add(used_tokens))
                .ok_or(AppError::Fixed(
                    crate::FixedAppError::PolicyModelTokenCountOverflow,
                ))?;
            let event = UsageEvent {
                cache: usage.cache,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                estimated_cost_microusd: self.usage_cost(usage)?,
            };
            if let Some(cost) = event.estimated_cost_microusd {
                let owned = id.clone();
                let previous = self
                    .blocking_local(move |local| {
                        crate::case_budget::reported_cost_subtotal(
                            &local.audit_log.entries(&owned)?,
                        )
                    })
                    .await?;
                previous.checked_add(cost).ok_or(AppError::Fixed(
                    crate::FixedAppError::PolicyModelCostOverflow,
                ))?;
            }
            self.audit_local(
                id,
                crate::AuditOrigin::System,
                irmind_domain::AuditEventKind::ModelUsage,
                &serde_json::to_string(&event)
                    .map_err(|error| AppError::Storage(error.to_string()))?,
                None,
            )
            .await?;
            if used_tokens
                .saturating_add(usage.input_tokens)
                .saturating_add(usage.output_tokens)
                > token_limit
            {
                self.audit_local(
                    id,
                    crate::AuditOrigin::Policy,
                    irmind_domain::AuditEventKind::BudgetExceeded,
                    "model token quota",
                    None,
                )
                .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub(crate) fn usage_cost(&self, usage: ModelUsage) -> Result<Option<u64>, AppError> {
        usage.validate()?;
        let Some(pricing) = self.pricing else {
            return Ok(None);
        };
        pricing.estimate(usage)
    }
}
