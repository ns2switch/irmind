use crate::{AppError, CaseId, Engine, ModelUsage, UsageEvent, summarize_usage};

impl Engine<'_> {
    pub(super) async fn used_model_tokens(&self, id: &CaseId) -> Result<u64, AppError> {
        let id_owned = id.clone();
        let spent = self
            .blocking_local(move |local| summarize_usage(&local.audit_log.entries(&id_owned)?))
            .await?;
        let used_tokens =
            spent
                .input_tokens
                .checked_add(spent.output_tokens)
                .ok_or(AppError::Fixed(
                    crate::FixedAppError::PolicyModelTokenCountOverflow,
                ))?;
        Ok(used_tokens)
    }

    pub(super) async fn record_model_usage(
        &self,
        id: &CaseId,
        usage: Option<ModelUsage>,
        used_tokens: u64,
    ) -> Result<(), AppError> {
        if let Some(usage) = usage {
            let event = UsageEvent {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                estimated_cost_microusd: self.usage_cost(usage)?,
            };
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
                > self.policy.max_model_tokens_per_case
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
        let Some(pricing) = self.pricing else {
            return Ok(None);
        };
        let input = u128::from(usage.input_tokens)
            .checked_mul(u128::from(pricing.input_microusd_per_million))
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyModelCostOverflow,
            ))?;
        let output = u128::from(usage.output_tokens)
            .checked_mul(u128::from(pricing.output_microusd_per_million))
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyModelCostOverflow,
            ))?;
        let total = input.checked_add(output).ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyModelCostOverflow,
        ))? / 1_000_000;
        Ok(Some(u64::try_from(total).map_err(|_| {
            AppError::Fixed(crate::FixedAppError::PolicyModelCostOverflow)
        })?))
    }
}
