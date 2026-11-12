use super::{TurnContext, untrusted_user_message};
use crate::{
    AppError, AuditEventKind, AuditOrigin, Case, Decision, Engine, ModelToolCall, ProposedCall,
    Tool,
};
use irmind_domain::SkillName;
impl Engine<'_> {
    pub(super) async fn initialize_turn_skills(
        &self,
        case: &Case,
        turn: &mut TurnContext,
        input: &str,
    ) -> Result<(), AppError> {
        if self.skills.is_none() {
            return Ok(());
        }
        let catalog = self
            .blocking_local(|local| local.skill_catalog_text())
            .await?;
        if !catalog.is_empty() {
            turn.messages.insert(2, untrusted_user_message(&format!("Available forensic methods (name and description only):\n{catalog}\nUse skill_read when a method is relevant."), &turn.nonce));
        }
        let Some(command) = input
            .strip_prefix('/')
            .and_then(|s| s.split_whitespace().next())
        else {
            return Ok(());
        };
        let name = command.to_owned();
        if !self
            .blocking_local(move |local| Ok(local.skill_invocable(&name)))
            .await?
        {
            return Ok(());
        }
        let proposal = ProposedCall {
            tool: Tool::SkillRead,
            args: std::collections::BTreeMap::from([("name".into(), command.into())]),
        };
        let call = ModelToolCall::from_proposal(&format!("manual_skill_{}", turn.nonce), proposal)?;
        turn.messages
            .push(crate::CompletionMessage::assistant_tools(
                String::new(),
                vec![call.clone()],
            ));
        let result = self.read_turn_skill(case, turn, &call).await?;
        turn.messages.push(crate::CompletionMessage::tool_result(
            call.id().into(),
            untrusted_user_message(&result, &turn.nonce).content,
        ));
        Ok(())
    }
    pub(super) async fn read_turn_skill(
        &self,
        case: &Case,
        turn: &TurnContext,
        call: &ModelToolCall,
    ) -> Result<String, AppError> {
        let decision = self
            .evaluate_proposal(case, call.proposal().clone(), AuditOrigin::Model)
            .await?;
        let Decision::Allow(authorized) = decision else {
            self.audit_local(
                &case.id,
                AuditOrigin::Policy,
                AuditEventKind::Denied,
                "skill read denied by policy",
                None,
            )
            .await?;
            return Ok("Skill read denied by policy; no content was exposed.".into());
        };
        self.audit_local(
            &case.id,
            AuditOrigin::Policy,
            AuditEventKind::Allowed,
            "bounded skill read",
            None,
        )
        .await?;
        let name = SkillName::parse(
            authorized
                .arg("name")
                .ok_or(crate::SkillServiceError::NotInstalled)?,
        )?;
        let resource = authorized.arg("resource").unwrap_or("SKILL.md").to_owned();
        let id = case.id.clone();
        let nonce = turn.nonce;
        let call_id = call.id().to_owned();
        let budget = turn.skills.clone();
        let remaining = self
            .policy
            .max_model_tokens_per_case
            .saturating_sub(self.used_model_tokens(&case.id).await?)
            .saturating_sub(512);
        let available = 48_000usize
            .saturating_sub(super::compaction::context_bytes(&turn.messages))
            .saturating_sub(1024);
        let text_limit = available
            .min(23_000)
            .min(self.policy.max_model_result_bytes.saturating_sub(1024))
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.blocking_local(move |local| {
            let mut state = budget
                .lock()
                .map_err(|_| crate::SkillServiceError::InvalidReceipt)?;
            state.read_limit = text_limit;
            match local.read_skill_local(&id, &name, &resource, &mut state, nonce, &call_id) {
                Ok(text) => Ok(text),
                Err(error) => local.failed_skill_result(&id, &error),
            }
        })
        .await
    }
    pub(super) async fn skill_call_declared(
        &self,
        case: &Case,
        turn: &TurnContext,
        proposal: &ProposedCall,
    ) -> Result<bool, AppError> {
        let active = {
            let state = turn
                .skills
                .lock()
                .map_err(|_| crate::SkillServiceError::InvalidReceipt)?;
            state.active.clone()
        };
        let tool = proposal.tool.clone();
        let allowed = self
            .blocking_local(move |local| {
                Ok(active.is_none_or(|active| {
                    active.tools.contains(tool.as_str())
                        && local.resolve_skill(&active.name).is_ok_and(|resolved| {
                            resolved.skill.package().hash() == &active.package
                        })
                }))
            })
            .await?;
        if !allowed {
            self.audit_local(
                &case.id,
                AuditOrigin::Policy,
                AuditEventKind::Denied,
                "tool is not declared by the active skill",
                None,
            )
            .await?;
        }
        Ok(allowed)
    }
}
