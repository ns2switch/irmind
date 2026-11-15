//! Delegated reads retain their narrow capability and their own evidence receipt.
use super::{
    AppError, CancellationToken, CaseId, ChildReadResponse, Engine, ReadEffect,
    StartedSubagentPlan, invalid,
};
use crate::subagents::SubagentTaskSpec;
use crate::{AuthorizedCall, Tool};
mod object;

pub(super) fn supported(name: &str) -> bool {
    matches!(
        Tool::parse(name),
        Ok(Tool::SiemSearch
            | Tool::SiemGetAlert
            | Tool::CloudAuditEvents
            | Tool::CloudIdentity
            | Tool::EdrHostInfo
            | Tool::EdrProcessTree
            | Tool::EdrDetections
            | Tool::ThreatIntelInternal
            | Tool::ObjectList
            | Tool::ObjectRead)
    )
}
impl Engine<'_> {
    pub(super) fn permit_child_remote(&self, call: &AuthorizedCall) -> Result<bool, AppError> {
        self.validate_source_scope(call)?;
        // The instance mode deliberately widens an event query. A delegated
        // narrowed task must not acquire that widening through the adapter.
        Ok(!call
            .arg("source")
            .and_then(|source| self.source_scopes.get(source))
            .is_some_and(|source| source.mode() == crate::SiemScopeMode::Instance))
    }
    pub(super) async fn run_child_remote(
        &self,
        started: &StartedSubagentPlan,
        task: &SubagentTaskSpec,
        effect: &ReadEffect,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ChildReadResponse, AppError> {
        let case = CaseId::parse(&started.plan.case_id).map_err(|_| invalid())?;
        if call.case_id() != &case
            || call.tool().as_str() != effect.call.tool
            || call.proposal_args() != &effect.call.arguments
            || !self.permit_child_remote(call)?
        {
            return Err(invalid());
        }
        if call.tool() == &Tool::ObjectRead {
            return self
                .run_child_object(started, task, effect, call, cancel)
                .await;
        }
        let remaining = task.deadline_at.saturating_sub(self.clock.now()?).min(600);
        let signal = cancel.child_token();
        let response = tokio::select! { biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            result = tokio::time::timeout(std::time::Duration::from_secs(remaining),
                self.child_remote_bytes(call, &signal)) => result.unwrap_or(Err(AppError::Cancelled)),
        };
        signal.cancel();
        let (raw, complete) = response?;
        self.retain_child_remote_result(started, task, effect, &raw, complete, cancel)
    }
    async fn child_remote_bytes(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<(Vec<u8>, bool), AppError> {
        if call.tool() == &Tool::ObjectList {
            let crate::ObjectSourceOutput::Listing {
                objects,
                total_bytes,
                truncated,
            } = self.dispatch_object_source(call, cancel).await?
            else {
                return Err(AppError::RemoteTool);
            };
            Ok((
                crate::dispatch::listing::validated_listing(
                    call,
                    &objects,
                    total_bytes,
                    truncated,
                )?,
                !truncated,
            ))
        } else {
            self.run_authorized_tool(call, false, cancel)
                .await
                .map(|raw| (raw, false))
        }
    }
}
