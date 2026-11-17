use super::super::{Confirmation, confirmation::subagent_recovery_confirmation};
use super::CaseRuntime;

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn recover_subagents_command(&mut self, prompt: &str) -> bool {
        if prompt != "/subagents recover" {
            return false;
        }
        if self.active.is_some() {
            self.state.messages.push(
                "Stop the live turn with /pause and wait for it to finish before recovering interrupted plans.".into(),
            );
            return true;
        }
        if self.state.case.sealed {
            self.state
                .messages
                .push("Sealed cases are read-only; interrupted plans cannot be changed.".into());
            return true;
        }
        if matches!(
            self.state.confirmed_action.as_ref(),
            Some(Confirmation::RecoverSubagents(_))
        ) {
            self.state.confirmed_action = None;
            let engine = self.engine;
            let id = self.id;
            self.start_task("Recover subagents", move |cancel| {
                if cancel.is_cancelled() {
                    return Err(irmind_app::AppError::Cancelled);
                }
                let closed = engine.cancel_interrupted_subagent_plans(id)?;
                Ok(format!(
                    "Closed {closed} interrupted subagent plans; completed work and uncertain usage retained."
                ))
            });
        } else {
            self.state.confirmation_option = 0;
            self.state.confirmation = Some(Confirmation::RecoverSubagents(
                subagent_recovery_confirmation(),
            ));
        }
        true
    }
}
