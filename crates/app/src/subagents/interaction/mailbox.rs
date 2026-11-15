//! Bounded in-process Analyst review adapter, separate from read-only events.
use super::{AnalystPlanChoice, AnalystPlanInteraction, PortFuture, SafePlanPreview};
use crate::{AppError, CancellationToken, CaseId};
use std::{collections::VecDeque, sync::Mutex};
use tokio::sync::oneshot;

#[derive(Default)]
pub struct AnalystPlanMailbox {
    requests: Mutex<VecDeque<PlanReview>>,
}
pub struct PlanReview {
    preview: SafePlanPreview,
    reply: oneshot::Sender<AnalystPlanChoice>,
}
impl PlanReview {
    pub const fn preview(&self) -> &SafePlanPreview {
        &self.preview
    }
    pub fn is_active(&self) -> bool {
        !self.reply.is_closed()
    }
    pub fn start(self) -> Result<(), AppError> {
        let choice = self.preview.start()?;
        self.reply.send(choice).map_err(|_| unavailable())
    }
    pub fn cancel(self) -> Result<(), AppError> {
        let choice = self.preview.cancel()?;
        self.reply.send(choice).map_err(|_| unavailable())
    }
    /// Called only after the trusted UI has displayed the below-threshold plan.
    pub fn automatic_start(self) -> Result<(), AppError> {
        let choice = self.preview.automatic_start()?;
        self.reply.send(choice).map_err(|_| unavailable())
    }
}
impl AnalystPlanMailbox {
    pub fn take_review(&self, case: &CaseId) -> Result<Option<PlanReview>, AppError> {
        let mut requests = self.requests.lock().map_err(|_| unavailable())?;
        requests.retain(PlanReview::is_active);
        Ok(requests
            .iter()
            .position(|request| request.preview.case_id() == case.as_str())
            .and_then(|index| requests.remove(index)))
    }
}
impl AnalystPlanInteraction for AnalystPlanMailbox {
    fn review<'a>(
        &'a self,
        preview: &'a SafePlanPreview,
        cancel: &'a CancellationToken,
    ) -> PortFuture<'a, AnalystPlanChoice> {
        Box::pin(async move {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let (reply, receiver) = oneshot::channel();
            {
                let mut requests = self.requests.lock().map_err(|_| unavailable())?;
                requests.retain(PlanReview::is_active);
                if requests.len() >= 16 {
                    return Err(unavailable());
                }
                requests.push_back(PlanReview {
                    preview: preview.clone(),
                    reply,
                });
            }
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(AppError::Cancelled),
                choice = receiver => choice.map_err(|_| unavailable()),
            }
        })
    }
}
fn unavailable() -> AppError {
    AppError::Policy("The Analyst plan review is unavailable or has expired".into())
}
