use super::{AppError, CancellationToken, Engine, TaskEvidenceQuery, TaskEvidenceResult, invalid};
impl Engine<'_> {
    pub(super) async fn run_child_query(
        &self,
        view: crate::subagents::VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        deadline: u64,
        cancel: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        let queries = self.subagents.as_ref().ok_or_else(invalid)?.queries.clone();
        let token = cancel.child_token();
        let worker_cancel = token.clone();
        let mut worker =
            tokio::task::spawn_blocking(move || queries.execute(&view, query, &worker_cancel));
        let remaining = deadline.saturating_sub(self.clock.now()?).min(600);
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            () = tokio::time::sleep(std::time::Duration::from_secs(remaining)) => None,
            result = &mut worker => Some(result),
        };
        token.cancel();
        let Some(result) = result else {
            // Keep the worker and its view until it exits; timers and cancellation
            // run independently of the synchronous query callback.
            let _joined = worker.await;
            return Err(AppError::Cancelled);
        };
        result.map_err(|_| invalid())?
    }
}
