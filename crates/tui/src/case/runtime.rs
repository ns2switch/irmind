mod input;
use super::state::{CaseMessage, CaseState, update};
use super::{
    ActiveTask, CancellationToken, CaseId, CaseWorkflow, Confirmation, CrosstermBackend, Duration,
    Engine, Event, Instant, LlmPort, Result, Terminal, WorkspaceIo, cancelled_operation, event, io,
    mpsc, seal_confirmation,
};
use crossterm::event::KeyEventKind;

pub(super) struct CaseRuntime<'scope, 'env, 'ports> {
    pub terminal: &'env mut Terminal<CrosstermBackend<io::Stdout>>,
    pub engine: &'env Engine<'ports>,
    pub model: Option<&'env dyn LlmPort>,
    pub io_ops: &'env dyn WorkspaceIo,
    pub id: &'env CaseId,
    pub shutdown: &'env CancellationToken,
    pub scope: &'scope std::thread::Scope<'scope, 'env>,
    pub state: CaseState,
    pub active: Option<ActiveTask<'scope>>,
    pub progress_tx: mpsc::Sender<String>,
    pub progress_rx: mpsc::Receiver<String>,
    pub model_tx: mpsc::Sender<String>,
    pub model_rx: mpsc::Receiver<String>,
    pub seal_tx: mpsc::Sender<irmind_app::SealPreview>,
    pub seal_rx: mpsc::Receiver<irmind_app::SealPreview>,
    pub overrides_active: bool,
    pub modules: &'env [crate::ModuleStatus],
}

impl<'scope> CaseRuntime<'scope, '_, '_> {
    pub(super) fn run(&mut self) -> Result<()> {
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            for _ in 0..128 {
                let Ok(progress) = self.progress_rx.try_recv() else {
                    break;
                };
                update(&mut self.state, CaseMessage::Progress(progress));
            }
            let mut preview_dirty = false;
            for _ in 0..256 {
                let Ok(delta) = self.model_rx.try_recv() else {
                    break;
                };
                update(&mut self.state, CaseMessage::ModelDelta(delta));
                preview_dirty = true;
            }
            if preview_dirty {
                let safe = self.engine.guard.screen(&self.state.model_preview)?.text;
                self.state.conversation.set_preview(safe);
            }
            self.finish_task()?;
            self.refresh()?;
            self.render()?;
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key)
                        if key.kind != KeyEventKind::Release
                            && self.handle_key(key.code, key.modifiers)? =>
                    {
                        break;
                    }
                    Event::Mouse(mouse) => self.handle_mouse(mouse),
                    _ => {}
                }
            }
        }
        if let Some((cancel, task, label)) = self.active.take() {
            cancel.cancel();
            if let Ok(Err(irmind_app::AppError::Cancelled)) = task.join() {
                self.engine
                    .record_cancellation(self.id, cancelled_operation(label))?;
            }
        }
        Ok(())
    }

    fn finish_task(&mut self) -> Result<()> {
        if !self
            .active
            .as_ref()
            .is_some_and(|(_, task, _)| task.is_finished())
        {
            if self.active.is_some() && self.state.running_since.is_none() {
                self.state.running_since = Some(Instant::now());
            }
            return Ok(());
        }
        if let Some((_, task, label)) = self.active.take() {
            self.state.model_preview.clear();
            match task
                .join()
                .map_err(|_| anyhow::anyhow!("investigation thread panicked"))?
            {
                Ok(text) => {
                    if label == "IRMind" {
                        self.state.conversation.discard_preview();
                        self.state.pending_final_reply =
                            Some(self.engine.guard.screen(&text)?.text);
                    }
                    if label == "Prepare seal" {
                        let preview = self.seal_rx.try_recv().map_err(|_| {
                            anyhow::anyhow!("signed seal preview was not delivered")
                        })?;
                        let summary = seal_confirmation(&preview);
                        self.state.confirmation =
                            Some(Confirmation::Seal(Box::new(preview), summary));
                    }
                    if label != "IRMind" {
                        if label == "SIEM alert"
                            && !text.starts_with("approval pending:")
                            && !text.starts_with("denied:")
                        {
                            self.state.result_cards.push(("SIEM alert", text));
                        } else {
                            update(
                                &mut self.state,
                                CaseMessage::TaskFinished(format!("{label}: {text}")),
                            );
                        }
                    }
                }
                Err(irmind_app::AppError::Cancelled) => {
                    if label == "IRMind" {
                        self.state.conversation.discard_preview();
                    }
                    self.engine
                        .record_cancellation(self.id, cancelled_operation(label))?;
                    update(
                        &mut self.state,
                        CaseMessage::TaskFinished(format!("{label} cancelled and audited")),
                    );
                }
                Err(error) => {
                    if label == "IRMind" {
                        self.state.conversation.discard_preview();
                    }
                    update(
                        &mut self.state,
                        CaseMessage::TaskFinished(format!("Error: {error}")),
                    );
                }
            }
            self.state.case = self.engine.repo.get_case(self.id)?;
            self.state.approvals = self.engine.pending_approvals(self.id)?;
            self.state.approval_sources =
                super::load_approval_sources(self.engine, self.id, &self.state.approvals)?;
            self.state.findings = self.engine.findings(self.id)?;
            self.state.needs_refresh = true;
        }
        self.state.running_since = None;
        Ok(())
    }

    fn refresh(&mut self) -> Result<()> {
        self.state.selected_approval = self
            .state
            .selected_approval
            .min(self.state.approvals.len().saturating_sub(1));
        self.state.selected_finding = self.state.selected_finding.min(
            super::state::panel_findings(&self.state)
                .len()
                .saturating_sub(1),
        );
        if self.active.is_none() && self.state.needs_refresh {
            let _case_lock = self.engine.repo.lock_case(self.id)?;
            self.state.hashes = self.engine.evidence_store.evidence_hashes(self.id)?;
            self.state.entries = self.engine.audit_log.entries(self.id)?;
            self.state.operations = self.engine.audit_log.operations(self.id)?;
            self.state.timeline = self.engine.graph.timeline(self.id, 30)?;
            self.state.needs_refresh = false;
        }
        Ok(())
    }

    pub(super) fn start_approval(&mut self, request_id: String) {
        let workflow = CaseWorkflow {
            engine: self.engine,
            model: self.model,
            io_ops: self.io_ops,
        };
        let id = self.id;
        self.start_task("Approval", move |cancel| {
            workflow.approve(id, &request_id, &cancel)
        });
    }

    pub(super) fn start_task<F>(&mut self, label: &'static str, work: F)
    where
        F: FnOnce(CancellationToken) -> Result<String, irmind_app::AppError> + Send + 'scope,
    {
        let cancel = self.shutdown.child_token();
        let worker_cancel = cancel.clone();
        let task = self.scope.spawn(move || work(worker_cancel));
        self.active = Some((cancel, task, label));
    }
}
