use super::state::{CaseAction, CaseMessage, CaseState, update};
use super::{
    ActiveTask, CancellationToken, CaseId, CaseWorkflow, Confirmation, CrosstermBackend, Duration,
    Engine, Event, Instant, KeyCode, KeyModifiers, LlmPort, Result, Terminal, WorkspaceIo,
    cancelled_operation, event, io, mpsc, seal_confirmation,
};

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
}

impl<'scope> CaseRuntime<'scope, '_, '_> {
    pub(super) fn run(&mut self) -> Result<()> {
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            while let Ok(progress) = self.progress_rx.try_recv() {
                update(&mut self.state, CaseMessage::Progress(progress));
            }
            while let Ok(delta) = self.model_rx.try_recv() {
                update(&mut self.state, CaseMessage::ModelDelta(delta));
            }
            self.finish_task()?;
            self.refresh()?;
            self.render()?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && self.handle_key(key.code, key.modifiers)?
            {
                break;
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
                    if label == "Prepare seal" {
                        let preview = self.seal_rx.try_recv().map_err(|_| {
                            anyhow::anyhow!("signed seal preview was not delivered")
                        })?;
                        let summary = seal_confirmation(&preview);
                        self.state.confirmation =
                            Some(Confirmation::Seal(Box::new(preview), summary));
                    }
                    update(
                        &mut self.state,
                        CaseMessage::TaskFinished(format!("{label}: {text}")),
                    );
                }
                Err(irmind_app::AppError::Cancelled) => {
                    self.engine
                        .record_cancellation(self.id, cancelled_operation(label))?;
                    update(
                        &mut self.state,
                        CaseMessage::TaskFinished(format!("{label} cancelled and audited")),
                    );
                }
                Err(error) => {
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

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<bool> {
        if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            return Ok(true);
        }
        if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('k') {
            self.state.palette = Some(String::new());
            self.state.picker = None;
            self.state.confirmation = None;
            return Ok(false);
        }
        let Some(code) = self.handle_overlay_key(code)? else {
            return Ok(false);
        };
        match update(
            &mut self.state,
            CaseMessage::Key(code, self.active.is_some()),
        ) {
            CaseAction::None => Ok(false),
            CaseAction::Exit => Ok(true),
            CaseAction::Approve(request_id) => {
                self.start_approval(request_id);
                Ok(false)
            }
            CaseAction::ConfirmFinding(finding_id) => {
                if let Some(finding) = self
                    .state
                    .findings
                    .iter()
                    .find(|item| item.id == finding_id)
                {
                    self.state.confirmation = Some(Confirmation::Finding(
                        finding_id,
                        format!(
                            "Confirm {:?}: {}\nEvidence: {}\nPress y to sign confirmation or Esc to cancel",
                            finding.kind, finding.value, finding.evidence_hash
                        ),
                    ));
                }
                Ok(false)
            }
            CaseAction::Submit(prompt) => self.submit(prompt),
        }
    }

    fn handle_overlay_key(&mut self, code: KeyCode) -> Result<Option<KeyCode>> {
        if let Some(mut query) = self.state.palette.take() {
            match code {
                KeyCode::Esc => return Ok(None),
                KeyCode::Backspace => {
                    query.pop();
                    self.state.palette = Some(query);
                    return Ok(None);
                }
                KeyCode::Char(ch) if query.len() < 80 => {
                    query.push(ch);
                    self.state.palette = Some(query);
                    return Ok(None);
                }
                KeyCode::Enter => {
                    const ACTIONS: [&str; 7] = [
                        "ingest",
                        "verify",
                        "rebuild graph",
                        "report",
                        "export",
                        "seal",
                        "home",
                    ];
                    let selected = ACTIONS
                        .iter()
                        .find(|action| action.contains(query.as_str()));
                    self.state.input = match selected.copied() {
                        Some("ingest") => "/ingest".into(),
                        Some("verify") => "/verify".into(),
                        Some("rebuild graph") => "/rebuild".into(),
                        Some("report") => "/report".into(),
                        Some("export") => "/export".into(),
                        Some("seal") => "/seal".into(),
                        Some("home") => "/home".into(),
                        _ => String::new(),
                    };
                    return Ok(Some(KeyCode::Enter));
                }
                _ => {
                    self.state.palette = Some(query);
                    return Ok(None);
                }
            }
        }
        if self.state.picker.is_some() {
            return self.handle_picker_key(code);
        }
        if let Some(pending) = self.state.confirmation.take() {
            if code == KeyCode::Char('y') {
                self.state.input = match &pending {
                    Confirmation::Seal(_, _) => "/seal".into(),
                    Confirmation::Export(path, _) => format!("/export {}", path.to_string_lossy()),
                    Confirmation::Finding(id, _) => format!("/confirm {id}"),
                };
                if !matches!(pending, Confirmation::Finding(_, _)) {
                    self.state.confirmed_action = Some(pending);
                }
                return Ok(Some(KeyCode::Enter));
            }
            return Ok(None);
        }
        Ok(Some(code))
    }

    fn handle_picker_key(&mut self, code: KeyCode) -> Result<Option<KeyCode>> {
        let Some(mut browser) = self.state.picker.take() else {
            return Ok(Some(code));
        };
        match code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Up => browser.selected = browser.selected.saturating_sub(1),
            KeyCode::Down => {
                browser.selected =
                    (browser.selected + 1).min(browser.entries.len().saturating_sub(1));
            }
            KeyCode::Backspace => {
                if let Some(parent) = browser.current.parent() {
                    browser.current = parent.to_path_buf();
                    browser.refresh()?;
                }
            }
            KeyCode::Enter => {
                let selected = browser.selected_path();
                let metadata = std::fs::symlink_metadata(&selected)?;
                if metadata.file_type().is_symlink() {
                    self.state
                        .messages
                        .push("Symlink selection is not allowed".into());
                } else if metadata.is_dir() {
                    browser.current = selected;
                    browser.refresh()?;
                } else {
                    self.state.input = format!("/ingest {}", selected.to_string_lossy());
                    return Ok(Some(KeyCode::Enter));
                }
            }
            KeyCode::Char('s') => {
                self.state.input = format!("/ingest {}", browser.selected_path().to_string_lossy());
                return Ok(Some(KeyCode::Enter));
            }
            _ => {}
        }
        self.state.picker = Some(browser);
        Ok(None)
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
