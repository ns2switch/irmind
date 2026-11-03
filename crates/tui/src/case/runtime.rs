mod input;
mod presentation;
use super::CaseExit;
use super::demo_guide::DemoEvent;
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
    pub model_tx: mpsc::Sender<irmind_app::ModelProgress>,
    pub model_rx: mpsc::Receiver<irmind_app::ModelProgress>,
    pub seal_tx: mpsc::Sender<irmind_app::SealPreview>,
    pub seal_rx: mpsc::Receiver<irmind_app::SealPreview>,
    pub overrides_active: bool,
    pub modules: &'env [crate::ModuleStatus],
    pub exit_to: CaseExit,
}

impl<'scope> CaseRuntime<'scope, '_, '_> {
    pub(super) fn run(&mut self) -> Result<CaseExit> {
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
                let Ok(progress) = self.model_rx.try_recv() else {
                    break;
                };
                match progress {
                    irmind_app::ModelProgress::RoundStarted { round, limit } => {
                        if self.state.model_preview.is_empty() {
                            self.state.conversation.discard_preview();
                        } else {
                            let safe = self.engine.guard.screen(&self.state.model_preview)?.text;
                            self.state.conversation.set_preview(safe);
                            self.state.conversation.finish_preview();
                        }
                        update(
                            &mut self.state,
                            CaseMessage::ModelRoundStarted { round, limit },
                        );
                        preview_dirty = false;
                    }
                    irmind_app::ModelProgress::TextDelta(delta) => {
                        update(&mut self.state, CaseMessage::ModelDelta(delta));
                        preview_dirty = true;
                    }
                    irmind_app::ModelProgress::ToolProposed(summary) => {
                        let safe = self.engine.guard.screen(&summary)?.text;
                        self.state.conversation.push(
                            super::conversation::Card::new(
                                super::conversation::CardKind::Proposal,
                                safe,
                                "waiting for policy decision",
                                false,
                            )
                            .with_summary("waiting for policy decision"),
                        );
                    }
                }
            }
            if preview_dirty {
                let safe = self.engine.guard.screen(&self.state.model_preview)?.text;
                self.state.conversation.set_preview(safe);
            }
            self.finish_task()?;
            self.refresh()?;
            self.presentation_tick()?;
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
                    Event::Paste(value) => self.handle_paste(&value),
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
        Ok(self.exit_to.clone())
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
            match task.join() {
                Ok(Ok(text)) => self.finish_success(label, text)?,
                Ok(Err(irmind_app::AppError::Cancelled)) => {
                    if label == "Ingest" {
                        self.state.pending_ingest = None;
                    }
                    if label == "IRMind" {
                        self.state.conversation.discard_preview();
                    }
                    self.engine
                        .record_cancellation(self.id, cancelled_operation(label))?;
                    self.presentation_failed("The current action was cancelled and audited");
                    update(
                        &mut self.state,
                        CaseMessage::TaskFinished(format!("{label} cancelled and audited")),
                    );
                }
                Ok(Err(error)) => {
                    if self.finish_task_error(label, &error) {
                        return Ok(());
                    }
                }
                Err(_) => {
                    let message = self.task_failure(label, "unexpected task failure");
                    self.presentation_failed(&message);
                    update(&mut self.state, CaseMessage::TaskFinished(message));
                }
            }
            self.refresh_after_task()?;
        }
        self.state.running_since = None;
        self.state.model_round = None;
        self.state.progress_status = None;
        self.state.demo_pending_event = None;
        Ok(())
    }

    fn finish_task_error(&mut self, label: &str, error: &irmind_app::AppError) -> bool {
        if label == "Ingest" {
            let message = match error {
                irmind_app::AppError::ParserTimeContextRequired {
                    source_name,
                    requirement,
                    suggestions,
                } => {
                    self.state.time_prompt = Some(super::time_prompt::TimePrompt::new(
                        source_name.clone(),
                        requirement.clone(),
                        suggestions.clone(),
                    ));
                    Some("Confirm the source year and fixed UTC offset before ingestion.")
                }
                irmind_app::AppError::ParserSelection {
                    source_name,
                    candidates,
                } => {
                    self.state.parser_prompt = Some(super::state::ParserPrompt {
                        source: source_name.clone(),
                        candidates: candidates.clone(),
                        selected: 0,
                        typed_option: String::new(),
                    });
                    Some("Choose a parser and press Enter, or Esc to cancel.")
                }
                _ => None,
            };
            if let Some(message) = message {
                self.state.overlay_scroll = 0;
                self.state.running_since = None;
                self.state.progress_status = None;
                self.state.demo_pending_event = None;
                update(&mut self.state, CaseMessage::TaskFinished(message.into()));
                return true;
            }
            self.state.pending_ingest = None;
        }
        if label == "IRMind" {
            self.state.conversation.discard_preview();
        }
        let message = self.task_failure(label, &error.to_string());
        self.presentation_failed(&message);
        update(&mut self.state, CaseMessage::TaskFinished(message));
        false
    }

    fn task_failure(&self, label: &str, reason: &str) -> String {
        let retry = if self
            .state
            .demo_guide
            .as_ref()
            .is_some_and(|guide| !guide.hidden())
        {
            "See the current guide step."
        } else {
            "Retry the command or use /help."
        };
        format!("{label} failed: {reason}. {retry}")
    }

    fn refresh_after_task(&mut self) -> Result<()> {
        self.state.case = self.engine.repo.get_case(self.id)?;
        self.state.approvals = self.engine.pending_approvals(self.id)?;
        self.state.approval_sources =
            super::load_approval_sources(self.engine, self.id, &self.state.approvals)?;
        self.state.findings = self.engine.findings(self.id)?;
        self.state.needs_refresh = true;
        Ok(())
    }

    fn finish_success(&mut self, label: &'static str, text: String) -> Result<()> {
        let text = if label == "Ingest" && self.io_ops.demo_mode() {
            super::demo_ingest_result(self.engine, self.id, 1)?
        } else {
            text
        };
        if label == "Ingest" {
            self.state.pending_ingest = None;
        }
        if label == "IRMind" {
            self.state.conversation.discard_preview();
            self.state.pending_final_reply = Some(self.engine.guard.screen(&text)?.text);
        }
        if label == "Prepare seal" {
            let preview = self
                .seal_rx
                .try_recv()
                .map_err(|_| anyhow::anyhow!("signed seal preview was not delivered"))?;
            let summary = seal_confirmation(&preview);
            self.state.confirmation_option = 0;
            self.state.confirmation = Some(Confirmation::Seal(Box::new(preview), summary));
        }
        if label == "Cloud objects" && self.capture_object_listing().is_err() {
            self.state.messages.push(
                "Cloud object listing could not be displayed safely; retry or narrow the prefix"
                    .into(),
            );
        }
        if should_show_completion(label) {
            if is_result_card_label(label)
                && !text.starts_with("approval pending:")
                && !text.starts_with("denied:")
            {
                self.state.result_cards.push((label, text));
            } else {
                update(
                    &mut self.state,
                    CaseMessage::TaskFinished(format!("{label}: {text}")),
                );
            }
        }
        self.record_demo_task(label)?;
        Ok(())
    }

    fn record_demo_task(&mut self, label: &str) -> Result<()> {
        let parser = if label == "Ingest" && self.state.demo_guide.is_some() {
            self.engine
                .audit_log
                .entries(self.id)?
                .into_iter()
                .rev()
                .find(|entry| entry.kind == irmind_app::AuditEventKind::SourceManifestV2)
                .map(|entry| irmind_app::SourceManifestV2::decode(&entry.payload))
                .transpose()
                .map_err(|error| anyhow::anyhow!("Invalid signed demo manifest: {error:?}"))?
                .map(|manifest| (manifest.parser_id, manifest.confidence))
        } else {
            None
        };
        let Some(guide) = self.state.demo_guide.as_mut() else {
            return Ok(());
        };
        if let Some((name, confidence)) = parser {
            guide.record_ingest(&name, confidence);
        }
        let event = match label {
            "IRMind" => Some(DemoEvent::QuestionAnswered),
            "Approval" => Some(DemoEvent::ApprovalResolved),
            "Verify" | "Verify originals" => Some(DemoEvent::CustodyVerified),
            "Seal" => Some(DemoEvent::Sealed),
            "Export" => Some(DemoEvent::Exported),
            "Verify export" => Some(DemoEvent::ExportVerified),
            _ => self.state.demo_pending_event.take(),
        };
        if let Some(event) = event {
            guide.record(event);
        }
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

fn is_result_card_label(label: &str) -> bool {
    matches!(
        label,
        "SIEM alert"
            | "Cloud objects"
            | "Cloud object"
            | "Entity lookup"
            | "Graph neighbors"
            | "Entity timeline"
            | "Graph path"
            | "Evidence search"
            | "Source record"
            | "Case timeline"
    )
}

fn should_show_completion(label: &str) -> bool {
    !matches!(label, "IRMind" | "Cloud objects")
}

#[cfg(test)]
mod completion_tests {
    use super::should_show_completion;

    #[test]
    fn ingest_completion_remains_visible_after_progress_clears() {
        assert!(should_show_completion("Ingest"));
    }
}
