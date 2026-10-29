//! Deterministic driver for the same presentation controller and renderers used
//! by the interactive workspace. It accepts `ratatui::TestBackend` in tests.

use crate::{KeystoreChoice, ModuleStatus, WorkspaceIo, case, home, setup, workflow::CaseWorkflow};
use anyhow::Result;
use crossterm::event::KeyCode;
use irmind_app::{
    CancellationToken, CaseId, Engine, EntityDetails, FindingKind, LlmPort, Severity,
};
use ratatui::{Terminal, backend::Backend};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

pub fn render_keystore_setup<B: Backend>(
    terminal: &mut Terminal<B>,
    os_available: bool,
) -> Result<KeystoreChoice>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let choice = KeystoreChoice::initial(os_available, true)?;
    setup::render(
        terminal,
        &setup::KeystoreWizard::new(None, os_available, true, false),
    )?;
    Ok(choice)
}

pub struct ScriptedWorkspace<'a, 'ports, B: Backend> {
    terminal: Terminal<B>,
    workflow: CaseWorkflow<'a, 'ports>,
}

impl<'a, 'ports, B: Backend> ScriptedWorkspace<'a, 'ports, B>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    pub fn new(
        terminal: Terminal<B>,
        engine: &'a Engine<'ports>,
        model: Option<&'a dyn LlmPort>,
        io_ops: &'a dyn WorkspaceIo,
    ) -> Self {
        Self {
            terminal,
            workflow: CaseWorkflow {
                engine,
                model,
                io_ops,
            },
        }
    }

    pub fn terminal(&self) -> &Terminal<B> {
        &self.terminal
    }

    pub fn select_model(&mut self, model: &'a dyn LlmPort) {
        self.workflow.model = Some(model);
    }

    pub fn drive_module_screen(
        &mut self,
        modules: &[ModuleStatus],
        keys: &[KeyCode],
    ) -> Result<bool> {
        let mut state = home::HomeState::new(home::load_rows(self.workflow.engine)?, false);
        state.set_modules(modules);
        state.mode = home::Mode::Modules;
        for key in keys {
            home::render_home(
                &mut self.terminal,
                &state,
                self.workflow.engine,
                modules,
                self.workflow.model,
                false,
            )?;
            if let home::HomeAction::ChangeModule(change, confirmed) =
                home::update(&mut state, *key)
            {
                match self.workflow.io_ops.change_module_configuration(
                    self.workflow.engine,
                    change.clone(),
                    confirmed,
                ) {
                    Ok(changed) if changed => return Ok(true),
                    Ok(_) => {}
                    Err(error)
                        if error
                            .downcast_ref::<irmind_app::AppError>()
                            .is_some_and(|error| {
                                matches!(error, irmind_app::AppError::Fixed(
                            irmind_app::FixedAppError::PolicyConfigurationConfirmationRequired
                        ))
                            }) =>
                    {
                        state.pending_module_change = Some(change);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        home::render_home(
            &mut self.terminal,
            &state,
            self.workflow.engine,
            modules,
            self.workflow.model,
            false,
        )?;
        Ok(false)
    }

    pub fn render_home(&mut self) -> Result<()> {
        let state = home::HomeState::new(home::load_rows(self.workflow.engine)?, false);
        home::render_home(
            &mut self.terminal,
            &state,
            self.workflow.engine,
            &[],
            self.workflow.model,
            false,
        )
    }

    pub fn render_keystore(&mut self) -> Result<()> {
        home::render_keystore_status(
            &mut self.terminal,
            self.workflow.engine,
            self.workflow.io_ops.keystore_status()?,
        )
    }

    pub fn render_case(&mut self, id: &CaseId, message: &str) -> Result<()> {
        let case = self.workflow.engine.repo.get_case(id)?;
        let guard = self.workflow.engine.guard.as_ref();
        let title = guard.screen(&case.title)?.text;
        let message = guard.screen(message)?.text;
        let panel = guard
            .screen(&format!(
                "Severity: {}\nSealed: {}",
                case.severity.as_str(),
                case.sealed
            ))?
            .text;
        case::draw_case(
            &mut self.terminal,
            &case::CaseFrame {
                title: &title,
                messages: &message,
                visible_lines: None,
                input: "",
                input_focused: false,
                panel: &panel,
                overlay: None,
                menu: None,
                tab: 3,
                sidebar_visible: true,
                sidebar_scroll: 0,
                overlay_scroll: 0,
                new_content: false,
                model: "no model",
                tokens: 0,
                cost: "cost n/a",
                pending: self.workflow.engine.pending_approvals(id)?.len(),
                detections: 0,
                status: "idle",
            },
        )
    }

    pub fn render_entity_panel(&mut self, id: &CaseId, kind: FindingKind) -> Result<String> {
        let tab = match kind {
            FindingKind::Ioc => 5,
            FindingKind::Hypothesis => 6,
            FindingKind::Technique => 7,
            _ => 8,
        };
        let findings = self.workflow.engine.findings(id)?;
        let text = case::entity_panel(&findings, tab, 0);
        self.render_detail_panel(id, tab, &text)?;
        Ok(text)
    }

    pub fn render_model_preview(&mut self, id: &CaseId, preview: &str) -> Result<()> {
        let safe = self.workflow.engine.guard.screen(preview)?.text;
        self.render_detail_panel(id, 3, &format!("IRMind (streaming): {safe}"))
    }

    pub fn render_approval_panel(&mut self, id: &CaseId) -> Result<String> {
        let approvals = self.workflow.engine.pending_approvals(id)?;
        let sources = approvals
            .iter()
            .map(|request| {
                self.workflow
                    .engine
                    .approval_source(id, request)
                    .map(|source| (request.id.clone(), source))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let text = case::approval_panel(&approvals, &sources, 0);
        self.render_detail_panel(id, 4, &text)?;
        Ok(text)
    }

    fn render_detail_panel(&mut self, id: &CaseId, tab: usize, text: &str) -> Result<()> {
        let case = self.workflow.engine.repo.get_case(id)?;
        let guard = self.workflow.engine.guard.as_ref();
        let title = guard.screen(&case.title)?.text;
        let panel = guard.screen(text)?.text;
        case::draw_case(
            &mut self.terminal,
            &case::CaseFrame {
                title: &title,
                messages: "",
                visible_lines: None,
                input: "",
                input_focused: false,
                panel: &panel,
                overlay: None,
                menu: None,
                tab,
                sidebar_visible: true,
                sidebar_scroll: 0,
                overlay_scroll: 0,
                new_content: false,
                model: "no model",
                tokens: 0,
                cost: "cost n/a",
                pending: self.workflow.engine.pending_approvals(id)?.len(),
                detections: 0,
                status: "idle",
            },
        )
    }

    pub fn propose_entity(
        &self,
        id: &CaseId,
        kind: FindingKind,
        value: &str,
        evidence_hash: &str,
        details: EntityDetails,
    ) -> Result<String> {
        Ok(self
            .workflow
            .engine
            .add_entity(id, kind, value, evidence_hash, details)?)
    }

    pub fn confirm_finding(&self, id: &CaseId, finding_id: &str) -> Result<()> {
        Ok(self.workflow.engine.confirm_finding(id, finding_id)?)
    }

    pub fn report(&self, id: &CaseId) -> Result<String> {
        Ok(self.workflow.engine.report(id)?)
    }

    pub fn create_case(&self, title: &str, severity: Severity, scope: &str) -> Result<CaseId> {
        Ok(self.workflow.create_case(title, severity, scope)?)
    }

    pub fn ingest_path(&self, id: &CaseId, path: &Path) -> Result<usize> {
        Ok(self
            .workflow
            .ingest_path(id, path, &CancellationToken::new(), |_, _, _| {})?)
    }

    pub fn investigate(&self, id: &CaseId, alert: &str) -> Result<String> {
        Ok(self
            .workflow
            .investigate(id, alert, &CancellationToken::new())?)
    }

    pub fn investigate_with_deltas(
        &self,
        id: &CaseId,
        alert: &str,
    ) -> Result<(String, Vec<String>)> {
        let deltas = Mutex::new(Vec::new());
        let response = self.workflow.investigate_with_progress(
            id,
            alert,
            &CancellationToken::new(),
            &|part| {
                if let Ok(mut output) = deltas.lock() {
                    output.push(part.to_owned());
                }
            },
        )?;
        Ok((response, deltas.into_inner()?))
    }

    pub fn pending_approval_ids(&self, id: &CaseId) -> Result<Vec<String>> {
        Ok(self
            .workflow
            .engine
            .pending_approvals(id)?
            .into_iter()
            .map(|approval| approval.id)
            .collect())
    }

    pub fn approve(&self, id: &CaseId, request_id: &str) -> Result<String> {
        Ok(self
            .workflow
            .approve(id, request_id, &CancellationToken::new())?)
    }

    pub fn verify(&self, id: &CaseId) -> Result<usize> {
        Ok(self.workflow.verify(id, &CancellationToken::new())?)
    }

    pub fn seal(&self, id: &CaseId) -> Result<()> {
        Ok(self.workflow.seal(id)?)
    }

    pub fn export(&self, id: &CaseId, path: &Path) -> Result<String> {
        Ok(self.workflow.export(id, path, &CancellationToken::new())?)
    }

    pub fn verify_export(&self, path: &Path, expected_key: &str) -> Result<String> {
        self.workflow.io_ops.verify_export(path, expected_key)
    }
}
