//! Deterministic driver for the same presentation controller and renderers used
//! by the interactive workspace. It accepts `ratatui::TestBackend` in tests.

use crate::{WorkspaceIo, case, home, workflow::CaseWorkflow};
use anyhow::Result;
use irmind_app::{CancellationToken, CaseId, Engine, LlmPort, Severity};
use ratatui::{Terminal, backend::Backend};
use std::path::Path;

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
                id,
                title: &title,
                messages: &message,
                input: "",
                panel: &panel,
                overlay: None,
                tab: 3,
                tokens: 0,
                cost: "cost n/a",
                pending: self.workflow.engine.pending_approvals(id)?.len(),
                status: "idle",
            },
        )
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
