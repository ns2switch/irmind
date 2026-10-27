use crate::{WorkspaceIo, workflow::CaseWorkflow};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, CaseId, Engine, FindingKind, LlmPort, summarize_usage};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    io,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

mod commands;
mod confirmation;
mod operation;
mod picker;
mod render;
mod runtime;
mod state;
mod view;
pub(crate) use confirmation::escape_display;
use confirmation::{Confirmation, confirmation_summary, seal_confirmation};
use operation::{ActiveTask, cancelled_operation, parse_approval_args};
use picker::PathPicker;
use runtime::CaseRuntime;
use state::CaseState;
pub(crate) use view::{CaseFrame, draw_case};

pub(crate) fn run_case(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    id: &CaseId,
    shutdown: &CancellationToken,
    overrides_active: bool,
) -> Result<()> {
    let case = engine.repo.get_case(id)?;
    let messages = vec![format!(
        "Case: {}\nSeverity: {}\nScope: {}",
        case.title,
        case.severity.as_str(),
        case.scope
    )];
    let approvals = engine.pending_approvals(id)?;
    let findings = engine.findings(id)?;
    let (progress_tx, progress_rx) = mpsc::channel::<String>();
    let (seal_tx, seal_rx) = mpsc::channel::<irmind_app::SealPreview>();
    let (hashes, entries, operations, timeline) = {
        let _case_lock = engine.repo.lock_case(id)?;
        (
            engine.evidence_store.evidence_hashes(id)?,
            engine.audit_log.entries(id)?,
            engine.audit_log.operations(id)?,
            engine.graph.timeline(id, 30)?,
        )
    };
    let state = CaseState {
        case,
        input: String::new(),
        messages,
        approvals,
        findings,
        tab: 0,
        selected_approval: 0,
        palette: None,
        picker: None,
        confirmation: None,
        confirmed_action: None,
        hashes,
        entries,
        operations,
        timeline,
        needs_refresh: false,
        running_since: None,
    };
    std::thread::scope(|scope| {
        let mut runtime = CaseRuntime {
            terminal,
            engine,
            model,
            io_ops,
            id,
            shutdown,
            scope,
            state,
            active: None,
            progress_tx,
            progress_rx,
            seal_tx,
            seal_rx,
            overrides_active,
        };
        runtime.run()
    })
}
