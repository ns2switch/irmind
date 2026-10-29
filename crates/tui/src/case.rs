use crate::{WorkspaceIo, workflow::CaseWorkflow};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, CaseId, Engine, FindingKind, LlmPort, summarize_usage};
use ratatui::widgets::Paragraph;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

mod command_registry;
mod commands;
mod confirmation;
mod conversation;
mod markdown;
mod operation;
mod picker;
mod render;
pub(crate) use render::{approval_panel, entity_panel};
mod runtime;
mod state;
mod view;
pub(crate) use confirmation::escape_display;
use confirmation::{Confirmation, confirmation_summary, seal_confirmation};
use conversation::{Card, CardKind, Conversation};
use operation::{ActiveTask, cancelled_operation, parse_approval_args};
use picker::PathPicker;
use runtime::CaseRuntime;
use state::{CaseState, Focus};
pub(crate) use view::{CaseFrame, draw_case};

struct MouseCapture(bool);

impl MouseCapture {
    fn start(enabled: bool) -> Result<Self> {
        if enabled {
            crossterm::execute!(io::stdout(), crossterm::event::EnableMouseCapture)?;
        }
        Ok(Self(enabled))
    }
}

impl Drop for MouseCapture {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CasePresentation<'a> {
    pub modules: &'a [crate::ModuleStatus],
    pub overrides_active: bool,
    pub mouse_capture: bool,
}

fn initial_state(
    engine: &Engine<'_>,
    id: &CaseId,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
) -> Result<CaseState> {
    let case = engine.repo.get_case(id)?;
    let backend = io_ops.keystore_status()?.signer_backend;
    let case_summary = format!(
        "{} · {}\nModel: {} · Keystore: {}\n/ingest adds evidence · ? opens help",
        case.title,
        case.severity.as_str(),
        model.map_or_else(|| "no model".into(), LlmPort::descriptor),
        backend,
    );
    let mut conversation = Conversation::new(std::env::var_os("NO_COLOR").is_none());
    conversation.push(Card::new(
        CardKind::Welcome,
        concat!("IRMind v", env!("CARGO_PKG_VERSION")),
        engine.guard.screen(&case_summary)?.text,
        false,
    ));
    let approvals = engine.pending_approvals(id)?;
    let approval_sources = load_approval_sources(engine, id, &approvals)?;
    let findings = engine.findings(id)?;
    let (hashes, entries, operations, timeline) = {
        let _case_lock = engine.repo.lock_case(id)?;
        (
            engine.evidence_store.evidence_hashes(id)?,
            engine.audit_log.entries(id)?,
            engine.audit_log.operations(id)?,
            engine.graph.timeline(id, 30)?,
        )
    };
    Ok(CaseState {
        case,
        input: String::new(),
        input_history: Vec::new(),
        history_index: None,
        messages: Vec::new(),
        result_cards: Vec::new(),
        object_listing: Vec::new(),
        object_listing_source: None,
        object_listing_window: None,
        object_listing_after_seq: 0,
        conversation,
        audit_cursor: 0,
        live_reply_cutoff_seq: None,
        pending_final_reply: None,
        usage_cache_seq: 0,
        usage_cache_tokens: 0,
        usage_cache_cost: String::new(),
        turn_detection_count: 0,
        sidebar_visible: false,
        sidebar_scroll: 0,
        overlay_scroll: 0,
        focus: Focus::Composer,
        menu_open: false,
        menu_selected: 0,
        menu_query: None,
        model_preview: String::new(),
        approvals,
        approval_sources,
        findings,
        tab: 0,
        selected_approval: 0,
        approval_option: 0,
        selected_finding: 0,
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
        progress_status: None,
    })
}

pub(crate) fn run_case(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    id: &CaseId,
    shutdown: &CancellationToken,
    presentation: CasePresentation<'_>,
) -> Result<()> {
    verify_case_before_open(terminal, engine, id, shutdown)?;
    let state = initial_state(engine, id, model, io_ops)?;
    let (progress_tx, progress_rx) = mpsc::channel::<String>();
    let (model_tx, model_rx) = mpsc::channel::<irmind_app::ModelProgress>();
    let (seal_tx, seal_rx) = mpsc::channel::<irmind_app::SealPreview>();
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
            model_tx,
            model_rx,
            seal_tx,
            seal_rx,
            overrides_active: presentation.overrides_active,
            modules: presentation.modules,
        };
        let _mouse = MouseCapture::start(presentation.mouse_capture)?;
        runtime.run()
    })
}

fn verify_case_before_open(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    id: &CaseId,
    shutdown: &CancellationToken,
) -> Result<()> {
    let cancel = shutdown.child_token();
    std::thread::scope(|scope| -> Result<()> {
        let worker_cancel = cancel.clone();
        let worker = scope.spawn(move || engine.open_case_verified(id, &worker_cancel));
        let started = Instant::now();
        while !worker.is_finished() {
            terminal.draw(|frame| {
                frame.render_widget(
                    Paragraph::new(format!(
                        "Verifying case before opening · {}s · Esc cancels",
                        started.elapsed().as_secs()
                    )),
                    frame.area(),
                );
            })?;
            if shutdown.is_cancelled() {
                cancel.cancel();
            }
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && (key.code == KeyCode::Esc
                    || key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c'))
            {
                cancel.cancel();
            }
        }
        let verified = worker
            .join()
            .map_err(|_| anyhow::anyhow!("case verification worker failed"))?;
        if matches!(verified, Err(irmind_app::AppError::Cancelled)) {
            engine.record_cancellation(id, irmind_app::CancelledOperation::Verify)?;
        }
        if cancel.is_cancelled() && verified.is_ok() {
            engine.record_cancellation(id, irmind_app::CancelledOperation::Verify)?;
            return Err(irmind_app::AppError::Cancelled.into());
        }
        verified?;
        Ok(())
    })
}

fn load_approval_sources(
    engine: &Engine<'_>,
    id: &CaseId,
    approvals: &[irmind_app::ApprovalRequest],
) -> Result<BTreeMap<String, irmind_app::ApprovalSource>> {
    approvals
        .iter()
        .map(|request| Ok((request.id.clone(), engine.approval_source(id, request)?)))
        .collect()
}
