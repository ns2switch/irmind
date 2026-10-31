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

pub(crate) mod command_registry;
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

#[derive(Clone)]
pub(crate) enum CaseExit {
    Home,
    New,
    Settings(Option<String>, bool),
    Quit,
    Open(String),
}

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
    pub resumed: bool,
}

fn initial_state(
    engine: &Engine<'_>,
    id: &CaseId,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    resumed: bool,
) -> Result<CaseState> {
    let case = engine.repo.get_case(id)?;
    let backend = io_ops.keystore_status()?.signer_backend;
    let mut case_summary = welcome_summary(&case, model, &backend, resumed);
    if io_ops.demo_mode() {
        case_summary.insert_str(0, "Demo · synthetic data · deleted on exit\n");
    }
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
            graph_timeline_or_notice(engine, id, &mut conversation)?,
        )
    };
    Ok(CaseState {
        case,
        input: String::new(),
        confirm_exit: crate::ExitConfirmation::Inactive,
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
        model_round: None,
        approvals,
        approval_sources,
        findings,
        tab: 0,
        selected_approval: 0,
        approval_option: 0,
        confirmation_option: 0,
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

fn graph_timeline_or_notice(
    engine: &Engine<'_>,
    id: &CaseId,
    conversation: &mut Conversation,
) -> Result<Vec<irmind_app::TimelineEvent>> {
    match engine.graph.timeline(id, 30) {
        Ok(events) => Ok(events),
        Err(irmind_app::AppError::Policy(reason))
            if reason.starts_with("derived graph is unavailable until legacy evidence") =>
        {
            conversation.push(Card::new(
                CardKind::Notice,
                "",
                "This case has an old derived index. Use /migrate to rebuild Parquet from its original evidence. If originals are unavailable, the signed case history remains readable without graph queries.",
                false,
            ));
            Ok(Vec::new())
        }
        Err(error) => Err(error.into()),
    }
}

fn welcome_summary(
    case: &irmind_app::Case,
    model: Option<&dyn LlmPort>,
    backend: &str,
    resumed: bool,
) -> String {
    format!(
        "{} · {}\nModel: {} · Keystore: {}\n/ingest adds evidence · /help opens help{}",
        case.title,
        case.severity.as_str(),
        model.map_or_else(|| "no model".into(), LlmPort::descriptor),
        backend,
        if resumed {
            "\nResumed · /home to view all cases"
        } else {
            ""
        },
    )
}

pub(crate) fn run_case(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    id: &CaseId,
    shutdown: &CancellationToken,
    presentation: CasePresentation<'_>,
) -> Result<CaseExit> {
    if let Some(reason) = verify_case_before_open(terminal, engine, id, shutdown)? {
        return run_signed_history_only(terminal, engine, id, shutdown, &reason);
    }
    let mut state = initial_state(engine, id, model, io_ops, presentation.resumed)?;
    if io_ops.remember_last_case(id).is_err() {
        state.conversation.push(Card::new(
            CardKind::Notice,
            "",
            "Recent case could not be saved locally; this case is still verified.",
            false,
        ));
    }
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
            exit_to: CaseExit::Home,
        };
        let _mouse = MouseCapture::start(presentation.mouse_capture)?;
        if let Some(path) = io_ops.demo_initial_ingest() {
            let workflow = CaseWorkflow {
                engine,
                model,
                io_ops,
            };
            let progress = runtime.progress_tx.clone();
            runtime.start_task("Ingest", move |cancel| {
                workflow
                    .ingest_path(id, &path, &cancel, |done, count, source| {
                        let _ = progress.send(format!("Demo evidence {done}/{count}: {source}"));
                    })
                    .map(|count| format!("Ingested {count} synthetic file"))
            });
        }
        runtime.run()
    })
}

fn verify_case_before_open(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    id: &CaseId,
    shutdown: &CancellationToken,
) -> Result<Option<String>> {
    let cancel = shutdown.child_token();
    std::thread::scope(|scope| -> Result<Option<String>> {
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
        match verified {
            Ok(_) => Ok(None),
            Err(error) => {
                engine.inspect_signed_chain_only(id, &cancel)?;
                Ok(Some(engine.guard.screen(&error.to_string())?.text))
            }
        }
    })
}

fn run_signed_history_only(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    id: &CaseId,
    shutdown: &CancellationToken,
    reason: &str,
) -> Result<CaseExit> {
    let case = engine.repo.get_case(id)?;
    let title = engine.guard.screen(&case.title)?.text;
    let entries = engine.audit_log.entries(id)?;
    let mut offset = 0usize;
    let mut confirm_exit = false;
    loop {
        terminal.draw(|frame| {
            let visible = usize::from(frame.area().height).saturating_sub(5);
            let mut lines = vec![
                format!("IRMind · Signed history · {title}"),
                format!("Original evidence unavailable or changed: {reason}"),
                "Read-only view. Graph queries and case actions are disabled.".into(),
            ];
            lines.extend(entries.iter().skip(offset).take(visible).map(|entry| {
                let hash = irmind_app::hex(&entry.hash);
                format!(
                    "{:>6}  {:<24}  {}…{}",
                    entry.seq,
                    entry.kind.as_str(),
                    &hash[..8],
                    &hash[57..]
                )
            }));
            lines.push(if confirm_exit {
                "Exit IRMind? Enter confirms · Esc stays".into()
            } else {
                "PgUp/PgDn scroll · Esc returns home · Ctrl+C exits".into()
            });
            frame.render_widget(Paragraph::new(lines.join("\n")), frame.area());
        })?;
        if shutdown.is_cancelled() {
            return Ok(CaseExit::Home);
        }
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if confirm_exit {
            match key.code {
                KeyCode::Enter => return Ok(CaseExit::Quit),
                KeyCode::Esc => confirm_exit = false,
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Esc => return Ok(CaseExit::Home),
            KeyCode::PageUp => offset = offset.saturating_sub(20),
            KeyCode::PageDown => offset = (offset + 20).min(entries.len().saturating_sub(1)),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                confirm_exit = true;
            }
            _ => {}
        }
    }
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
