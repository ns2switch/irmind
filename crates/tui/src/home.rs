use crate::{KeystoreStatus, ModuleKind, ModuleStatus, WorkspaceIo, WorkspaceLaunch, case};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, CaseId, ConfigChange, Engine, LlmPort, hex, sha256};
use ratatui::{
    Terminal,
    backend::Backend,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use std::{io, sync::mpsc, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaseStatus {
    Open,
    Sealed,
    Inconsistent,
}

impl CaseStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Inconsistent => "inconsistent",
        }
    }
}

pub(crate) struct CaseRow {
    id: CaseId,
    title: String,
    severity: String,
    status: CaseStatus,
    last_activity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    List,
    Search,
    New,
    Modules,
    Keystore,
    Setup,
    VerifyExport,
}

pub(crate) struct HomeState {
    rows: Vec<CaseRow>,
    pub(crate) mode: Mode,
    search: String,
    status_filter: Option<CaseStatus>,
    selected: usize,
    form: [String; 7],
    form_field: usize,
    verify_form: [String; 2],
    verify_field: usize,
    notice: String,
    keystore: Option<KeystoreStatus>,
    keystore_selected: usize,
    confirm_credential_delete: bool,
    pending_migration: Option<&'static str>,
    restart_required: bool,
    overrides_active: bool,
    modules: Vec<ModuleStatus>,
    module_selected: usize,
    parameter_selected: usize,
    module_edit: Option<ModuleEdit>,
    pub(crate) pending_module_change: Option<ConfigChange>,
}

struct ModuleEdit {
    module: String,
    field: String,
    value: String,
}

impl HomeState {
    pub(crate) fn new(rows: Vec<CaseRow>, show_setup: bool) -> Self {
        Self {
            rows,
            mode: if show_setup { Mode::Setup } else { Mode::List },
            search: String::new(),
            status_filter: None,
            selected: 0,
            form: [
                String::new(),
                "medium".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
            form_field: 0,
            verify_form: Default::default(),
            verify_field: 0,
            notice: String::new(),
            keystore: None,
            keystore_selected: 0,
            confirm_credential_delete: false,
            pending_migration: None,
            restart_required: false,
            overrides_active: false,
            modules: Vec::new(),
            module_selected: 0,
            parameter_selected: 0,
            module_edit: None,
            pending_module_change: None,
        }
    }

    pub(crate) fn set_modules(&mut self, modules: &[ModuleStatus]) {
        self.modules = modules.to_vec();
        self.module_selected = self
            .module_selected
            .min(self.modules.len().saturating_sub(1));
    }

    fn visible(&self) -> Vec<&CaseRow> {
        let needle = self.search.to_lowercase();
        self.rows
            .iter()
            .filter(|row| {
                self.status_filter.is_none_or(|status| row.status == status)
                    && (needle.is_empty()
                        || row.title.to_lowercase().contains(&needle)
                        || row.id.as_str().contains(&needle))
            })
            .collect()
    }

    fn cycle_filter(&mut self) {
        self.status_filter = match self.status_filter {
            None => Some(CaseStatus::Open),
            Some(CaseStatus::Open) => Some(CaseStatus::Sealed),
            Some(CaseStatus::Sealed) => Some(CaseStatus::Inconsistent),
            Some(CaseStatus::Inconsistent) => None,
        };
        self.selected = 0;
    }

    fn scope(&self) -> String {
        let [_, _, sources, accounts, hosts, from, to] = &self.form;
        if [sources, accounts, hosts, from, to]
            .iter()
            .all(|part| part.is_empty())
        {
            return "local evidence only".into();
        }
        format!("v1;sources={sources};accounts={accounts};hosts={hosts};from={from};to={to}")
    }
}

pub(crate) fn load_rows(engine: &Engine<'_>) -> Result<Vec<CaseRow>> {
    let mut rows = Vec::new();
    for case in engine.repo.list_cases()? {
        let entries = engine.audit_log.entries(&case.id)?;
        let operations = engine.audit_log.operations(&case.id)?;
        rows.push(CaseRow {
            id: case.id,
            title: case.title,
            severity: case.severity.as_str().into(),
            status: if case.sealed {
                CaseStatus::Sealed
            } else {
                CaseStatus::Open
            },
            last_activity: entries
                .last()
                .map_or(0, |entry| entry.at)
                .max(operations.last().map_or(0, |entry| entry.at)),
        });
    }
    rows.sort_by(|a, b| {
        b.last_activity
            .cmp(&a.last_activity)
            .then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });
    Ok(rows)
}

pub(crate) fn render_keystore_status<B: Backend>(
    terminal: &mut Terminal<B>,
    engine: &Engine<'_>,
    status: KeystoreStatus,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut state = HomeState::new(Vec::new(), false);
    state.mode = Mode::Keystore;
    state.keystore = Some(status);
    render_home(terminal, &state, engine, &[], None, false)
}

mod render;
pub(crate) use render::render_home;
mod modules;
mod runtime;
mod state;
use runtime::HomeRuntime;
pub(crate) use state::{HomeAction, update};

pub(crate) fn run_home(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    modules: &[ModuleStatus],
    shutdown: &CancellationToken,
    launch: WorkspaceLaunch<'_>,
) -> Result<bool> {
    let mut state = HomeState::new(
        load_rows(engine)?,
        launch.new_analyst_key || engine.repo.list_cases()?.is_empty(),
    );
    state.set_modules(modules);
    state.overrides_active = launch.overrides_active;
    if let Some(id) = launch.initial_case {
        case::run_case(
            terminal,
            engine,
            model,
            io_ops,
            id,
            shutdown,
            launch.overrides_active,
        )?;
        state.rows = load_rows(engine)?;
    }
    let (tx, rx) = mpsc::channel::<(CaseId, CaseStatus)>();
    std::thread::scope(|scope| -> Result<bool> {
        let scan_cancel = shutdown.child_token();
        let rows = state
            .rows
            .iter()
            .map(|row| (row.id.clone(), row.status))
            .collect::<Vec<_>>();
        let worker_cancel = scan_cancel.clone();
        let scanner = scope.spawn(move || -> Result<()> {
            for (id, status) in rows {
                if worker_cancel.is_cancelled() {
                    break;
                }
                let next = match engine.verify_cancelable(&id, &worker_cancel) {
                    Ok(_) => status,
                    Err(irmind_app::AppError::Cancelled) => {
                        engine.record_cancellation(&id, irmind_app::CancelledOperation::Verify)?;
                        break;
                    }
                    Err(_) => CaseStatus::Inconsistent,
                };
                if tx.send((id, next)).is_err() {
                    break;
                }
            }
            Ok(())
        });
        let mut runtime = HomeRuntime {
            terminal,
            engine,
            model,
            io_ops,
            modules,
            shutdown,
            scope,
            state,
            statuses: rx,
            new_analyst_key: launch.new_analyst_key,
            verify_task: None,
            verify_started: None,
            migration_task: None,
            migration_started: None,
            restart_requested: false,
        };
        let outcome = runtime.run();
        scan_cancel.cancel();
        scanner
            .join()
            .map_err(|_| anyhow::anyhow!("case verification worker failed"))??;
        outcome
    })
}

pub(crate) fn show_startup_error(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    message: &str,
) -> Result<()> {
    let visible = message
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>();
    loop {
        terminal.draw(|frame| {
            let block = Block::default().title(" IRMind startup blocked ").borders(Borders::ALL);
            frame.render_widget(Paragraph::new(format!("The selected keystore or local storage is unavailable.\n\n{visible}\n\nNo investigation can start. Press q or Esc to exit.")).block(block).wrap(Wrap { trim: false }), frame.area());
        })?;
        if let Event::Key(key) = event::read()?
            && matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter)
        {
            break;
        }
    }
    Ok(())
}
