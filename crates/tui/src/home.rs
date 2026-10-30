use crate::{KeystoreStatus, ModuleKind, ModuleStatus, WorkspaceIo, WorkspaceLaunch, case};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, CaseId, ConfigChange, Engine, LlmPort, hex, sha256};
use ratatui::{
    Terminal,
    backend::Backend,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::Style,
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
    Settings,
    New,
    Model,
    Modules,
    Config,
    Keystore,
    Setup,
    Help,
    VerifyExport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SettingsSection {
    Model,
    Connectors,
    Keystore,
    Preferences,
}

impl SettingsSection {
    const ALL: [Self; 4] = [
        Self::Model,
        Self::Connectors,
        Self::Keystore,
        Self::Preferences,
    ];

    fn mode(self) -> Mode {
        match self {
            Self::Model => Mode::Model,
            Self::Connectors => Mode::Modules,
            Self::Keystore => Mode::Keystore,
            Self::Preferences => Mode::Config,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Model => "AI model",
            Self::Connectors => "Connectors",
            Self::Keystore => "Keystore and credentials",
            Self::Preferences => "Preferences",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "model" => Some(Self::Model),
            "connectors" | "modules" => Some(Self::Connectors),
            "keystore" | "credentials" => Some(Self::Keystore),
            "preferences" | "config" => Some(Self::Preferences),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RemoteScopeStep {
    Local,
    Remote,
}

impl RemoteScopeStep {
    fn is_remote(self) -> bool {
        self == Self::Remote
    }
}

pub(crate) struct HomeState {
    rows: Vec<CaseRow>,
    pub(crate) mode: Mode,
    status_filter: Option<CaseStatus>,
    selected: usize,
    settings_selected: usize,
    settings_return: Mode,
    preference_selected: usize,
    ui_selection: UiSelection,
    theme_choice: String,
    form: [String; 9],
    form_field: usize,
    remote_scope_step: RemoteScopeStep,
    verify_form: [String; 2],
    verify_field: usize,
    notice: String,
    input: String,
    menu_selected: usize,
    menu_query: Option<String>,
    palette_return: Option<Mode>,
    help_return: Mode,
    help_selected: usize,
    confirm_exit: crate::ExitConfirmation,
    selected_option: usize,
    model_setup: model::ModelSetup,
    keystore: Option<KeystoreStatus>,
    keystore_selected: usize,
    keystore_action_selected: usize,
    confirm_credential_delete: bool,
    pending_migration: Option<&'static str>,
    restart_required: bool,
    overrides_active: bool,
    modules: Vec<ModuleStatus>,
    module_selected: usize,
    parameter_selected: usize,
    module_edit: Option<ModuleEdit>,
    pub(crate) pending_module_change: Option<ConfigChange>,
    resume_last_case: crate::ResumeMode,
}

struct UiSelection {
    mouse_capture: bool,
    keystore_action_focus: bool,
    parameter_focused: bool,
}

struct ModuleEdit {
    module: String,
    field: String,
    value: String,
    replace_on_type: bool,
}

impl HomeState {
    pub(crate) fn new(rows: Vec<CaseRow>, show_setup: bool) -> Self {
        Self {
            rows,
            mode: if show_setup { Mode::Setup } else { Mode::List },
            status_filter: None,
            selected: 0,
            settings_selected: 0,
            settings_return: Mode::List,
            preference_selected: 0,
            ui_selection: UiSelection {
                mouse_capture: true,
                keystore_action_focus: false,
                parameter_focused: false,
            },
            theme_choice: "auto".into(),
            form: [
                String::new(),
                "medium".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
            form_field: 0,
            remote_scope_step: RemoteScopeStep::Local,
            verify_form: Default::default(),
            verify_field: 0,
            notice: String::new(),
            input: String::new(),
            menu_selected: 0,
            menu_query: None,
            palette_return: None,
            help_return: Mode::List,
            help_selected: 0,
            confirm_exit: crate::ExitConfirmation::Inactive,
            selected_option: 0,
            model_setup: model::ModelSetup::new(),
            keystore: None,
            keystore_selected: 0,
            keystore_action_selected: 0,
            confirm_credential_delete: false,
            pending_migration: None,
            restart_required: false,
            overrides_active: false,
            modules: Vec::new(),
            module_selected: 0,
            parameter_selected: 0,
            module_edit: None,
            pending_module_change: None,
            resume_last_case: crate::ResumeMode::Enabled,
        }
    }

    pub(crate) fn set_modules(&mut self, modules: &[ModuleStatus]) {
        self.modules = modules.to_vec();
        self.module_selected = module_catalog::ordered(&self.modules)
            .first()
            .map_or(0, |(index, _)| *index);
    }

    fn refresh_keystore(&mut self, io_ops: &dyn WorkspaceIo) {
        match io_ops.keystore_status() {
            Ok(status) => self.keystore = Some(status),
            Err(_) => {
                self.notice = "Keystore status unavailable; use /settings keystore to retry".into();
            }
        }
    }

    fn visible(&self) -> Vec<&CaseRow> {
        let needle = if self.input.starts_with('/') {
            String::new()
        } else {
            self.input.to_lowercase()
        };
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

    fn scope(&self) -> String {
        let [_, _, sources, accounts, projects, hosts, objects, from, to] = &self.form;
        if [sources, accounts, projects, hosts, objects, from, to]
            .iter()
            .all(|part| part.is_empty())
        {
            return "local evidence only".into();
        }
        if objects.is_empty() {
            format!(
                "v2;sources={sources};accounts={accounts};projects={projects};hosts={hosts};from={from};to={to}"
            )
        } else {
            format!(
                "v3;sources={sources};accounts={accounts};projects={projects};hosts={hosts};objects={objects};from={from};to={to}"
            )
        }
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
mod model;
mod module_catalog;
mod modules;
mod new_case;
mod resume;
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
    state.resume_last_case = launch.resume_last_case;
    state.ui_selection.mouse_capture = launch.mouse_capture;
    state.theme_choice = launch.theme.unwrap_or("auto").into();
    state.overrides_active = launch.overrides_active;
    state.refresh_keystore(io_ops);
    {
        let mut startup = StartupCaseView {
            terminal,
            engine,
            model,
            io_ops,
            modules,
            shutdown,
        };
        startup.open(&mut state, launch)?;
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
            mouse_capture: launch.mouse_capture,
            verify_task: None,
            verify_started: None,
            migration_task: None,
            migration_started: None,
            model_probe_task: None,
            model_models_task: None,
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

struct StartupCaseView<'a, 'ports> {
    terminal: &'a mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &'a Engine<'ports>,
    model: Option<&'a dyn LlmPort>,
    io_ops: &'a dyn WorkspaceIo,
    modules: &'a [ModuleStatus],
    shutdown: &'a CancellationToken,
}

impl StartupCaseView<'_, '_> {
    fn open(&mut self, state: &mut HomeState, launch: WorkspaceLaunch<'_>) -> Result<()> {
        if let Some(id) = launch.initial_case {
            let exit = self.run_case(id, false, launch)?;
            apply_case_exit(state, &exit);
            state.rows = load_rows(self.engine)?;
            return Ok(());
        }
        let remembered = if launch.resume_last_case.enabled() && !launch.new_analyst_key {
            self.io_ops.load_last_case()
        } else {
            Ok(None)
        };
        let outcome = resume::attempt(
            &state.rows,
            remembered,
            launch.resume_last_case.enabled(),
            launch.new_analyst_key,
            |id| self.run_case(id, true, launch),
        );
        match outcome {
            resume::ResumeOutcome::Home(Some(notice)) => state.notice = notice,
            resume::ResumeOutcome::Home(None) => {}
            resume::ResumeOutcome::Opened(exit) => {
                apply_case_exit(state, &exit);
                state.rows = load_rows(self.engine)?;
            }
            resume::ResumeOutcome::Failed {
                id,
                notice,
                inconsistent,
            } => {
                state.notice = notice;
                if inconsistent && let Some(row) = state.rows.iter_mut().find(|row| row.id == id) {
                    row.status = CaseStatus::Inconsistent;
                }
            }
        }
        Ok(())
    }

    fn run_case(
        &mut self,
        id: &CaseId,
        resumed: bool,
        launch: WorkspaceLaunch<'_>,
    ) -> Result<case::CaseExit> {
        case::run_case(
            self.terminal,
            self.engine,
            self.model,
            self.io_ops,
            id,
            self.shutdown,
            case::CasePresentation {
                overrides_active: launch.overrides_active,
                modules: self.modules,
                mouse_capture: launch.mouse_capture,
                resumed,
            },
        )
    }
}

pub(super) fn apply_case_exit(state: &mut HomeState, exit: &case::CaseExit) {
    state.mode = match exit {
        case::CaseExit::Home | case::CaseExit::Open(_) | case::CaseExit::Quit => Mode::List,
        case::CaseExit::New => Mode::New,
        case::CaseExit::Settings(section, legacy) => {
            if *legacy {
                state.notice = "Now in /settings".into();
            }
            state.settings_return = Mode::Settings;
            section
                .as_deref()
                .and_then(SettingsSection::parse)
                .map_or(Mode::Settings, SettingsSection::mode)
        }
    };
    if state.mode == Mode::Model {
        state.model_setup = model::ModelSetup::new();
    }
    if let case::CaseExit::Open(name) = exit {
        state.input = format!("/open {name}");
    } else if matches!(exit, case::CaseExit::Quit) {
        state.confirm_exit = crate::ExitConfirmation::Pending;
    }
}

pub(crate) fn show_startup_error(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    message: &str,
) -> Result<bool> {
    let visible = message
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>();
    loop {
        terminal.draw(|frame| {
            let block = Block::default()
                .title(" IRMind startup blocked ")
                .borders(Borders::ALL);
            frame.render_widget(
                Paragraph::new(format!(
                    "Startup needs attention.\n\n{visible}\n\nEnter retries; Esc exits safely."
                ))
                .block(block)
                .wrap(Wrap { trim: false }),
                frame.area(),
            );
        })?;
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Enter => return Ok(true),
                KeyCode::Esc => return Ok(false),
                _ => {}
            }
        }
    }
}
