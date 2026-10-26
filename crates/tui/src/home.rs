use crate::{
    KeystoreStatus, ModuleStatus, WorkspaceIo, case, prompt_hidden, workflow::CaseWorkflow,
};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, CaseId, Engine, LlmPort, hex, sha256};
use ratatui::{
    Terminal,
    backend::Backend,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use secrecy::ExposeSecret as _;
use std::{
    io,
    sync::mpsc,
    time::{Duration, Instant},
};

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
enum Mode {
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
    mode: Mode,
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
        }
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

pub(crate) fn render_home<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &HomeState,
    engine: &Engine<'_>,
    modules: &[ModuleStatus],
    model: Option<&dyn LlmPort>,
    new_analyst_key: bool,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let fingerprint = hex(&sha256(&engine.signer.public_key()));
    let safe = |value: &str| -> Result<String> { Ok(engine.guard.screen(value)?.text) };
    let rows = state.visible();
    let content = match state.mode {
        Mode::List | Mode::Search => rows
            .iter()
            .enumerate()
            .map(|(index, row)| -> Result<ListItem<'_>> {
                let marker = if index == state.selected { ">" } else { " " };
                let at = i64::try_from(row.last_activity)
                    .ok()
                    .and_then(|at| chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0))
                    .map_or_else(
                        || "unknown".into(),
                        |at| at.format("%Y-%m-%d %H:%M UTC").to_string(),
                    );
                Ok(ListItem::new(safe(&format!(
                    "{marker} {}  {}  {}  {}  {}",
                    row.title,
                    row.severity,
                    row.status.label(),
                    at,
                    row.id.as_str()
                ))?))
            })
            .collect::<Result<Vec<_>>>()?,
        Mode::New => {
            const NAMES: [&str; 7] = [
                "Title",
                "Severity (low/medium/high/critical)",
                "Sources",
                "Accounts",
                "Hosts",
                "From UTC",
                "To UTC",
            ];
            NAMES
                .iter()
                .enumerate()
                .map(|(index, label)| -> Result<ListItem<'_>> {
                    Ok(ListItem::new(safe(&format!(
                        "{} {label}: {}",
                        if index == state.form_field { ">" } else { " " },
                        state.form[index]
                    ))?))
                })
                .collect::<Result<Vec<_>>>()?
        }
        Mode::Modules => modules
            .iter()
            .map(|module| -> Result<ListItem<'_>> {
                Ok(ListItem::new(safe(&format!(
                    "{}  compiled={} enabled={}  {}",
                    module.id, module.compiled, module.enabled, module.configuration
                ))?))
            })
            .collect::<Result<Vec<_>>>()?,
        Mode::Keystore => state.keystore.as_ref().map_or_else(Vec::new, |keystore| {
            let mut items = vec![
                ListItem::new(format!("Signer: {}", keystore.signer_backend)),
                ListItem::new(format!("Secrets: {}", keystore.secrets_backend)),
                ListItem::new(format!("Analyst key: {}", keystore.analyst_fingerprint)),
            ];
            items.extend(
                keystore
                    .credentials
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        ListItem::new(format!(
                            "{} {}: {}",
                            if index == state.keystore_selected {
                                ">"
                            } else {
                                " "
                            },
                            item.name,
                            if item.present { "stored" } else { "missing" }
                        ))
                    }),
            );
            items
        }),
        Mode::VerifyExport => ["Package path", "Expected analyst key fingerprint"]
            .iter()
            .enumerate()
            .map(|(index, label)| {
                ListItem::new(format!(
                    "{} {label}: {}",
                    if index == state.verify_field {
                        ">"
                    } else {
                        " "
                    },
                    case::escape_display(&state.verify_form[index])
                ))
            })
            .collect(),
        Mode::Setup => vec![
            ListItem::new(if new_analyst_key {
                "Signing key: created"
            } else {
                "Signing key: available"
            }),
            ListItem::new(format!("Analyst public-key fingerprint: {fingerprint}")),
            ListItem::new("Save this fingerprint outside this computer before investigating."),
            ListItem::new(if model.is_some() {
                "LLM: explicitly selected"
            } else {
                "LLM: none selected; investigation is disabled"
            }),
            ListItem::new("Press m to inspect compiled modules and missing configuration."),
            ListItem::new("Press k to inspect the active keystore and credentials."),
            ListItem::new("Press n to create a case; no CLI setup is required."),
        ],
    };
    let header = match state.mode {
        Mode::List | Mode::Search => " Cases ",
        Mode::New => " New case ",
        Mode::Modules => " Modules ",
        Mode::Keystore => " Keystore ",
        Mode::Setup => " First-run guide ",
        Mode::VerifyExport => " Verify exported package ",
    };
    let filter = state.status_filter.map_or("all", CaseStatus::label);
    let info = safe(&format!(
        "Search: {} | Filter: {filter} | {}",
        state.search, state.notice
    ))?;
    terminal.draw(|frame| {
        let areas = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());
        frame.render_widget(
            Paragraph::new("IRMind · incident workspace")
                .block(Block::default().borders(Borders::ALL)),
            areas[0],
        );
        frame.render_widget(
            List::new(content).block(Block::default().title(header).borders(Borders::ALL)),
            areas[1],
        );
        frame.render_widget(
            Paragraph::new(info)
                .block(Block::default().borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            areas[2],
        );
        let help = help_line(state);
        frame.render_widget(
            Paragraph::new(Line::from(help)).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            areas[3],
        );
    })?;
    Ok(())
}

fn help_line(state: &HomeState) -> &'static str {
    match state.mode {
        Mode::List => {
            "Enter open · n new · / search · f filter · v verify export · m modules · k keystore · ? setup · q quit"
        }
        Mode::Search => "Type to search · Enter apply · Esc cancel",
        Mode::New => {
            "Tab next field · Enter create · Esc cancel · sources, accounts, hosts: comma-separated"
        }
        Mode::Modules | Mode::Setup => "Esc back · n new case · m modules · q quit",
        Mode::Keystore => {
            if state.confirm_credential_delete {
                "Delete selected credential? y confirm · Esc cancel"
            } else if state.pending_migration.is_some() {
                "Copy to the other backend and sign the event? y confirm · Esc cancel"
            } else if state.restart_required {
                "r restart session · active connectors may still hold old credentials · Esc back"
            } else {
                "Up/Down select · a add/replace · d delete · p passphrase · s migrate signer · x migrate secrets · Esc"
            }
        }
        Mode::VerifyExport => {
            "Tab switch field · Enter verify · Esc back; expected key is mandatory"
        }
    }
}

#[cfg(test)]
mod help_tests {
    use super::{HomeState, Mode, help_line};

    #[test]
    fn keystore_offers_session_restart_after_credentials_change() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Keystore;
        assert!(!help_line(&state).contains("restart session"));
        state.restart_required = true;
        assert!(help_line(&state).contains("r restart session"));
        assert!(help_line(&state).contains("active connectors"));
    }
}

#[derive(Clone, Copy)]
pub(crate) struct HomeLaunch<'a> {
    pub initial_case: Option<&'a CaseId>,
    pub new_analyst_key: bool,
}

pub(crate) fn run_home(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    modules: &[ModuleStatus],
    shutdown: &CancellationToken,
    launch: HomeLaunch<'_>,
) -> Result<bool> {
    let workflow = CaseWorkflow {
        engine,
        model,
        io_ops,
    };
    let mut state = HomeState::new(
        load_rows(engine)?,
        launch.new_analyst_key || engine.repo.list_cases()?.is_empty(),
    );
    if let Some(id) = launch.initial_case {
        case::run_case(terminal, engine, model, io_ops, id, shutdown)?;
        state.rows = load_rows(engine)?;
    }
    let (tx, rx) = mpsc::channel::<(CaseId, CaseStatus)>();
    let mut restart_requested = false;
    std::thread::scope(|scope| -> Result<()> {
        let mut verify_task: Option<std::thread::ScopedJoinHandle<'_, Result<String>>> = None;
        let mut verify_started: Option<Instant> = None;
        let mut migration_task: Option<std::thread::ScopedJoinHandle<'_, Result<String>>> = None;
        let mut migration_started: Option<Instant> = None;
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
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            if verify_task
                .as_ref()
                .is_some_and(std::thread::ScopedJoinHandle::is_finished)
                && let Some(task) = verify_task.take()
            {
                state.notice = match task.join() {
                    Ok(Ok(message)) => message,
                    Ok(Err(_)) => {
                        "Export verification failed: check the package and expected key".into()
                    }
                    Err(_) => "Export verification worker failed".into(),
                };
                verify_started = None;
                state.mode = Mode::List;
            }
            if let Some(started) = verify_started {
                state.notice = format!(
                    "Verifying export · {}s elapsed",
                    started.elapsed().as_secs()
                );
            }
            if migration_task
                .as_ref()
                .is_some_and(std::thread::ScopedJoinHandle::is_finished)
                && let Some(task) = migration_task.take()
            {
                state.notice = match task.join() {
                    Ok(Ok(message)) => {
                        state.restart_required = true;
                        message
                    }
                    Ok(Err(error)) => format!("Keystore migration failed: {error}"),
                    Err(_) => "Keystore migration worker failed".into(),
                };
                migration_started = None;
                state.keystore = Some(io_ops.keystore_status()?);
            }
            if let Some(started) = migration_started {
                state.notice = format!(
                    "Migrating keystore · {}s elapsed",
                    started.elapsed().as_secs()
                );
            }
            while let Ok((id, status)) = rx.try_recv() {
                if let Some(row) = state.rows.iter_mut().find(|row| row.id == id) {
                    row.status = status;
                }
            }
            render_home(
                terminal,
                &state,
                engine,
                modules,
                model,
                launch.new_analyst_key,
            )?;
            if !event::poll(Duration::from_millis(100))? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if migration_task.is_some() {
                continue;
            }
            if state.restart_required
                && matches!(state.mode, Mode::List | Mode::Setup | Mode::Modules)
                && matches!(key.code, KeyCode::Enter | KeyCode::Char('n'))
            {
                state.notice =
                    "Restart IRMind before opening a case so changed credentials take effect"
                        .into();
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                break;
            }
            match state.mode {
                Mode::List => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('n') => {
                        state.form = HomeState::new(Vec::new(), false).form;
                        state.form_field = 0;
                        state.mode = Mode::New;
                    }
                    KeyCode::Char('/') => state.mode = Mode::Search,
                    KeyCode::Char('f') => state.cycle_filter(),
                    KeyCode::Char('m') => state.mode = Mode::Modules,
                    KeyCode::Char('k') => {
                        state.keystore = Some(io_ops.keystore_status()?);
                        state.keystore_selected = 0;
                        state.mode = Mode::Keystore;
                    }
                    KeyCode::Char('v') => {
                        state.verify_form = Default::default();
                        state.verify_field = 0;
                        state.mode = Mode::VerifyExport;
                    }
                    KeyCode::Char('?') => state.mode = Mode::Setup,
                    KeyCode::Up => state.selected = state.selected.saturating_sub(1),
                    KeyCode::Down => {
                        state.selected =
                            (state.selected + 1).min(state.visible().len().saturating_sub(1));
                    }
                    KeyCode::Enter => {
                        if let Some(row) = state.visible().get(state.selected) {
                            let id = row.id.clone();
                            case::run_case(terminal, engine, model, io_ops, &id, shutdown)?;
                            state.rows = load_rows(engine)?;
                            state.notice = "Returned to case list".into();
                        }
                    }
                    _ => {}
                },
                Mode::Search => match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        state.mode = Mode::List;
                        state.selected = 0;
                    }
                    KeyCode::Backspace => {
                        state.search.pop();
                        state.selected = 0;
                    }
                    KeyCode::Char(ch) if state.search.len() < 200 => {
                        state.search.push(ch);
                        state.selected = 0;
                    }
                    _ => {}
                },
                Mode::New => match key.code {
                    KeyCode::Esc => state.mode = Mode::List,
                    KeyCode::Tab => state.form_field = (state.form_field + 1) % state.form.len(),
                    KeyCode::BackTab => {
                        state.form_field =
                            (state.form_field + state.form.len() - 1) % state.form.len();
                    }
                    KeyCode::Backspace => {
                        state.form[state.form_field].pop();
                    }
                    KeyCode::Char(ch) if state.form[state.form_field].len() < 200 => {
                        state.form[state.form_field].push(ch);
                    }
                    KeyCode::Enter => {
                        let scope_text = state.scope();
                        let severity = irmind_app::Severity::parse(&state.form[1]);
                        let result = severity
                            .map_err(|_| {
                                "severity must be low, medium, high or critical".to_owned()
                            })
                            .and_then(|severity| {
                                workflow
                                    .create_case(&state.form[0], severity, &scope_text)
                                    .map_err(|error| error.to_string())
                            });
                        match result {
                            Ok(case_id) => {
                                state.rows = load_rows(engine)?;
                                state.mode = Mode::List;
                                state.notice = format!("Created signed case {}", case_id.as_str());
                                case::run_case(
                                    terminal, engine, model, io_ops, &case_id, shutdown,
                                )?;
                                state.rows = load_rows(engine)?;
                            }
                            Err(error) => state.notice = format!("Case creation failed: {error}"),
                        }
                    }
                    _ => {}
                },
                Mode::VerifyExport => {
                    if verify_task.is_some() {
                        continue;
                    }
                    match key.code {
                        KeyCode::Esc => state.mode = Mode::List,
                        KeyCode::Tab => state.verify_field = (state.verify_field + 1) % 2,
                        KeyCode::Backspace => {
                            state.verify_form[state.verify_field].pop();
                        }
                        KeyCode::Char(ch) if state.verify_form[state.verify_field].len() < 4096 => {
                            state.verify_form[state.verify_field].push(ch);
                        }
                        KeyCode::Enter => {
                            let path = std::path::PathBuf::from(&state.verify_form[0]);
                            let fingerprint = state.verify_form[1].clone();
                            if path.as_os_str().is_empty()
                                || fingerprint.len() != 64
                                || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
                            {
                                state.notice =
                                    "Enter a package path and 64-character key fingerprint".into();
                            } else {
                                verify_task = Some(
                                    scope.spawn(move || io_ops.verify_export(&path, &fingerprint)),
                                );
                                verify_started = Some(Instant::now());
                            }
                        }
                        _ => {}
                    }
                }
                Mode::Modules | Mode::Setup => match key.code {
                    KeyCode::Esc => state.mode = Mode::List,
                    KeyCode::Char('m') => state.mode = Mode::Modules,
                    KeyCode::Char('k') => {
                        state.keystore = Some(io_ops.keystore_status()?);
                        state.mode = Mode::Keystore;
                    }
                    KeyCode::Char('n') => {
                        state.form = HomeState::new(Vec::new(), false).form;
                        state.mode = Mode::New;
                    }
                    KeyCode::Char('q') => break,
                    _ => {}
                },
                Mode::Keystore => {
                    if key.code == KeyCode::Char('r') && state.restart_required {
                        restart_requested = true;
                        break;
                    }
                    if let Some(capability) = state.pending_migration {
                        match key.code {
                            KeyCode::Esc => state.pending_migration = None,
                            KeyCode::Char('y') => {
                                if let Some(status) = state.keystore.as_ref() {
                                    let current = if capability == "signer" {
                                        &status.signer_backend
                                    } else {
                                        &status.secrets_backend
                                    };
                                    let target = if current == "os" { "file" } else { "os" };
                                    let needs_phrase =
                                        target == "file" && !status.file_backend_active;
                                    let phrase = if needs_phrase {
                                        Some(prompt_hidden(
                                            terminal,
                                            "Target file keystore passphrase (input hidden): ",
                                        )?)
                                    } else {
                                        None
                                    };
                                    migration_task = Some(scope.spawn(move || {
                                        io_ops.migrate_keystore(engine, capability, target, phrase.as_ref())?;
                                        Ok(format!("{capability} copied to {target}; restart IRMind to activate it"))
                                    }));
                                    migration_started = Some(Instant::now());
                                }
                                state.pending_migration = None;
                            }
                            _ => {}
                        }
                        continue;
                    }
                    if state.confirm_credential_delete {
                        match key.code {
                            KeyCode::Esc => state.confirm_credential_delete = false,
                            KeyCode::Char('y') => {
                                if let Some(name) = state
                                    .keystore
                                    .as_ref()
                                    .and_then(|item| item.credentials.get(state.keystore_selected))
                                    .map(|item| item.name.clone())
                                {
                                    state.restart_required = true;
                                    state.notice = match io_ops.delete_credential(&name) {
                                        Ok(()) => {
                                            format!(
                                                "Deleted {name}. Active connectors may still use it; press r to restart this session"
                                            )
                                        }
                                        Err(error) => {
                                            format!("Credential deletion failed: {error}")
                                        }
                                    };
                                    state.keystore = Some(io_ops.keystore_status()?);
                                }
                                state.confirm_credential_delete = false;
                            }
                            _ => {}
                        }
                        continue;
                    }
                    match key.code {
                        KeyCode::Esc => state.mode = Mode::List,
                        KeyCode::Up => {
                            state.keystore_selected = state.keystore_selected.saturating_sub(1);
                        }
                        KeyCode::Down => {
                            let count = state
                                .keystore
                                .as_ref()
                                .map_or(0, |item| item.credentials.len());
                            state.keystore_selected =
                                (state.keystore_selected + 1).min(count.saturating_sub(1));
                        }
                        KeyCode::Char('a') => {
                            if let Some((name, replacing)) = state
                                .keystore
                                .as_ref()
                                .and_then(|item| item.credentials.get(state.keystore_selected))
                                .map(|item| (item.name.clone(), item.present))
                            {
                                let value =
                                    prompt_hidden(terminal, &format!("{name} (input hidden): "))?;
                                state.restart_required = true;
                                state.notice = match io_ops.put_credential(&name, &value) {
                                    Ok(()) => {
                                        if replacing {
                                            format!(
                                                "Replaced {name}. Active connectors still use the previous credential; press r to restart this session"
                                            )
                                        } else {
                                            format!(
                                                "Saved {name}. Restart the session with r to activate the credential"
                                            )
                                        }
                                    }
                                    Err(error) => format!("Credential update failed: {error}"),
                                };
                                state.keystore = Some(io_ops.keystore_status()?);
                            }
                        }
                        KeyCode::Char('d') => state.confirm_credential_delete = true,
                        KeyCode::Char('s') => {
                            state.pending_migration = Some("signer");
                            state.notice = "Copy the analyst key to the other backend; its fingerprint must remain unchanged".into();
                        }
                        KeyCode::Char('x') => {
                            state.pending_migration = Some("secrets");
                            state.notice = "Copy module credentials to the other backend; source credentials remain".into();
                        }
                        KeyCode::Char('p')
                            if state
                                .keystore
                                .as_ref()
                                .is_some_and(|item| item.file_backend_active) =>
                        {
                            let value = prompt_hidden(
                                terminal,
                                "New file keystore passphrase (input hidden): ",
                            )?;
                            let repeated =
                                prompt_hidden(terminal, "Repeat new passphrase (input hidden): ")?;
                            state.notice = if value.expose_secret() == repeated.expose_secret() {
                                match io_ops.change_keystore_passphrase(&value) {
                                    Ok(()) => "File keystore passphrase changed".into(),
                                    Err(error) => format!("Passphrase change failed: {error}"),
                                }
                            } else {
                                "Passphrases differ; the keystore was not changed".into()
                            };
                        }
                        _ => {}
                    }
                }
            }
        }
        scan_cancel.cancel();
        scanner
            .join()
            .map_err(|_| anyhow::anyhow!("case verification worker failed"))??;
        Ok(())
    })?;
    Ok(restart_requested)
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
