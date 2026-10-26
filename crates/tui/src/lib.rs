#![forbid(unsafe_code)]

mod case;
mod home;
pub mod scripted;
mod setup;
mod workflow;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use irmind_app::{CancellationToken, Engine, LlmPort};
use ratatui::{Terminal, backend::CrosstermBackend};
use secrecy::SecretString;
use std::{
    io,
    path::{Path, PathBuf},
};

pub struct ModuleStatus {
    pub id: String,
    pub compiled: bool,
    pub enabled: bool,
    pub configuration: String,
}

#[derive(Clone)]
pub struct CredentialStatus {
    pub name: String,
    pub present: bool,
}

#[derive(Clone)]
pub struct KeystoreStatus {
    pub signer_backend: String,
    pub secrets_backend: String,
    pub analyst_fingerprint: String,
    pub credentials: Vec<CredentialStatus>,
    pub file_backend_active: bool,
}

pub use setup::{KeystoreChoice, choose_keystore};

/// Filesystem selection is presentation I/O. The composition root supplies the
/// same bounded, no-follow reader used by the noninteractive ingest command.
pub trait WorkspaceIo: Send + Sync {
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>>;
    fn read_evidence(&self, path: &Path) -> Result<Vec<u8>>;
    fn audit_source_name(&self, root: &Path, file: &Path) -> Result<String>;
    fn save_evidence(&self, path: &Path, bytes: &[u8]) -> Result<()>;
    fn verify_export(&self, path: &Path, expected_key: &str) -> Result<String>;
    fn case_exporter(&self) -> &dyn irmind_app::CaseExporter;
    fn keystore_status(&self) -> Result<KeystoreStatus>;
    fn put_credential(&self, name: &str, value: &SecretString) -> Result<()>;
    fn delete_credential(&self, name: &str) -> Result<()>;
    fn change_keystore_passphrase(&self, value: &SecretString) -> Result<()>;
    fn migrate_keystore(
        &self,
        engine: &Engine<'_>,
        capability: &str,
        target: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<()>;
}

struct TerminalSession;

pub(crate) fn prompt_hidden(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    prompt: &str,
) -> Result<SecretString> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    let answer = rpassword::prompt_password(prompt);
    execute!(io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    terminal.clear()?;
    Ok(SecretString::from(answer?))
}

impl TerminalSession {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub fn run_workspace(
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    modules: &[ModuleStatus],
    shutdown: &CancellationToken,
    initial_case: Option<&irmind_app::CaseId>,
    new_analyst_key: bool,
) -> Result<bool> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    home::run_home(
        &mut terminal,
        engine,
        model,
        io_ops,
        modules,
        shutdown,
        home::HomeLaunch {
            initial_case,
            new_analyst_key,
        },
    )
}

/// A startup failure is rendered inside the TUI without constructing an engine.
/// A missing configured backend never triggers a silent backend change.
pub fn show_startup_error(message: &str) -> Result<()> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    home::show_startup_error(&mut terminal, message)
}
