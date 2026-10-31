#![forbid(unsafe_code)]

mod case;
mod demo_choice;
mod home;
mod menu_layout;
pub mod scripted;
mod setup;
mod startup_review;
mod theme;
mod workflow;

use anyhow::Result;
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste},
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExitConfirmation {
    Inactive,
    Pending,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ModuleKind {
    Llm,
    Connector,
    Local,
    Keystore,
}

#[derive(Clone)]
pub struct ModuleParameter {
    pub name: String,
    pub value: String,
    pub defaulted: bool,
    pub required: bool,
    pub overridden: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ModuleSelectionSource {
    Persistent,
    Override,
}

#[derive(Clone)]
pub struct ModuleStatus {
    pub id: String,
    pub compiled: bool,
    pub enabled: bool,
    pub configuration: String,
    pub kind: ModuleKind,
    pub selected: bool,
    pub selection_source: ModuleSelectionSource,
    pub parameters: Vec<ModuleParameter>,
    pub credentials: Vec<String>,
    pub missing: Vec<String>,
}

impl ModuleStatus {
    #[must_use]
    pub fn selection_overridden(&self) -> bool {
        self.selection_source == ModuleSelectionSource::Override
    }
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

pub use demo_choice::choose_demo_model;
pub use setup::{KeystoreChoice, KeystoreWizard, run_keystore_wizard};
pub use startup_review::{
    ConfigurationRecoveryChoice, OverrideReviewEntry, resolve_configuration_review,
    resolve_override_review,
};

#[derive(Clone, Copy)]
pub struct WorkspaceLaunch<'a> {
    pub initial_case: Option<&'a irmind_app::CaseId>,
    pub resume_last_case: ResumeMode,
    pub new_analyst_key: bool,
    pub overrides_active: bool,
    pub mouse_capture: bool,
    pub theme: Option<&'a str>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ResumeMode {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceOutcome {
    Exit,
    Restart,
    Demo,
}

impl ResumeMode {
    #[must_use]
    pub fn enabled(self) -> bool {
        self == Self::Enabled
    }
}

impl From<bool> for ResumeMode {
    fn from(value: bool) -> Self {
        if value { Self::Enabled } else { Self::Disabled }
    }
}

/// Filesystem selection is presentation I/O. The composition root supplies the
/// same bounded, no-follow reader used by the noninteractive ingest command.
pub trait WorkspaceIo: Send + Sync {
    fn demo_mode(&self) -> bool {
        false
    }
    fn demo_initial_ingest(&self) -> Option<PathBuf> {
        None
    }
    fn demo_check(&self, _engine: &Engine<'_>, _id: &irmind_app::CaseId) -> Result<Option<String>> {
        Ok(None)
    }
    fn load_last_case(&self) -> Result<Option<irmind_app::CaseId>> {
        Ok(None)
    }
    fn remember_last_case(&self, _id: &irmind_app::CaseId) -> Result<()> {
        Ok(())
    }
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>>;
    fn parser_catalog(&self) -> Option<&irmind_app::modules::ParserCatalog> {
        None
    }
    fn read_format_sample(&self, _path: &Path) -> Result<Vec<u8>> {
        anyhow::bail!("bounded parser sampling is unavailable")
    }
    fn read_evidence(&self, path: &Path) -> Result<Vec<u8>>;
    fn audit_source_name(&self, root: &Path, file: &Path) -> Result<String>;
    fn save_evidence(&self, path: &Path, bytes: &[u8]) -> Result<()>;
    fn verify_export(&self, path: &Path, expected_key: &str) -> Result<String>;
    fn case_exporter(&self) -> &dyn irmind_app::CaseExporter;
    fn large_case_exporter(&self) -> Option<&dyn irmind_app::LargeCaseExporter> {
        None
    }
    fn large_case_store(&self) -> Option<&dyn irmind_app::LargeCaseStore> {
        None
    }
    fn streaming_parser(&self) -> Option<&dyn irmind_app::StreamingEventParser> {
        None
    }
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
    fn change_module_configuration(
        &self,
        engine: &Engine<'_>,
        change: irmind_app::ConfigChange,
        confirmed: bool,
    ) -> Result<bool>;
    fn ca_fingerprint(&self, _path: &Path) -> Result<String> {
        anyhow::bail!("CA inspection is unavailable in this workspace")
    }
    fn list_ollama_models(&self, _base_url: &str) -> Result<Vec<String>> {
        anyhow::bail!("Ollama discovery is unavailable in this workspace")
    }
    fn list_provider_models(
        &self,
        provider: &str,
        base_url: &str,
        _key: Option<&SecretString>,
    ) -> Result<Vec<String>> {
        if provider == "llm-openai-compatible" && base_url.starts_with("http://127.0.0.1:11434/") {
            return self.list_ollama_models(base_url);
        }
        anyhow::bail!("Model listing is unavailable in this workspace")
    }
    fn test_model_connection(
        &self,
        _provider: &str,
        _base_url: &str,
        _model: &str,
        _key: Option<&SecretString>,
    ) -> Result<String> {
        anyhow::bail!("Model connection testing is unavailable in this workspace")
    }
}

struct TerminalSession;

pub(crate) fn prompt_hidden(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    prompt: &str,
) -> Result<SecretString> {
    setup::prompt_secret(terminal, prompt)
}

impl TerminalSession {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
    }
}

pub fn run_workspace(
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    modules: &[ModuleStatus],
    shutdown: &CancellationToken,
    launch: WorkspaceLaunch<'_>,
) -> Result<WorkspaceOutcome> {
    let _theme = theme::Theme::configure(launch.theme);
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    home::run_home(
        &mut terminal,
        engine,
        model,
        io_ops,
        modules,
        shutdown,
        launch,
    )
}

/// A startup failure is rendered inside the TUI without constructing an engine.
/// A missing configured backend never triggers a silent backend change.
pub fn show_startup_error(message: &str) -> Result<bool> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    home::show_startup_error(&mut terminal, message)
}
