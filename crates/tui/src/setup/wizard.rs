use super::{KeystoreChoice, TerminalSession};
use crate::theme::Theme;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    widgets::{Block, BorderType, Borders, Paragraph},
};
use secrecy::{ExposeSecret as _, SecretString};
use std::fmt::Write as _;
use std::{io, time::Duration};

const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Welcome,
    Backend,
    Passphrase,
    Confirm,
    Unlock,
    Complete,
}

pub struct KeystoreWizard {
    step: Step,
    existing: bool,
    choice: KeystoreChoice,
    availability: BackendAvailability,
    password: SecretString,
    confirmation: SecretString,
    error: Option<String>,
    fingerprint: Option<String>,
    confirm_exit: bool,
    retry_count: u32,
}

struct BackendAvailability {
    os: bool,
    file: bool,
    vault_exists: bool,
}

impl KeystoreWizard {
    #[must_use]
    pub fn new(
        configured: Option<KeystoreChoice>,
        os_available: bool,
        file_compiled: bool,
        vault_exists: bool,
    ) -> Self {
        let preferred = if os_available { "os" } else { "file" };
        Self {
            step: if configured.is_some() {
                Step::Unlock
            } else {
                Step::Welcome
            },
            existing: configured.is_some(),
            choice: configured.unwrap_or(KeystoreChoice {
                signer: preferred,
                secrets: preferred,
            }),
            availability: BackendAvailability {
                os: os_available,
                file: file_compiled,
                vault_exists,
            },
            password: SecretString::from(String::new()),
            confirmation: SecretString::from(String::new()),
            error: None,
            fingerprint: None,
            confirm_exit: false,
            retry_count: 0,
        }
    }

    fn creating_file(&self) -> bool {
        (self.choice.signer == "file" || self.choice.secrets == "file")
            && !self.availability.vault_exists
    }

    fn needs_password(&self) -> bool {
        self.choice.signer == "file" || self.choice.secrets == "file"
    }

    fn previous(&mut self) {
        self.error = None;
        self.step = match self.step {
            Step::Welcome | Step::Backend => Step::Welcome,
            Step::Passphrase | Step::Unlock => Step::Backend,
            Step::Confirm => Step::Passphrase,
            Step::Complete => Step::Complete,
        };
    }

    fn strength(&self) -> &'static str {
        let value = self.password.expose_secret();
        if value.chars().count() < MIN_PASSPHRASE_CHARS {
            "too short"
        } else if value.chars().count() >= 20
            && value.chars().any(char::is_uppercase)
            && value.chars().any(char::is_numeric)
        {
            "strong"
        } else {
            "acceptable; a longer passphrase is safer"
        }
    }

    fn masked(secret: &SecretString) -> String {
        "•".repeat(secret.expose_secret().chars().count().min(128))
    }

    fn description(&self) -> String {
        match self.step {
            Step::Welcome => "IRMind signs every investigation with your analyst key.\nThe keystore protects that key and connector credentials.\n\nEnter to choose a backend.".into(),
            Step::Backend => format!(
                "Signer: {}  (s to change)\nSecrets: {}  (c to change)\n\nOS keyring: {}. Uses the desktop key service.\nEncrypted file: {}. Works locally and over SSH.\n\nEnter to continue.",
                self.choice.signer,
                self.choice.secrets,
                if self.availability.os { "available" } else { "unavailable in this session" },
                if self.availability.file { "available" } else { "not compiled" },
            ),
            Step::Passphrase => format!(
                "Create a passphrase for the encrypted file.\nAt least {MIN_PASSPHRASE_CHARS} characters; use several unrelated words.\n\nPassphrase: {}\nStrength: {}",
                Self::masked(&self.password), self.strength(),
            ),
            Step::Confirm => format!(
                "Repeat the passphrase to prevent a typing mistake.\n\nConfirmation: {}",
                Self::masked(&self.confirmation),
            ),
            Step::Unlock if self.needs_password() => format!(
                "Unlock the configured file keystore.\n\nPassphrase: {}\n\nEnter to unlock · Esc to choose another backend",
                Self::masked(&self.password),
            ),
            Step::Unlock => "Connect to the configured OS keyring.\n\nEnter to continue · Esc to choose another backend".into(),
            Step::Complete => format!(
                "Analyst public-key fingerprint:\n{}\n\nSave this fingerprint outside this computer. You can use it to verify exported cases.\n\nEnter to continue.",
                self.fingerprint.as_deref().unwrap_or("unavailable"),
            ),
        }
    }

    fn accept_text(&mut self, key: KeyCode) {
        let secret = if self.step == Step::Confirm {
            &mut self.confirmation
        } else {
            &mut self.password
        };
        if update_secret(secret, key) {
            self.error = None;
        }
    }

    fn advance(&mut self) -> bool {
        self.error = None;
        match self.step {
            Step::Welcome => self.step = Step::Backend,
            Step::Backend if !self.availability.file && self.needs_password() => {
                self.error = Some(
                    "The encrypted file backend was not compiled. Select the OS keyring.".into(),
                );
            }
            Step::Backend
                if !self.availability.os
                    && (self.choice.signer == "os" || self.choice.secrets == "os") =>
            {
                self.error = Some("The OS keyring is unavailable in this session. Select file for both capabilities; it also works over SSH.".into());
            }
            Step::Backend if self.needs_password() => {
                self.step = if self.creating_file() {
                    Step::Passphrase
                } else {
                    Step::Unlock
                };
            }
            Step::Passphrase
                if self.password.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS =>
            {
                self.error = Some(format!(
                    "Use at least {MIN_PASSPHRASE_CHARS} characters so a stolen vault resists guessing."
                ));
            }
            Step::Passphrase => self.step = Step::Confirm,
            Step::Confirm if self.password.expose_secret() != self.confirmation.expose_secret() => {
                self.error =
                    Some("The passphrases do not match. Re-enter the confirmation.".into());
                self.confirmation = SecretString::from(String::new());
            }
            Step::Backend | Step::Confirm | Step::Unlock | Step::Complete => return true,
        }
        false
    }

    fn key(&mut self, key: KeyEvent) -> WizardAction {
        if key.kind != KeyEventKind::Press {
            return WizardAction::None;
        }
        if self.confirm_exit {
            return match key.code {
                KeyCode::Char('y') | KeyCode::Enter => WizardAction::Exit,
                _ => {
                    self.confirm_exit = false;
                    WizardAction::None
                }
            };
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.confirm_exit = true;
            return WizardAction::None;
        }
        match key.code {
            KeyCode::Esc => self.previous(),
            KeyCode::Char('s') if self.step == Step::Backend => {
                self.choice.signer = if self.choice.signer == "os" {
                    "file"
                } else {
                    "os"
                };
            }
            KeyCode::Char('c') if self.step == Step::Backend => {
                self.choice.secrets = if self.choice.secrets == "os" {
                    "file"
                } else {
                    "os"
                };
            }
            KeyCode::Enter if self.advance() => {
                return if self.step == Step::Complete {
                    WizardAction::Done
                } else {
                    WizardAction::Attempt
                };
            }
            code if matches!(self.step, Step::Passphrase | Step::Confirm)
                || self.step == Step::Unlock && self.needs_password() =>
            {
                self.accept_text(code);
            }
            _ => {}
        }
        WizardAction::None
    }

    fn attempted(&mut self, outcome: Result<String, String>) {
        match outcome {
            Ok(fingerprint) => {
                self.fingerprint = Some(fingerprint);
                self.step = Step::Complete;
                self.password = SecretString::from(String::new());
                self.confirmation = SecretString::from(String::new());
                self.error = None;
            }
            Err(error) => {
                self.retry_count = self.retry_count.saturating_add(1);
                self.error = Some(error);
                self.password = SecretString::from(String::new());
                self.confirmation = SecretString::from(String::new());
                if self.creating_file() {
                    self.step = Step::Passphrase;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WizardAction {
    None,
    Attempt,
    Done,
    Exit,
}

pub(crate) fn render<B: Backend>(terminal: &mut Terminal<B>, wizard: &KeystoreWizard) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    terminal.draw(|frame| {
        let theme = Theme::detect();
        let rows = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(9),
            Constraint::Length(3),
        ])
        .split(frame.area());
        let heading = if wizard.existing {
            "IRMind · unlock keystore"
        } else {
            "IRMind · first-run keystore"
        };
        frame.render_widget(Paragraph::new(heading).style(theme.accent()), rows[0]);
        let mut text = wizard.description();
        if let Some(error) = &wizard.error {
            let _ = write!(
                text,
                "\n\nError: {error}\nRetry, Esc to go back, or choose another backend."
            );
        }
        if wizard.confirm_exit {
            text.push_str("\n\nExit setup? Enter/y confirms; any other key stays.");
        }
        frame.render_widget(
            Paragraph::new(text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(
                        ratatui::style::Style::default().fg(if wizard.error.is_some() {
                            theme.error
                        } else if wizard.step == Step::Complete {
                            theme.success
                        } else {
                            theme.border
                        }),
                    ),
            ),
            rows[1],
        );
        frame.render_widget(
            Paragraph::new("Enter continue · Esc back · Ctrl+C exit").style(theme.muted()),
            rows[2],
        );
    })?;
    Ok(())
}

/// The caller owns the keystore; the wizard keeps secret input in the alternate screen.
pub fn run_keystore_wizard<T>(
    mut wizard: KeystoreWizard,
    mut attempt: impl FnMut(KeystoreChoice, Option<&SecretString>) -> Result<(String, T), String>,
) -> Result<Option<T>> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut completed = None;
    loop {
        render(&mut terminal, &wizard)?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        match wizard.key(key) {
            WizardAction::None => {}
            WizardAction::Exit => return Ok(None),
            WizardAction::Done => return Ok(completed),
            WizardAction::Attempt => {
                let secret = wizard.needs_password().then_some(&wizard.password);
                let outcome = attempt(wizard.choice, secret);
                match outcome {
                    Ok((fingerprint, active)) => {
                        completed = Some(active);
                        wizard.attempted(Ok(fingerprint));
                    }
                    Err(error) => {
                        wizard.attempted(Err(error));
                        if wizard.step == Step::Unlock {
                            std::thread::sleep(Duration::from_millis(
                                500u64.saturating_mul(u64::from(wizard.retry_count.min(8))),
                            ));
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn prompt_secret(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    prompt: &str,
) -> Result<SecretString> {
    let mut secret = SecretString::from(String::new());
    loop {
        terminal.draw(|frame| {
            let rows =
                Layout::vertical([Constraint::Min(4), Constraint::Length(3)]).split(frame.area());
            frame.render_widget(
                Paragraph::new(format!("{prompt}\n{}", KeystoreWizard::masked(&secret)))
                    .block(Block::default().borders(Borders::ALL)),
                rows[0],
            );
            frame.render_widget(Paragraph::new("Enter confirm · Esc cancel"), rows[1]);
        })?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter => return Ok(secret),
            KeyCode::Esc => anyhow::bail!("secret entry cancelled"),
            code => {
                update_secret(&mut secret, code);
            }
        }
    }
}

fn update_secret(secret: &mut SecretString, code: KeyCode) -> bool {
    let current = secret.expose_secret();
    let mut value = match code {
        KeyCode::Char(ch) if !ch.is_control() && current.len() + ch.len_utf8() <= 4096 => {
            let mut bytes = current.as_bytes().to_vec();
            let mut encoded = [0u8; 4];
            bytes.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
            bytes
        }
        KeyCode::Backspace if !current.is_empty() => {
            let mut bytes = current.as_bytes().to_vec();
            let start = current
                .char_indices()
                .next_back()
                .map_or(0, |(start, _)| start);
            bytes[start..].fill(0);
            bytes.truncate(start);
            bytes
        }
        _ => return false,
    };
    match String::from_utf8(std::mem::take(&mut value)) {
        Ok(next) => {
            *secret = SecretString::from(next);
            true
        }
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
