use super::{KeystoreChoice, TerminalSession};
use crate::case::escape_display;
use crate::theme::Theme;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendField {
    Signer,
    Secrets,
}

pub struct KeystoreWizard {
    step: Step,
    existing: bool,
    choice: KeystoreChoice,
    backend_field: BackendField,
    backend_cursor: &'static str,
    backend_input: String,
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
    fn step_heading(&self) -> &'static str {
        match self.step {
            Step::Welcome => "Step 1 of 4 · Welcome",
            Step::Backend => "Step 2 of 4 · Backend",
            Step::Passphrase | Step::Confirm => "Step 3 of 4 · Passphrase",
            Step::Unlock => "Step 3 of 4 · Unlock",
            Step::Complete => "Step 4 of 4 · Fingerprint",
        }
    }

    #[must_use]
    pub fn new(
        configured: Option<KeystoreChoice>,
        os_available: bool,
        file_compiled: bool,
        vault_exists: bool,
    ) -> Self {
        let preferred = if os_available { "os" } else { "file" };
        let choice = configured.unwrap_or(KeystoreChoice {
            signer: preferred,
            secrets: preferred,
        });
        let backend_cursor = if choice.signer == "os" && os_available {
            "os"
        } else if file_compiled {
            "file"
        } else {
            "os"
        };
        Self {
            step: if configured.is_some() {
                Step::Unlock
            } else {
                Step::Welcome
            },
            existing: configured.is_some(),
            choice,
            backend_field: BackendField::Signer,
            backend_cursor,
            backend_input: String::new(),
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
            Step::Backend if self.backend_field == BackendField::Secrets => {
                self.backend_field = BackendField::Signer;
                self.select_available(self.choice.signer);
                Step::Backend
            }
            Step::Backend if self.existing => Step::Unlock,
            Step::Welcome | Step::Backend => Step::Welcome,
            Step::Passphrase => {
                self.backend_field = BackendField::Secrets;
                self.select_available(self.choice.secrets);
                Step::Backend
            }
            Step::Unlock => {
                self.backend_field = BackendField::Signer;
                self.select_available(self.choice.signer);
                Step::Backend
            }
            Step::Confirm => Step::Passphrase,
            Step::Complete => Step::Complete,
        };
    }

    fn available(&self, backend: &str) -> bool {
        match backend {
            "os" => self.availability.os,
            "file" => self.availability.file,
            _ => false,
        }
    }

    fn select_available(&mut self, preferred: &str) {
        self.backend_cursor = if self.available(preferred) {
            if preferred == "os" { "os" } else { "file" }
        } else if self.availability.file {
            "file"
        } else {
            "os"
        };
    }

    fn move_backend(&mut self, direction: KeyCode) {
        let target = match direction {
            KeyCode::Up => "os",
            KeyCode::Down => "file",
            _ => return,
        };
        if self.available(target) {
            self.backend_cursor = target;
            self.error = None;
        }
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
            Step::Backend => "Choose a backend with ↑/↓ and Enter, or type 1/2 then Enter. Signing and module secrets are selected separately.".into(),
            Step::Passphrase => format!(
                "Create a passphrase for the encrypted file.\nAt least {MIN_PASSPHRASE_CHARS} characters; use several unrelated words."
            ),
            Step::Confirm => "Repeat the passphrase to prevent a typing mistake.".into(),
            Step::Unlock if self.needs_password() => "Unlock the configured file keystore.\nEnter to unlock · Esc to choose another backend.".into(),
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
        if self.step == Step::Backend && !self.backend_input.is_empty() {
            let requested = match self.backend_input.as_str() {
                "1" => "os",
                "2" => "file",
                _ => {
                    self.error = Some("Choose option 1 or 2.".into());
                    return false;
                }
            };
            self.backend_input.clear();
            if !self.available(requested) {
                self.error = Some("That backend is unavailable in this session.".into());
                return false;
            }
            self.backend_cursor = requested;
        }
        self.error = None;
        match self.step {
            Step::Welcome => self.step = Step::Backend,
            Step::Backend if !self.available(self.backend_cursor) => {
                self.error = Some("No selectable backend is available. Check the system keyring or use a build with the encrypted-file backend.".into());
            }
            Step::Backend => {
                if self.backend_field == BackendField::Signer {
                    self.choice.signer = self.backend_cursor;
                    self.backend_field = BackendField::Secrets;
                    self.select_available(self.choice.secrets);
                } else {
                    self.choice.secrets = self.backend_cursor;
                    if self.needs_password() {
                        self.step = if self.creating_file() {
                            Step::Passphrase
                        } else {
                            Step::Unlock
                        };
                    } else {
                        return true;
                    }
                }
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
            Step::Confirm | Step::Unlock | Step::Complete => return true,
        }
        false
    }

    fn key(&mut self, key: KeyEvent) -> WizardAction {
        if key.kind != KeyEventKind::Press {
            return WizardAction::None;
        }
        if self.confirm_exit {
            return if key.code == KeyCode::Enter {
                WizardAction::Exit
            } else {
                self.confirm_exit = false;
                WizardAction::None
            };
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.confirm_exit = true;
            return WizardAction::None;
        }
        match key.code {
            KeyCode::Esc => self.previous(),
            KeyCode::Up | KeyCode::Down if self.step == Step::Backend => {
                self.move_backend(key.code);
            }
            KeyCode::Backspace if self.step == Step::Backend => {
                self.backend_input.pop();
            }
            KeyCode::Char(ch)
                if self.step == Step::Backend
                    && !ch.is_control()
                    && self.backend_input.len() < 4 =>
            {
                self.backend_input.push(ch);
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
        let heading = format!("IRMind · {}", wizard.step_heading());
        frame.render_widget(Paragraph::new(heading).style(theme.accent()), rows[0]);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(if wizard.error.is_some() {
                    theme.error
                } else if wizard.step == Step::Complete {
                    theme.success
                } else {
                    theme.border
                })),
            rows[1],
        );
        let inner = Rect::new(
            rows[1].x.saturating_add(2),
            rows[1].y.saturating_add(2),
            rows[1].width.saturating_sub(4),
            rows[1].height.saturating_sub(4),
        );
        match wizard.step {
            Step::Backend => render_backends(frame, wizard, inner, theme),
            Step::Passphrase | Step::Confirm => render_secret_field(frame, wizard, inner, theme),
            Step::Unlock if wizard.needs_password() => {
                render_secret_field(frame, wizard, inner, theme);
            }
            _ => render_explanation(frame, wizard, inner, theme),
        }
        frame.render_widget(
            Paragraph::new(if wizard.step == Step::Backend {
                "↑/↓ choose · Enter select · Esc back · Ctrl+C exit"
            } else {
                "Enter continue · Esc back · Ctrl+C exit"
            })
            .style(theme.muted()),
            rows[2],
        );
    })?;
    Ok(())
}

fn render_backends(
    frame: &mut ratatui::Frame<'_>,
    wizard: &KeystoreWizard,
    area: Rect,
    theme: Theme,
) {
    let focus = if wizard.backend_field == BackendField::Signer {
        "signing key"
    } else {
        "module secrets"
    };
    let mut lines = vec![
        Line::from(format!("Choose a backend for the {focus}:")),
        Line::default(),
    ];
    for (number, id, label, description, unavailable) in [
        (
            1,
            "os",
            "OS keyring",
            "Uses the system key service.",
            "Unavailable in this session: no system keyring.",
        ),
        (
            2,
            "file",
            "Encrypted file",
            "Works locally and over SSH.",
            "Unavailable: not compiled in this build.",
        ),
    ] {
        let available = wizard.available(id);
        let selected = wizard.backend_cursor == id && available;
        lines.push(Line::from(Span::styled(
            format!(
                "{} {number}. {label} — {}",
                if selected { '›' } else { ' ' },
                if available { description } else { unavailable }
            ),
            if !available {
                theme.muted()
            } else if selected {
                theme.accent()
            } else {
                Style::default().fg(theme.text)
            },
        )));
    }
    lines.extend([
        Line::default(),
        Line::from(format!("Choice: {}", wizard.backend_input)),
        Line::styled(format!("Signing: {}", wizard.choice.signer), theme.muted()),
        Line::styled(format!("Secrets: {}", wizard.choice.secrets), theme.muted()),
    ]);
    if let Some(error) = &wizard.error {
        lines.push(Line::default());
        lines.push(Line::styled(
            escape_display(error),
            Style::default().fg(theme.error),
        ));
    }
    if wizard.confirm_exit {
        lines.push(Line::styled(
            "Exit setup? Enter/y confirms.",
            theme.warning(),
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_secret_field(
    frame: &mut ratatui::Frame<'_>,
    wizard: &KeystoreWizard,
    area: Rect,
    theme: Theme,
) {
    frame.render_widget(Paragraph::new(wizard.description()), area);
    let (label, value) = if wizard.step == Step::Confirm {
        (" Confirmation ", &wizard.confirmation)
    } else {
        (" Passphrase ", &wizard.password)
    };
    let field = Rect::new(
        area.x,
        area.y.saturating_add(4),
        area.width,
        3.min(area.height.saturating_sub(4)),
    );
    frame.render_widget(
        Paragraph::new(KeystoreWizard::masked(value)).block(
            Block::default()
                .title(label)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border)),
        ),
        field,
    );
    let strength = if wizard.step == Step::Unlock {
        "Input is hidden from the terminal scrollback.".to_owned()
    } else {
        format!("Strength: {}", wizard.strength())
    };
    frame.render_widget(
        Paragraph::new(strength).style(theme.muted()),
        Rect::new(area.x, field.bottom().saturating_add(1), area.width, 1),
    );
    render_feedback(frame, wizard, area, field.bottom().saturating_add(3), theme);
}

fn render_explanation(
    frame: &mut ratatui::Frame<'_>,
    wizard: &KeystoreWizard,
    area: Rect,
    theme: Theme,
) {
    let mut text = wizard.description();
    if let Some(error) = &wizard.error {
        let _ = write!(
            text,
            "\n\nError: {error}\nRetry or go back to choose another backend."
        );
    }
    if wizard.confirm_exit {
        text.push_str("\n\nExit setup? Enter confirms; Esc stays.");
    }
    frame.render_widget(
        Paragraph::new(escape_display(&text)).style(Style::default().fg(theme.text)),
        area,
    );
}

fn render_feedback(
    frame: &mut ratatui::Frame<'_>,
    wizard: &KeystoreWizard,
    area: Rect,
    start: u16,
    theme: Theme,
) {
    let text = if let Some(error) = &wizard.error {
        format!("Error: {error}\nRetry, Esc to go back, or choose another backend.")
    } else if wizard.confirm_exit {
        "Exit setup? Enter confirms; Esc stays.".into()
    } else {
        String::new()
    };
    frame.render_widget(
        Paragraph::new(escape_display(&text)).style(Style::default().fg(
            if wizard.error.is_some() {
                theme.error
            } else {
                theme.warning
            },
        )),
        Rect::new(
            area.x,
            start,
            area.width,
            area.bottom().saturating_sub(start),
        ),
    );
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
    let safe_prompt = escape_display(prompt);
    loop {
        terminal.draw(|frame| {
            let rows =
                Layout::vertical([Constraint::Min(4), Constraint::Length(3)]).split(frame.area());
            frame.render_widget(
                Paragraph::new(format!(
                    "{safe_prompt}\n{}",
                    KeystoreWizard::masked(&secret)
                ))
                .block(Block::default().borders(Borders::ALL)),
                rows[0],
            );
            frame.render_widget(
                Paragraph::new("Enter confirm · Esc cancel").style(Theme::detect().muted()),
                rows[1],
            );
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
