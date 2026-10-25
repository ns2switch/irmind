use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    widgets::{Block, Borders, Paragraph},
};
use std::{io, time::Duration};

use crate::TerminalSession;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeystoreChoice {
    pub signer: &'static str,
    pub secrets: &'static str,
}

impl KeystoreChoice {
    pub fn initial(os_available: bool, file_compiled: bool) -> Result<Self> {
        let backend = if os_available {
            "os"
        } else if file_compiled {
            "file"
        } else {
            anyhow::bail!("no usable keystore backend is available");
        };
        Ok(Self {
            signer: backend,
            secrets: backend,
        })
    }
}

pub(crate) fn render_setup<B: Backend>(
    terminal: &mut Terminal<B>,
    reason: &str,
    choice: KeystoreChoice,
    os_available: bool,
    file_compiled: bool,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let safe_reason = reason
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>();
    terminal.draw(|frame| {
        let areas = Layout::vertical([Constraint::Length(3), Constraint::Min(6), Constraint::Length(2)]).split(frame.area());
        frame.render_widget(Paragraph::new("IRMind · keystore setup").block(Block::default().borders(Borders::ALL)), areas[0]);
        frame.render_widget(Paragraph::new(format!(
            "{safe_reason}\n\nSigner backend: {}\nSecrets backend: {}\n\nOS keyring: {} · encrypted file: {}\nFile backend works over SSH without a graphical session.",
            choice.signer, choice.secrets,
            if os_available { "available" } else { "unavailable" },
            if file_compiled { "compiled" } else { "not compiled" },
        )).block(Block::default().borders(Borders::ALL)), areas[1]);
        frame.render_widget(Paragraph::new("s change signer · c change secrets · Enter save selection · Esc exit"), areas[2]);
    })?;
    Ok(())
}

/// The choice is explicit even when only one backend is compiled.
pub fn choose_keystore(
    reason: &str,
    os_available: bool,
    file_compiled: bool,
) -> Result<Option<KeystoreChoice>> {
    let initial = KeystoreChoice::initial(os_available, file_compiled)?;
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut signer = initial.signer;
    let mut secrets = initial.secrets;
    loop {
        render_setup(
            &mut terminal,
            reason,
            KeystoreChoice { signer, secrets },
            os_available,
            file_compiled,
        )?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        match key.code {
            KeyCode::Char('s') if os_available && file_compiled => {
                signer = if signer == "os" { "file" } else { "os" }
            }
            KeyCode::Char('c') if os_available && file_compiled => {
                secrets = if secrets == "os" { "file" } else { "os" }
            }
            KeyCode::Enter => return Ok(Some(KeystoreChoice { signer, secrets })),
            KeyCode::Esc | KeyCode::Char('q') => return Ok(None),
            _ => {}
        }
    }
}
