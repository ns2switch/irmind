use crate::TerminalSession;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use irmind_app::{ConfigurationReview, ContentGuard};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::{io, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationRecoveryChoice {
    Restore,
    Accept,
    Quit,
}

pub struct OverrideReviewEntry {
    pub field: String,
    pub saved: Option<String>,
    pub effective: Option<String>,
}

#[derive(Default)]
struct OverrideScreen {
    offset: usize,
}

impl OverrideScreen {
    fn update(&mut self, key: KeyCode, count: usize) -> Option<bool> {
        match key {
            KeyCode::Char('y') => Some(true),
            KeyCode::Char('n' | 'q') | KeyCode::Esc => Some(false),
            KeyCode::Down => {
                self.offset = self.offset.saturating_add(1).min(count);
                None
            }
            KeyCode::Up => {
                self.offset = self.offset.saturating_sub(1);
                None
            }
            _ => None,
        }
    }

    fn render<B: Backend>(
        &self,
        terminal: &mut Terminal<B>,
        entries: &[OverrideReviewEntry],
        guard: &dyn ContentGuard,
    ) -> Result<()>
    where
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let rows = entries
            .iter()
            .skip(self.offset)
            .map(|entry| {
                let line = format!(
                    "{}: saved={} session={}",
                    entry.field,
                    entry.saved.as_deref().unwrap_or("<unset>"),
                    entry.effective.as_deref().unwrap_or("<unset>")
                );
                guard
                    .screen(&line)
                    .map(|screened| ListItem::new(screened.text))
            })
            .collect::<Result<Vec<_>, _>>()?;
        terminal.draw(|frame| {
            let areas = Layout::vertical([Constraint::Length(3), Constraint::Min(3), Constraint::Length(3)]).split(frame.area());
            frame.render_widget(
                Paragraph::new("Flags or environment settings change where data may be sent")
                    .block(Block::default().title(" Session overrides ").borders(Borders::ALL)),
                areas[0],
            );
            frame.render_widget(List::new(rows).block(Block::default().title(" Saved and effective values ").borders(Borders::ALL)), areas[1]);
            frame.render_widget(
                Paragraph::new("Up/Down inspect every field · y accept and sign for this session · n use saved configuration")
                    .block(Block::default().borders(Borders::ALL)),
                areas[2],
            );
        })?;
        Ok(())
    }
}

pub fn resolve_override_review(
    entries: &[OverrideReviewEntry],
    guard: &dyn ContentGuard,
) -> Result<bool> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut screen = OverrideScreen::default();
    loop {
        screen.render(&mut terminal, entries, guard)?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()?
            && let Some(accepted) = screen.update(key.code, entries.len())
        {
            return Ok(accepted);
        }
    }
}

#[derive(Default)]
struct RecoveryScreen {
    offset: usize,
    confirming_acceptance: bool,
}

impl RecoveryScreen {
    fn update(
        &mut self,
        key: KeyCode,
        review: &ConfigurationReview,
    ) -> Option<ConfigurationRecoveryChoice> {
        if self.confirming_acceptance {
            return match key {
                KeyCode::Char('y') if review.current.is_some() => {
                    Some(ConfigurationRecoveryChoice::Accept)
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.confirming_acceptance = false;
                    None
                }
                _ => None,
            };
        }
        match key {
            KeyCode::Char('r') if review.approved.is_some() => {
                Some(ConfigurationRecoveryChoice::Restore)
            }
            KeyCode::Char('a') if review.current.is_some() => {
                self.confirming_acceptance = true;
                None
            }
            KeyCode::Char('q') | KeyCode::Esc => Some(ConfigurationRecoveryChoice::Quit),
            KeyCode::Down => {
                self.offset = self.offset.saturating_add(1).min(review.differences.len());
                None
            }
            KeyCode::Up => {
                self.offset = self.offset.saturating_sub(1);
                None
            }
            _ => None,
        }
    }

    fn render<B: Backend>(
        &self,
        terminal: &mut Terminal<B>,
        review: &ConfigurationReview,
        guard: &dyn ContentGuard,
    ) -> Result<()>
    where
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let status = if review.file_missing {
            "config.toml is missing"
        } else if review.current_invalid {
            "config.toml is invalid; its contents cannot be accepted"
        } else {
            "config.toml differs from the last signed version"
        };
        let rows = review
            .differences
            .iter()
            .skip(self.offset)
            .map(|item| {
                let line = format!(
                    "{}: approved={} current={}",
                    item.field,
                    item.approved.as_deref().unwrap_or("<unset>"),
                    item.current.as_deref().unwrap_or("<unset>")
                );
                guard.screen(&line).map(|safe| ListItem::new(safe.text))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let help = if self.confirming_acceptance {
            "Accept the current file and sign it? It may change where case data is sent. y confirm · Esc cancel"
        } else if review.approved.is_none() {
            "Older signed event has no recoverable copy · a review and accept a valid file · q quit"
        } else {
            "Up/Down review fields · r restore approved file · a review and accept current file · q quit"
        };
        terminal.draw(|frame| {
            let areas = Layout::vertical([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(frame.area());
            frame.render_widget(
                Paragraph::new(status).block(
                    Block::default()
                        .title(" Configuration recovery ")
                        .borders(Borders::ALL),
                ),
                areas[0],
            );
            frame.render_widget(
                List::new(rows).block(
                    Block::default()
                        .title(" Field differences ")
                        .borders(Borders::ALL),
                ),
                areas[1],
            );
            frame.render_widget(
                Paragraph::new(help).block(Block::default().borders(Borders::ALL)),
                areas[2],
            );
        })?;
        Ok(())
    }
}

pub fn resolve_configuration_review(
    review: &ConfigurationReview,
    guard: &dyn ContentGuard,
) -> Result<ConfigurationRecoveryChoice> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut screen = RecoveryScreen::default();
    loop {
        screen.render(&mut terminal, review, guard)?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()?
            && let Some(choice) = screen.update(key.code, review)
        {
            return Ok(choice);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{AppError, PersistentConfig, Screened};
    use ratatui::backend::TestBackend;

    struct TestGuard;

    impl ContentGuard for TestGuard {
        fn fingerprint(&self) -> String {
            "synthetic".into()
        }
        fn self_test(&self) -> Result<(), AppError> {
            Ok(())
        }
        fn screen(&self, input: &str) -> Result<Screened, AppError> {
            Ok(Screened {
                text: input.into(),
                detections: Vec::new(),
            })
        }
    }

    fn screen_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    #[test]
    fn override_screen_accepts_after_showing_saved_and_effective_values() {
        let mut terminal = Terminal::new(TestBackend::new(110, 12)).unwrap();
        let mut screen = OverrideScreen::default();
        let rows = [OverrideReviewEntry {
            field: "modules.siem-splunk.IRMIND_SPLUNK_URL".into(),
            saved: Some("https://saved.example".into()),
            effective: Some("https://session.example".into()),
        }];
        screen.render(&mut terminal, &rows, &TestGuard).unwrap();
        let shown = screen_text(&terminal);
        assert!(shown.contains("https://saved.example"));
        assert!(shown.contains("https://session.example"));
        assert_eq!(screen.update(KeyCode::Char('y'), rows.len()), Some(true));
    }

    #[test]
    fn override_screen_rejects_and_recovery_requires_explicit_choice() {
        let mut terminal = Terminal::new(TestBackend::new(110, 12)).unwrap();
        let rows = [OverrideReviewEntry {
            field: "llm_module".into(),
            saved: None,
            effective: Some("llm-openai-compatible".into()),
        }];
        let mut screen = OverrideScreen::default();
        screen.render(&mut terminal, &rows, &TestGuard).unwrap();
        assert!(screen_text(&terminal).contains("llm-openai-compatible"));
        assert_eq!(screen.update(KeyCode::Char('n'), rows.len()), Some(false));
        let review = ConfigurationReview {
            approved: Some(PersistentConfig::default()),
            current: Some(PersistentConfig::default()),
            differences: Vec::new(),
            file_missing: false,
            current_invalid: false,
        };
        let mut recovery = RecoveryScreen::default();
        assert_eq!(recovery.update(KeyCode::Char('a'), &review), None);
        assert_eq!(recovery.update(KeyCode::Char('n'), &review), None);
        assert_eq!(
            recovery.update(KeyCode::Char('r'), &review),
            Some(ConfigurationRecoveryChoice::Restore)
        );
    }
}
