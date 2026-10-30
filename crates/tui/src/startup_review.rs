use crate::TerminalSession;
use crate::theme::Theme;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{ConfigurationReview, ContentGuard};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    widgets::{Block, Borders, Paragraph, Wrap},
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
    selected: usize,
    typed: Option<usize>,
    confirm_exit: bool,
}

impl OverrideScreen {
    fn update(&mut self, key: KeyCode, count: usize) -> Option<bool> {
        if self.confirm_exit {
            return match key {
                KeyCode::Enter => Some(false),
                KeyCode::Esc => {
                    self.confirm_exit = false;
                    None
                }
                _ => None,
            };
        }
        match key {
            KeyCode::Esc => Some(false),
            KeyCode::Down => {
                self.selected = 1;
                None
            }
            KeyCode::Up => {
                self.selected = 0;
                None
            }
            KeyCode::PageDown => {
                self.offset = self
                    .offset
                    .saturating_add(10)
                    .min(count.saturating_mul(1024));
                None
            }
            KeyCode::PageUp => {
                self.offset = self.offset.saturating_sub(10);
                None
            }
            KeyCode::Char('1' | '2') => {
                self.typed = Some(usize::from(key == KeyCode::Char('2')));
                None
            }
            KeyCode::Enter => Some(self.typed.take().unwrap_or(self.selected) == 1),
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
            .map(|entry| {
                let line = format!(
                    "{}\n  saved: {}\n  session: {}",
                    entry.field,
                    entry.saved.as_deref().unwrap_or("<unset>"),
                    entry.effective.as_deref().unwrap_or("<unset>")
                );
                guard.screen(&line).map(|screened| screened.text)
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("\n\n");
        terminal.draw(|frame| {
            let areas = Layout::vertical([Constraint::Length(3), Constraint::Min(3), Constraint::Length(3)]).split(frame.area());
            frame.render_widget(
                Paragraph::new("Flags or environment settings change where data may be sent")
                    .block(Block::default().title(" Session overrides ").borders(Borders::ALL)),
                areas[0],
            );
            frame.render_widget(
                Paragraph::new(rows)
                    .wrap(Wrap { trim: false })
                    .scroll((u16::try_from(self.offset).unwrap_or(u16::MAX), 0))
                    .block(Block::default().title(" Saved and effective values ").borders(Borders::ALL)),
                areas[1],
            );
            frame.render_widget(
                Paragraph::new(if self.confirm_exit { "Exit IRMind? Enter confirms · Esc returns".into() } else { format!("{} 1. Use saved configuration   {} 2. Accept overrides and sign\n↑/↓ choose · Enter confirm · PgUp/PgDn inspect fields · typed: {}",
                    if self.selected == 0 { ">" } else { " " },
                    if self.selected == 1 { ">" } else { " " }, self.typed.map_or(String::new(), |value| (value + 1).to_string())) })
                    .style(Theme::detect().muted())
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
        if let Event::Key(key) = event::read()? {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                screen.confirm_exit = true;
                continue;
            }
            if let Some(accepted) = screen.update(key.code, entries.len()) {
                return Ok(accepted);
            }
        }
    }
}

#[derive(Default)]
struct RecoveryScreen {
    offset: usize,
    confirming_acceptance: bool,
    selected: usize,
    typed: Option<usize>,
    confirm_exit: bool,
}

impl RecoveryScreen {
    fn update(
        &mut self,
        key: KeyCode,
        review: &ConfigurationReview,
    ) -> Option<ConfigurationRecoveryChoice> {
        if self.confirm_exit {
            return match key {
                KeyCode::Enter => Some(ConfigurationRecoveryChoice::Quit),
                KeyCode::Esc => {
                    self.confirm_exit = false;
                    None
                }
                _ => None,
            };
        }
        if self.confirming_acceptance {
            return match key {
                KeyCode::Enter if review.current.is_some() => {
                    Some(ConfigurationRecoveryChoice::Accept)
                }
                KeyCode::Esc => {
                    self.confirming_acceptance = false;
                    None
                }
                _ => None,
            };
        }
        match key {
            KeyCode::Esc => Some(ConfigurationRecoveryChoice::Quit),
            KeyCode::Char('1' | '2' | '3') => {
                self.typed = match key {
                    KeyCode::Char(ch) => ch.to_digit(10).map(|value| value as usize - 1),
                    _ => None,
                };
                None
            }
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(2);
                None
            }
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                None
            }
            KeyCode::PageDown => {
                self.offset = self
                    .offset
                    .saturating_add(10)
                    .min(review.differences.len().saturating_mul(1024));
                None
            }
            KeyCode::PageUp => {
                self.offset = self.offset.saturating_sub(10);
                None
            }
            KeyCode::Enter => match self.typed.take().unwrap_or(self.selected) {
                0 if review.approved.is_some() => Some(ConfigurationRecoveryChoice::Restore),
                1 if review.current.is_some() => {
                    self.confirming_acceptance = true;
                    None
                }
                2 => Some(ConfigurationRecoveryChoice::Quit),
                _ => None,
            },
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
            .map(|item| {
                let line = format!(
                    "{}\n  approved: {}\n  current: {}",
                    item.field,
                    item.approved.as_deref().unwrap_or("<unset>"),
                    item.current.as_deref().unwrap_or("<unset>")
                );
                guard.screen(&line).map(|safe| safe.text)
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("\n\n");
        let help = if self.confirm_exit {
            "Exit IRMind? Enter confirms · Esc returns"
        } else if self.confirming_acceptance {
            "Accept current config.toml and sign it? Enter confirms · Esc cancels"
        } else if review.approved.is_none() {
            "1. Restore unavailable · 2. Review and accept current file · 3. Quit · ↑/↓ choose, Enter confirm"
        } else {
            "1. Restore approved file · 2. Review and accept current file · 3. Quit · ↑/↓ choose, Enter confirm"
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
                Paragraph::new(rows)
                    .wrap(Wrap { trim: false })
                    .scroll((u16::try_from(self.offset).unwrap_or(u16::MAX), 0))
                    .block(
                        Block::default()
                            .title(" Field differences ")
                            .borders(Borders::ALL),
                    ),
                areas[1],
            );
            frame.render_widget(
                Paragraph::new(format!(
                    "{help} · typed: {}",
                    self.typed
                        .map_or(String::new(), |value| (value + 1).to_string())
                ))
                .style(Theme::detect().muted())
                .block(Block::default().borders(Borders::ALL)),
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
        if let Event::Key(key) = event::read()? {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                screen.confirm_exit = true;
                continue;
            }
            if let Some(choice) = screen.update(key.code, review) {
                return Ok(choice);
            }
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
        assert_eq!(screen.update(KeyCode::Char('y'), rows.len()), None);
        assert_eq!(screen.update(KeyCode::Down, rows.len()), None);
        assert_eq!(screen.update(KeyCode::Enter, rows.len()), Some(true));
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
        assert_eq!(screen.update(KeyCode::Char('n'), rows.len()), None);
        assert_eq!(screen.update(KeyCode::Enter, rows.len()), Some(false));
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
            recovery.update(KeyCode::Enter, &review),
            Some(ConfigurationRecoveryChoice::Restore)
        );
    }
}
