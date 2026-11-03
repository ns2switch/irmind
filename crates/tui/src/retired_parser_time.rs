use crate::{TerminalSession, theme::Theme};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    widgets::{Paragraph, Wrap},
};
use std::{io, time::Duration};

#[derive(Default)]
struct RetirementScreen {
    selected: usize,
    typed: Option<usize>,
    confirm_exit: bool,
}
impl RetirementScreen {
    fn update(&mut self, key: KeyCode) -> Option<bool> {
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
            KeyCode::Up => self.selected = 0,
            KeyCode::Down => self.selected = 1,
            KeyCode::Char('1') => self.typed = Some(0),
            KeyCode::Char('2') => self.typed = Some(1),
            KeyCode::Enter => return Some(self.typed.take().unwrap_or(self.selected) == 1),
            KeyCode::Esc => return Some(false),
            _ => {}
        }
        None
    }
    fn render(&self, frame: &mut Frame<'_>) {
        let text = if self.confirm_exit {
            "Exit IRMind? Enter confirms · Esc returns".to_owned()
        } else {
            format!(
                "RFC 3164 time settings are now chosen for each ingestion\n\nRemove LEGACY_YEAR and LEGACY_UTC_OFFSET_MINUTES from config.toml and sign the change?\nPreviously signed sources keep their original year and offset. No case will be rewritten.\n\n{} 1. Leave unchanged and exit\n{} 2. Remove retired settings and sign\n\n↑/↓ choose · Enter confirm · Esc exit",
                if self.selected == 0 { ">" } else { " " },
                if self.selected == 1 { ">" } else { " " }
            )
        };
        frame.render_widget(
            Paragraph::new(text)
                .style(ratatui::style::Style::default().fg(Theme::detect().text))
                .wrap(Wrap { trim: false }),
            frame.area(),
        );
    }
}

pub fn confirm_retired_parser_time_settings() -> Result<bool> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut screen = RetirementScreen::default();
    loop {
        terminal.draw(|frame| screen.render(frame))?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                screen.confirm_exit = true;
                continue;
            }
            if let Some(accepted) = screen.update(key.code) {
                return Ok(accepted);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retired_settings_are_never_removed_without_confirmation() {
        let mut screen = RetirementScreen::default();
        assert_eq!(screen.update(KeyCode::Enter), Some(false));
        assert_eq!(screen.update(KeyCode::Char('y')), None);
        assert_eq!(screen.update(KeyCode::Down), None);
        assert_eq!(screen.update(KeyCode::Enter), Some(true));
    }
}
