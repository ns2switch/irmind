use super::{CancellationToken, CrosstermBackend, Terminal, TerminalSession};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    widgets::{List, ListItem, ListState, Paragraph},
};
use std::{io, time::Duration};

/// The list contains only loopback Ollama models advertising tool support.
/// `None` selects the offline scripted model.
pub fn choose_demo_model(
    models: &[String],
    shutdown: &CancellationToken,
) -> Result<Option<String>> {
    if models.is_empty() {
        return Ok(None);
    }
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut selected = 0usize;
    loop {
        if shutdown.is_cancelled() {
            return Ok(None);
        }
        let mut state = ListState::default().with_selected(Some(selected));
        terminal.draw(|frame| {
            let theme = crate::theme::Theme::detect();
            let areas = Layout::vertical([Constraint::Length(4), Constraint::Min(3), Constraint::Length(1)]).split(frame.area());
            frame.render_widget(Paragraph::new("Demo · synthetic data · deleted on exit\nChoose a local Ollama model with tools, or use the scripted demo. No remote provider is used."), areas[0]);
            let mut entries = models.iter().map(|model| ListItem::new(format!("Ollama · {model}"))).collect::<Vec<_>>();
            entries.push(ListItem::new("Scripted demo model · offline"));
            frame.render_stateful_widget(List::new(entries).highlight_style(theme.accent()), areas[1], &mut state);
            frame.render_widget(Paragraph::new("↑/↓ choose · Enter continue · Esc scripted model").style(theme.muted()), areas[2]);
        })?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        match event::read()? {
            Event::Key(key)
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c') =>
            {
                shutdown.cancel();
                return Ok(None);
            }
            Event::Key(key) => match key.code {
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1).min(models.len()),
                KeyCode::Enter => return Ok(models.get(selected).cloned()),
                KeyCode::Esc => return Ok(None),
                _ => {}
            },
            _ => {}
        }
    }
}
