use super::state::{Screen, State};
use crate::{case::escape_display, theme::Theme};
use irmind_app::Engine;
use ratatui::{
    Frame, Terminal,
    backend::Backend,
    layout::{Constraint, Layout},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
pub(super) fn draw<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &State,
    engine: &Engine<'_>,
) -> anyhow::Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let safe = |text: &str| -> anyhow::Result<String> {
        Ok(escape_display(&engine.guard.screen(text)?.text))
    };
    let notice = safe(&state.notice)?;
    let preview = safe(&state.preview)?;
    let path = safe(&state.path)?;
    let rows = state
        .rows
        .iter()
        .map(|row| {
            safe(&format!(
                "{} · {} · {} · {:?}{}",
                row.name.as_str(),
                row.version,
                if row.active && row.available {
                    "active"
                } else {
                    "disabled"
                },
                row.origin,
                row.warning
                    .as_deref()
                    .map_or(String::new(), |s| format!(" · {s}"))
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    terminal.draw(|frame| paint(frame, state, &notice, &preview, &path, &rows))?;
    Ok(())
}
fn paint(
    frame: &mut Frame<'_>,
    state: &State,
    notice: &str,
    preview: &str,
    path: &str,
    rows: &[String],
) {
    let theme = Theme::detect();
    let areas = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .split(frame.area());
    frame.render_widget(
        Paragraph::new(if state.confirm_exit {
            "Exit IRMind? Enter confirms; Esc cancels."
        } else {
            "Forensic skills · methodology never grants permissions"
        })
        .style(theme.accent()),
        areas[0],
    );
    match state.screen {
        Screen::List => {
            let list = List::new(rows.iter().map(|s| ListItem::new(s.as_str())))
                .highlight_style(theme.accent());
            frame.render_stateful_widget(
                list,
                areas[1],
                &mut ListState::default().with_selected(Some(state.selected)),
            );
            frame.render_widget(
                Paragraph::new(format!(
                    "1. Inspect   2. Install/update   3. Enable/disable   4. Restore approved file\nSelected action: {} · Input: {}", state.action + 1, escape_display(&state.input)
                ))
                .wrap(Wrap { trim: false })
                .style(theme.muted()),
                areas[2],
            );
        }
        Screen::Path => {
            paint_path(frame, areas[1], areas[2], path, theme);
        }
        Screen::Inspect | Screen::Review | Screen::Confirm => {
            let confirmation = confirmation(state);
            let body = if state.screen == Screen::Confirm {
                &confirmation
            } else {
                preview
            };
            frame.render_widget(
                Paragraph::new(body)
                    .wrap(Wrap { trim: false })
                    .scroll((state.scroll, 0)),
                areas[1],
            );
            if state.screen != Screen::Inspect {
                frame.render_widget(
                    Paragraph::new(if state.option == 0 {
                        "> 1. Cancel     2. Sign and apply"
                    } else {
                        "  1. Cancel   > 2. Sign and apply"
                    })
                    .style(theme.muted()),
                    areas[2],
                );
            }
        }
    }
    paint_footer(frame, notice, areas[3], areas[4], theme);
}
fn paint_path(
    frame: &mut Frame<'_>,
    body: ratatui::layout::Rect,
    input: ratatui::layout::Rect,
    path: &str,
    theme: Theme,
) {
    frame.render_widget(Paragraph::new("Choose a local skill folder containing SKILL.md. Nothing is downloaded. The original folder remains unchanged.").wrap(Wrap { trim: false }), body);
    frame.render_widget(
        Paragraph::new(path).block(
            Block::bordered()
                .title("Skill folder")
                .border_style(theme.accent()),
        ),
        input,
    );
}
fn confirmation(state: &State) -> String {
    state.rows.get(state.selected).map_or_else(|| "Select a skill first.".into(), |row| format!(
                "{} · {}\nSHA-256: {}\n\n{}",
                row.name.as_str(), row.version, row.sha256,
                if state.action == 3 { "Restore the locally stored package from its signed admission? No content is downloaded." }
                else if row.active { "Disable this method for future loads? Existing case receipts remain unchanged." }
                else { "Enable this method? Its name and description become available to the configured model." }
            ))
}
fn paint_footer(
    frame: &mut Frame<'_>,
    notice: &str,
    message: ratatui::layout::Rect,
    help: ratatui::layout::Rect,
    theme: Theme,
) {
    frame.render_widget(
        Paragraph::new(notice)
            .wrap(Wrap { trim: false })
            .style(theme.muted()),
        message,
    );
    frame.render_widget(
        Paragraph::new("↑/↓ choose · Tab actions · Enter confirm · PgUp/PgDn scroll · Esc back")
            .style(theme.muted()),
        help,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn skill_forms_keep_password_free_input_visible_at_eighty_columns() {
        let mut state = State::new(false);
        for screen in [
            Screen::List,
            Screen::Path,
            Screen::Review,
            Screen::Inspect,
            Screen::Confirm,
        ] {
            state.screen = screen;
            let mut terminal =
                Terminal::new(ratatui::backend::TestBackend::new(80, 24)).expect("backend");
            terminal
                .draw(|f| {
                    paint(
                        f,
                        &state,
                        "Synthetic notice",
                        "Synthetic methodology",
                        "examples/skill",
                        &[],
                    );
                })
                .expect("render");
            let text = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>();
            assert!(text.contains("Forensic skills"));
            assert!(text.contains("Esc back"));
        }
    }
}
#[cfg(test)]
#[path = "view/snapshots.rs"]
#[allow(clippy::unwrap_used)]
mod snapshots;
