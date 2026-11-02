use super::{Backend, Engine, Result, State, Terminal, Theme, state};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use state::Screen;

pub(super) fn draw<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &State,
    engine: &Engine<'_>,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let safe = |text: &str| -> Result<String> { Ok(engine.guard.screen(text)?.text) };
    let status = safe(&state.notice)?;
    let preview = safe(&state.preview)?;
    let fields = state
        .fields
        .iter()
        .map(|text| safe(text))
        .collect::<Result<Vec<_>>>()?;
    let rows = state
        .statuses
        .iter()
        .map(|item| {
            safe(&format!(
                "{} · {} · {}{}",
                item.id,
                if item.active && item.available {
                    "active"
                } else {
                    "disabled"
                },
                item.version,
                item.warning
                    .as_ref()
                    .map_or(String::new(), |text| format!(" · {text}"))
            ))
            .map(ListItem::new)
        })
        .collect::<Result<Vec<_>>>()?;
    terminal.draw(|frame| paint(frame, state, &status, &preview, &fields, rows))?;
    Ok(())
}

fn paint(
    frame: &mut Frame<'_>,
    state: &State,
    status: &str,
    preview: &str,
    fields: &[String],
    rows: Vec<ListItem<'_>>,
) {
    let theme = Theme::detect();
    let areas = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(frame.area());
    frame.render_widget(
        Paragraph::new("Declarative parsers · experimental").style(theme.accent()),
        areas[0],
    );
    match state.screen {
        Screen::List => draw_list(frame, areas[1], state, rows, theme),
        Screen::Install | Screen::Test => draw_form(frame, areas[1], state, fields, theme),
        Screen::ConfirmInstall | Screen::ConfirmDeactivate | Screen::ConfirmRestore => {
            draw_confirmation(frame, areas[1], state, preview, theme);
        }
        Screen::Preview => frame.render_widget(
            Paragraph::new(preview)
                .wrap(Wrap { trim: false })
                .scroll((state.scroll, 0)),
            areas[1],
        ),
    }
    frame.render_widget(
        Paragraph::new(if state.confirm_exit {
            "Exit IRMind? Enter confirms; Esc cancels."
        } else {
            status
        })
        .style(theme.muted())
        .wrap(Wrap { trim: false }),
        areas[2],
    );
    frame.render_widget(
        Paragraph::new(
            "↑/↓ select · Tab action/field · Enter continue · PgUp/PgDn scroll · Esc back",
        )
        .style(theme.muted()),
        areas[3],
    );
}

fn draw_list(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    rows: Vec<ListItem<'_>>,
    theme: Theme,
) {
    let parts = Layout::vertical([Constraint::Min(2), Constraint::Length(5)]).split(area);
    let mut selected = ListState::default().with_selected(Some(state.selected));
    frame.render_stateful_widget(
        List::new(rows).highlight_style(theme.accent()),
        parts[0],
        &mut selected,
    );
    let actions = [
        "Install definition",
        "Test definition (no ingestion)",
        "Deactivate definition",
        "Restore approved file",
    ];
    let mut lines = actions
        .iter()
        .enumerate()
        .map(|(index, label)| {
            Line::from(Span::styled(
                format!("{}. {label}", index + 1),
                if index == state.option {
                    theme.accent()
                } else {
                    theme.muted()
                },
            ))
        })
        .collect::<Vec<_>>();
    lines.push(Line::from(format!(
        "Action: {}",
        crate::case::escape_display(&state.action_input)
    )));
    frame.render_widget(Paragraph::new(lines), parts[1]);
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, state: &State, fields: &[String], theme: Theme) {
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(area);
    let count = if state.screen == Screen::Test { 2 } else { 1 };
    for index in 0..count {
        let label = if index == 0 {
            "Definition TOML path"
        } else {
            "Sample path (at most 1 MiB)"
        };
        frame.render_widget(
            Paragraph::new(fields[index].as_str()).block(
                Block::bordered()
                    .title(label)
                    .border_style(if index == state.field {
                        theme.accent()
                    } else {
                        ratatui::style::Style::default().fg(theme.border)
                    }),
            ),
            parts[index],
        );
    }
}

fn draw_confirmation(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &State,
    preview: &str,
    theme: Theme,
) {
    let parts = Layout::vertical([Constraint::Min(2), Constraint::Length(2)]).split(area);
    frame.render_widget(Paragraph::new(preview).wrap(Wrap { trim: false }), parts[0]);
    let options = ["1. Cancel", "2. Sign and apply"];
    frame.render_widget(
        Paragraph::new(
            options
                .iter()
                .enumerate()
                .map(|(index, label)| {
                    Line::from(Span::styled(
                        *label,
                        if index == state.option {
                            theme.accent()
                        } else {
                            theme.muted()
                        },
                    ))
                })
                .collect::<Vec<_>>(),
        ),
        parts[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    #[test]
    fn declarative_manager_forms_and_confirmation_fit_eighty_columns() {
        let mut state = State::new("/parsers");
        for (name, screen) in [
            ("declarative_list", Screen::List),
            ("declarative_test", Screen::Test),
            ("declarative_install", Screen::ConfirmInstall),
        ] {
            state.screen = screen;
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test backend");
            terminal
                .draw(|frame| {
                    paint(
                        frame,
                        &state,
                        "Only signed definitions are active.",
                        "Install parser-declarative-custom-access?\nSHA-256: synthetic-example",
                        &["definition.toml".into(), "sample.csv".into()],
                        Vec::new(),
                    );
                })
                .expect("render manager");
            let buffer = terminal.backend().buffer();
            let text = (0..24)
                .map(|y| {
                    (0..80)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                        .trim_end()
                        .to_owned()
                })
                .collect::<Vec<_>>()
                .join("\n");
            insta::assert_snapshot!(name, text);
        }
    }
}
