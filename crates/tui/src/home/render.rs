use super::{
    Backend, Block, Borders, CaseStatus, Constraint, Engine, HomeState, Layout, Line, List,
    ListItem, LlmPort, Mode, ModuleStatus, Paragraph, Result, Style, Terminal, case, hex, model,
    sha256,
};
use crate::theme::Theme;
use ratatui::{
    layout::Rect,
    widgets::{BorderType, Clear, ListState},
};
use unicode_width::UnicodeWidthStr;

struct HomeVisual<'a> {
    title: &'a str,
    summary: &'a str,
    notice: &'a str,
    input: &'a str,
    has_model: bool,
    form: &'a [String],
    form_check: &'a super::new_case::FormCheck,
    module_detail: &'a [String],
}

pub(crate) fn render_home<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &HomeState,
    engine: &Engine<'_>,
    modules: &[ModuleStatus],
    model: Option<&dyn LlmPort>,
    new_analyst_key: bool,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let safe = |value: &str| -> Result<String> { Ok(engine.guard.screen(value)?.text) };
    let content = home_items(state, engine, modules, model, new_analyst_key)?;
    let title = safe(&format!("IRMind v{}", env!("CARGO_PKG_VERSION")))?;
    let keystore = state.keystore.as_ref().map_or_else(
        || "not loaded".to_owned(),
        |status| format!("{} / {}", status.signer_backend, status.secrets_backend),
    );
    let summary = safe(&format!(
        "Keystore: {keystore} · Model: {}",
        model.map_or_else(
            || "No model · /settings model to configure".to_owned(),
            LlmPort::descriptor,
        )
    ))?;
    let notice = safe(&if state.confirm_exit == crate::ExitConfirmation::Pending {
        "Exit IRMind? Enter confirms; Esc cancels.".to_owned()
    } else {
        state.notice.clone()
    })?;
    let input = safe(&state.input)?;
    let safe_form = state
        .form
        .iter()
        .map(|value| safe(value))
        .collect::<Result<Vec<_>>>()?;
    let form_check = super::new_case::check(state, engine);
    let module_detail = if state.mode == Mode::Modules {
        items::module_detail(state, modules, &|value| Ok(case::escape_display(value)))?
    } else {
        Vec::new()
    };
    let menu = home_menu_rows(state, &safe)?;
    let visual = HomeVisual {
        title: &title,
        summary: &summary,
        notice: &notice,
        input: &input,
        has_model: model.is_some(),
        form: &safe_form,
        form_check: &form_check,
        module_detail: &module_detail,
    };
    let mut list_state = home_list_state(state);
    terminal.draw(|frame| {
        let theme = Theme::detect();
        let areas =
            Layout::vertical([Constraint::Min(4), Constraint::Length(1)]).split(frame.area());
        if state.mode == Mode::List {
            draw_list_screen(frame, areas[0], state, &visual, content, &menu, theme);
        } else if state.mode == Mode::Settings {
            draw_settings_screen(frame, areas[0], &visual, content, &mut list_state, theme);
        } else {
            draw_dialog_screen(
                frame,
                areas[0],
                state,
                &visual,
                content,
                &mut list_state,
                theme,
            );
        }
        frame.render_widget(
            Paragraph::new(help_line(state)).style(theme.muted()),
            areas[1],
        );
    })?;
    Ok(())
}

fn draw_settings_screen(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    visual: &HomeVisual<'_>,
    content: Vec<ListItem<'static>>,
    selected: &mut ListState,
    theme: Theme,
) {
    frame.render_widget(
        Paragraph::new(visual.title.to_owned()).style(theme.accent()),
        Rect::new(area.x, area.y, area.width, 1),
    );
    frame.render_widget(
        Paragraph::new("Settings · choose a section").style(theme.muted()),
        Rect::new(area.x, area.y.saturating_add(2), area.width, 1),
    );
    frame.render_stateful_widget(
        List::new(content),
        Rect::new(
            area.x.saturating_add(2),
            area.y.saturating_add(4),
            area.width.saturating_sub(2),
            area.height.saturating_sub(4),
        ),
        selected,
    );
    if !visual.notice.is_empty() {
        frame.render_widget(
            Paragraph::new(visual.notice.to_owned()).style(theme.warning()),
            Rect::new(area.x, area.bottom().saturating_sub(1), area.width, 1),
        );
    }
}

fn draw_list_screen(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    visual: &HomeVisual<'_>,
    content: Vec<ListItem<'static>>,
    menu: &[String],
    theme: Theme,
) {
    let rows = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(area);
    draw_home_header(
        frame,
        rows[0],
        visual.title,
        visual.summary,
        visual.notice,
        theme,
    );
    draw_case_list(frame, rows[1], state, content, visual.has_model, theme);
    draw_home_input(frame, rows[2], state, visual.input, theme);
    draw_home_menu(frame, rows[2], menu, theme);
}

fn draw_home_header(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    title: &str,
    summary: &str,
    notice: &str,
    theme: Theme,
) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(title.to_owned(), theme.accent()),
            Line::styled("Assisted Incident Response", theme.muted()),
            Line::styled(summary.to_owned(), Style::default().fg(theme.text)),
            Line::styled(notice.to_owned(), theme.warning()),
        ]),
        area,
    );
}

fn draw_case_list(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    content: Vec<ListItem<'static>>,
    has_model: bool,
    theme: Theme,
) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);
    let filter = state.status_filter.map_or("all", CaseStatus::label);
    frame.render_widget(
        Paragraph::new(format!("Recent cases · {filter}")).style(theme.muted()),
        rows[0],
    );
    if state.rows.is_empty() {
        let mut lines = vec![Line::from("No cases yet · /new to create one")];
        if !has_model {
            lines.push(Line::styled(
                "No model? Use /settings model when you are ready to investigate.",
                theme.muted(),
            ));
        }
        frame.render_widget(Paragraph::new(lines), rows[1]);
    } else if content.is_empty() {
        frame.render_widget(
            Paragraph::new("No cases match this search or status."),
            rows[1],
        );
    } else {
        let mut selected = ListState::default().with_selected(Some(state.selected));
        frame.render_stateful_widget(
            List::new(content).highlight_style(theme.accent()),
            rows[1],
            &mut selected,
        );
    }
}

fn draw_home_input(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    input: &str,
    theme: Theme,
) {
    let placeholder = "Find cases or type / for commands · /help for help";
    let shown = if input.is_empty() { placeholder } else { input };
    frame.render_widget(
        Paragraph::new(shown)
            .style(Style::default().fg(theme.text).bg(theme.user_background))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(theme.border)),
            ),
        area,
    );
    if state.confirm_exit == crate::ExitConfirmation::Inactive {
        let width = UnicodeWidthStr::width(input).min(usize::from(area.width.saturating_sub(3)));
        frame.set_cursor_position((
            area.x + 1 + u16::try_from(width).unwrap_or(u16::MAX),
            area.y + 1,
        ));
    }
}

fn home_menu_rows(
    state: &HomeState,
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<String>> {
    if !state.input.starts_with('/') || state.mode != Mode::List {
        return Ok(Vec::new());
    }
    super::state::command_options(state)
        .into_iter()
        .take(9)
        .enumerate()
        .map(|(index, option)| {
            let name = option
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or("");
            let description = case::command_registry::matches(name)
                .into_iter()
                .find(|command| command.name == name)
                .map_or("Open a case", |command| command.description);
            safe(&format!(
                "{} {option} — {description}",
                if index == state.menu_selected {
                    ">"
                } else {
                    " "
                }
            ))
        })
        .collect()
}

fn draw_home_menu(frame: &mut ratatui::Frame<'_>, prompt: Rect, rows: &[String], theme: Theme) {
    if rows.is_empty() {
        return;
    }
    let width = crate::menu_layout::width(rows, prompt.width);
    let height = u16::try_from(rows.len().saturating_add(2))
        .unwrap_or(u16::MAX)
        .min(prompt.y.saturating_sub(frame.area().y));
    if height < 3 {
        return;
    }
    let area = Rect::new(prompt.x, prompt.y - height, width, height);
    frame.render_widget(Clear, area);
    let lines = rows
        .iter()
        .map(|row| {
            Line::styled(
                crate::menu_layout::clip(row, usize::from(width.saturating_sub(2))),
                if row.starts_with('>') {
                    theme.accent()
                } else {
                    Style::default().fg(theme.text)
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(" Commands ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border)),
        ),
        area,
    );
}

fn draw_dialog_screen(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    visual: &HomeVisual<'_>,
    content: Vec<ListItem<'static>>,
    selected: &mut ListState,
    theme: Theme,
) {
    frame.render_widget(
        Paragraph::new(visual.title.to_owned()).style(theme.accent()),
        Rect::new(area.x, area.y, area.width, 1),
    );
    let width = area.width.saturating_sub(4).clamp(1, 96);
    let height = area.height.saturating_sub(3).clamp(1, 25);
    let modal = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + 1 + area.height.saturating_sub(height + 1) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, modal);
    let block = Block::default()
        .title(home_header(state.mode))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border));
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    if state.mode == Mode::New {
        new_case::draw(frame, inner, state, visual, theme);
        return;
    }
    if state.mode == Mode::Modules {
        draw_modules(frame, inner, state, content, selected, visual, theme);
        return;
    }
    let content_area = Rect {
        height: inner.height.saturating_sub(2),
        ..inner
    };
    frame.render_stateful_widget(
        List::new(content).highlight_style(theme.accent()),
        content_area,
        selected,
    );
    if !visual.input.is_empty() {
        frame.render_widget(
            Paragraph::new(format!("> {}", visual.input)).style(Style::default().fg(theme.text)),
            Rect::new(inner.x, inner.bottom().saturating_sub(2), inner.width, 1),
        );
    }
    if !visual.notice.is_empty() {
        frame.render_widget(
            Paragraph::new(visual.notice.to_owned()).style(theme.warning()),
            Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        );
    }
}

fn draw_modules(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    content: Vec<ListItem<'static>>,
    selected: &mut ListState,
    visual: &HomeVisual<'_>,
    theme: Theme,
) {
    let split =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    frame.render_stateful_widget(
        List::new(content).highlight_style(theme.accent()),
        split[0],
        selected,
    );
    let status = state
        .modules
        .get(state.module_selected)
        .map(super::module_catalog::status);
    let lines = visual
        .module_detail
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let style = if index == 1 {
                match status {
                    Some(super::module_catalog::DisplayStatus::Active) => {
                        Style::default().fg(theme.success)
                    }
                    Some(super::module_catalog::DisplayStatus::Missing) => theme.warning(),
                    _ => theme.muted(),
                }
            } else {
                Style::default().fg(theme.text)
            };
            Line::styled(row.clone(), style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(ratatui::widgets::Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(theme.muted()),
            ),
        split[1],
    );
    if let Some(edit) = &state.module_edit {
        let box_area = Rect::new(
            split[1].x.saturating_add(2),
            split[1].bottom().saturating_sub(5),
            split[1].width.saturating_sub(3),
            3,
        );
        frame.render_widget(Clear, box_area);
        frame.render_widget(
            Paragraph::new(case::escape_display(&edit.value)).block(
                Block::default()
                    .title(edit.field.as_str())
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(theme.accent()),
            ),
            box_area,
        );
    }
}

fn home_header(mode: Mode) -> &'static str {
    match mode {
        Mode::List => " Cases ",
        Mode::Settings => " Settings ",
        Mode::New => " New case ",
        Mode::Model => " Model setup ",
        Mode::Modules => " Connectors ",
        Mode::Config => " Preferences ",
        Mode::Keystore => " Keystore ",
        Mode::Setup => " First-run guide ",
        Mode::Help => " Commands and keys ",
        Mode::VerifyExport => " Verify exported package ",
    }
}

fn home_list_state(state: &HomeState) -> ListState {
    let mut selected = ListState::default();
    match state.mode {
        Mode::Settings => selected.select(Some(state.settings_selected)),
        Mode::Model => match state.model_setup.step {
            model::ModelStep::Provider => selected.select(Some(state.model_setup.provider + 1)),
            model::ModelStep::AvailableModels if !state.model_setup.models.is_empty() => {
                selected.select(Some(state.model_setup.selected_model + 1));
            }
            _ => {}
        },
        Mode::Config => selected.select(Some(state.preference_selected)),
        Mode::Keystore => {
            let count = state
                .keystore
                .as_ref()
                .map_or(0, |status| status.credentials.len());
            selected.select(Some(if state.ui_selection.keystore_action_focus {
                4 + count + state.keystore_action_selected
            } else {
                3 + state.keystore_selected
            }));
        }
        Mode::Modules => {
            selected.select(Some(super::module_catalog::selected_row(
                &state.modules,
                state.module_selected,
            )));
        }
        Mode::Help => selected.select(Some(state.help_selected)),
        _ => {}
    }
    selected
}

mod items;
use items::home_items;
#[cfg(test)]
pub(super) use items::model_items;

mod help;
use help::help_line;

mod new_case;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
