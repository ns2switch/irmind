mod narration;
use super::markdown;
use crate::menu_layout;
use crate::theme::Theme;
use anyhow::Result;
pub(super) use narration::{compact as presentation_compact, supported as presentation_supported};
use ratatui::{
    Terminal,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};
use unicode_width::UnicodeWidthStr;

pub(crate) struct CaseFrame<'a> {
    pub title: &'a str,
    pub guide: Option<&'a str>,
    pub guide_scroll: u16,
    pub messages: &'a str,
    pub visible_lines: Option<&'a [Line<'static>]>,
    pub input: &'a str,
    pub input_focused: bool,
    pub panel: &'a str,
    pub overlay: Option<&'a str>,
    pub menu: Option<&'a str>,
    pub tab: usize,
    pub sidebar_visible: bool,
    pub sidebar_scroll: u16,
    pub overlay_scroll: u16,
    pub new_content: bool,
    pub model: &'a str,
    pub tokens: u64,
    pub cost: &'a str,
    pub pending: usize,
    pub detections: usize,
    pub status: &'a str,
}

pub(crate) fn composer_height(input: &str, width: u16) -> u16 {
    let columns = usize::from(width.saturating_sub(4)).max(1);
    let lines = input
        .split('\n')
        .map(|line| line.chars().count().div_ceil(columns).max(1))
        .sum::<usize>();
    u16::try_from(lines.clamp(1, 5)).unwrap_or(5) + 2
}

pub(crate) fn conversation_area(
    area: Rect,
    input: &str,
    sidebar_visible: bool,
    guide_visible: bool,
) -> Rect {
    let sections = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(composer_height(input, area.width)),
        Constraint::Length(1),
        Constraint::Length(narration::height(area, guide_visible)),
    ])
    .split(area);
    let sidebar_visible = sidebar_visible && !(guide_visible && presentation_compact(area));
    if sidebar_visible && area.width >= 110 {
        Layout::horizontal([Constraint::Percentage(68), Constraint::Percentage(32)])
            .split(sections[0])[0]
    } else {
        sections[0]
    }
}

pub(crate) fn draw_case<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    view: &CaseFrame<'_>,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    terminal.draw(|frame| {
        let area = frame.area();
        let theme = Theme::detect();
        if view.guide.is_some() && !presentation_supported(area) {
            frame.render_widget(Paragraph::new(format!(
                "Demo presentation needs at least 80 × 24 cells. Recommended: 100 × 40.\nCurrent: {} × {}. Resize the terminal; Esc exits.", area.width, area.height
            )).style(Style::default().fg(theme.text)), area);
            return;
        }
        let sections = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(composer_height(view.input, area.width)),
            Constraint::Length(1),
            Constraint::Length(narration::height(area, view.guide.is_some())),
        ])
        .split(area);
        if let Some(guide) = view.guide {
            if presentation_compact(area) {
                narration::draw_compact(frame, guide, sections[3], view.guide_scroll, theme);
            } else {
                draw_guide(frame, guide, sections[3], theme);
            }
        }
        draw_thread(frame, view, area, sections[0], theme);
        draw_prompt(frame, view, sections[1], theme);
        draw_footer(frame, view, sections[2], theme);
        draw_menu(frame, view, area, sections[1], theme);
        let overlay_area = if view.status.starts_with("FULL INSTANCE SCOPE") {
            Rect::new(area.x, area.y, area.width, sections[2].y.saturating_sub(area.y))
        } else if view.guide.is_some() && presentation_compact(area) {
            Rect::new(area.x, area.y, area.width, sections[3].y.saturating_sub(area.y))
        } else if view.guide.is_some() { sections[0] } else { area };
        draw_overlay(frame, view, overlay_area, theme);
    })?;
    Ok(())
}

fn draw_guide(frame: &mut ratatui::Frame<'_>, guide: &str, area: Rect, theme: Theme) {
    frame.render_widget(
        Paragraph::new(guide)
            .style(Style::default().fg(theme.text))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(theme.accent)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_thread(
    frame: &mut ratatui::Frame<'_>,
    view: &CaseFrame<'_>,
    area: Rect,
    section: Rect,
    theme: Theme,
) {
    let sidebar_visible =
        view.sidebar_visible && !(view.guide.is_some() && presentation_compact(area));
    let columns = if sidebar_visible && area.width >= 110 {
        Some(
            Layout::horizontal([Constraint::Percentage(68), Constraint::Percentage(32)])
                .split(section),
        )
    } else {
        None
    };
    let chat_area = columns.as_ref().map_or(section, |columns| columns[0]);
    if !sidebar_visible || area.width >= 110 {
        let lines = view.visible_lines.map_or_else(
            || {
                view.messages
                    .lines()
                    .map(|line| Line::from(line.to_owned()))
                    .collect()
            },
            <[Line<'static>]>::to_vec,
        );
        frame.render_widget(
            Paragraph::new(lines)
                .style(Style::default().fg(theme.text))
                .block(if view.guide.is_some() {
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Live investigation ")
                        .border_style(theme.accent())
                } else {
                    Block::default()
                }),
            chat_area,
        );
        if view.new_content {
            frame.render_widget(
                Paragraph::new(" new content ↓ End ").style(theme.warning()),
                Rect::new(
                    chat_area.right().saturating_sub(22),
                    chat_area.y,
                    chat_area.width.min(22),
                    1,
                ),
            );
        }
    }
    if sidebar_visible {
        let side_area = columns.as_ref().map_or(section, |columns| columns[1]);
        let titles = [
            "Timeline",
            "Evidence",
            "Audit",
            "Case",
            "Approvals",
            "IOCs",
            "Hypotheses",
            "ATT&CK",
            "Findings",
        ];
        let title = titles.get(view.tab).copied().unwrap_or("Case");
        frame.render_widget(
            Paragraph::new(view.panel)
                .block(
                    Block::default()
                        .title(format!(" {title} · Tab next · Esc close "))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(theme.border)),
                )
                .wrap(Wrap { trim: false })
                .scroll((view.sidebar_scroll, 0)),
            side_area,
        );
    }
}

fn draw_prompt(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, section: Rect, theme: Theme) {
    let input_width = usize::from(section.width.saturating_sub(2)).max(1);
    let input_rows = markdown::render(view.input, input_width, false);
    let visible_count = usize::from(section.height.saturating_sub(2));
    let input_visible = input_rows
        .iter()
        .rev()
        .take(visible_count)
        .cloned()
        .collect::<Vec<_>>();
    let input_visible = input_visible.into_iter().rev().collect::<Vec<_>>();
    let shown = if view.input.is_empty() {
        vec![Line::from(if view.guide.is_some() {
            "Presentation types and runs each command here…"
        } else {
            "Ask about the case… · / for commands · /help for help"
        })]
    } else {
        input_visible.clone()
    };
    frame.render_widget(
        Paragraph::new(shown)
            .style(Style::default().fg(theme.text).bg(theme.user_background))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(theme.border)),
            ),
        section,
    );
    if view.input_focused && view.overlay.is_none() && visible_count > 0 {
        let width = input_visible
            .last()
            .map_or(0, |line| UnicodeWidthStr::width(line.to_string().as_str()));
        let col = u16::try_from(width)
            .unwrap_or(u16::MAX)
            .min(section.width.saturating_sub(3));
        let row = u16::try_from(input_visible.len().saturating_sub(1)).unwrap_or(u16::MAX);
        frame.set_cursor_position((
            section.x.saturating_add(1).saturating_add(col),
            section.y.saturating_add(1).saturating_add(row),
        ));
    }
}

fn draw_footer(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, section: Rect, theme: Theme) {
    let title = if view.title.chars().count() > 18 {
        format!("{}…", view.title.chars().take(17).collect::<String>())
    } else {
        view.title.to_owned()
    };
    let mut label = format!("{title} · {} · {} tok", view.model, view.tokens);
    if !view.cost.is_empty() && !matches!(view.cost, "n/a" | "cost n/a") {
        label.push_str(" · ");
        label.push_str(view.cost);
    }
    let mut spans = vec![Span::styled(label, theme.muted())];
    let status = if let Some(rest) = view.status.strip_prefix("FULL INSTANCE SCOPE · ") {
        spans.insert(0, Span::styled("FULL INSTANCE SCOPE · ", theme.warning()));
        rest
    } else {
        view.status
    };
    if view.pending > 0 {
        spans.push(Span::styled(
            format!(
                " · {} approval{} pending",
                view.pending,
                if view.pending == 1 { "" } else { "s" }
            ),
            theme.warning(),
        ));
    }
    if view.detections > 0 {
        spans.push(Span::styled(
            format!(" · {} detections", view.detections),
            theme.warning(),
        ));
    }
    if status != "idle" {
        spans.push(Span::styled(
            format!(" · {status}"),
            if status.contains("OVR") || status.contains("SCOPE LIMITED") {
                theme.warning()
            } else {
                theme.muted()
            },
        ));
    }
    if view.new_content {
        spans.push(Span::styled(" · End ↓", theme.warning()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            height: 1,
            ..section
        },
    );
}

fn draw_menu(
    frame: &mut ratatui::Frame<'_>,
    view: &CaseFrame<'_>,
    area: Rect,
    prompt_area: Rect,
    theme: Theme,
) {
    if let Some(menu) = view.menu {
        let rows = menu.lines().map(str::to_owned).collect::<Vec<_>>();
        let width = menu_layout::width(&rows, area.width);
        let height = u16::try_from(menu.lines().count().saturating_add(2))
            .unwrap_or(16)
            .min(16)
            .min(area.height.saturating_sub(3));
        let menu_area = Rect::new(area.x, prompt_area.y.saturating_sub(height), width, height);
        frame.render_widget(Clear, menu_area);
        let lines = rows
            .iter()
            .map(|line| {
                Line::styled(
                    menu_layout::clip(line, usize::from(width.saturating_sub(2))),
                    if line.starts_with('>') {
                        theme.accent()
                    } else if line.starts_with("· ") {
                        theme.muted()
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
            menu_area,
        );
    }
}

fn draw_overlay(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, area: Rect, theme: Theme) {
    if let Some(overlay) = view.overlay {
        let margin = if view.guide.is_some() && presentation_compact(frame.area()) {
            0
        } else {
            4
        };
        let width = area.width.saturating_sub(margin).clamp(1, 90);
        let height = area.height.saturating_sub(margin).clamp(1, 20);
        let box_area = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, box_area);
        frame.render_widget(
            Paragraph::new(overlay)
                .block(
                    Block::default()
                        .title(" Detail · PgUp/PgDn scroll · Esc close ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(theme.border)),
                )
                .wrap(Wrap { trim: false })
                .scroll((view.overlay_scroll, 0)),
            box_area,
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod compact_tests;
