use super::command_registry;
use super::markdown;
use anyhow::Result;
use irmind_app::CaseId;
use ratatui::{
    Terminal,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use unicode_width::UnicodeWidthStr;

pub(crate) struct CaseFrame<'a> {
    pub id: &'a CaseId,
    pub title: &'a str,
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

pub(crate) fn conversation_area(area: Rect, input: &str, sidebar_visible: bool) -> Rect {
    let sections = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(composer_height(input, area.width)),
        Constraint::Length(2),
    ])
    .split(area);
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
        let sections = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(composer_height(view.input, area.width)),
            Constraint::Length(2),
        ])
        .split(area);
        draw_thread(frame, view, area, sections[0]);
        draw_prompt(frame, view, sections[1]);
        draw_footer(frame, view, sections[2]);
        draw_menu(frame, view, area, sections[1]);
        draw_overlay(frame, view, area);
    })?;
    Ok(())
}

fn draw_thread(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, area: Rect, section: Rect) {
    let columns = if view.sidebar_visible && area.width >= 110 {
        Some(
            Layout::horizontal([Constraint::Percentage(68), Constraint::Percentage(32)])
                .split(section),
        )
    } else {
        None
    };
    let chat_area = columns.as_ref().map_or(section, |columns| columns[0]);
    if !view.sidebar_visible || area.width >= 110 {
        let lines = view.visible_lines.map_or_else(
            || {
                view.messages
                    .lines()
                    .map(|line| Line::from(line.to_owned()))
                    .collect()
            },
            <[Line<'static>]>::to_vec,
        );
        let title = if view.new_content {
            format!(" {} · new content ↓ ", view.title)
        } else {
            format!(" {} ", view.title)
        };
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().title(title).borders(Borders::ALL)),
            chat_area,
        );
    }
    if view.sidebar_visible {
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
                        .title(format!(" {title} · Tab next · Ctrl+B close "))
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false })
                .scroll((view.sidebar_scroll, 0)),
            side_area,
        );
    }
}

fn draw_prompt(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, section: Rect) {
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
    frame.render_widget(
        Paragraph::new(input_visible.clone()).block(
            Block::default()
                .title(" Prompt · Enter send · Alt/Shift+Enter newline ")
                .borders(Borders::ALL),
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

fn draw_footer(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, section: Rect) {
    let case_short = view.id.as_str().chars().take(8).collect::<String>();
    let model_short = view.model.chars().take(12).collect::<String>();
    let status = format!(
        "{case_short} | {model_short} | {} tok | {} | {} appr | {} det | {}{}",
        view.tokens,
        view.cost,
        view.pending,
        view.detections,
        view.status,
        if view.new_content { " | End↓" } else { "" }
    );
    frame.render_widget(
        Paragraph::new(status),
        Rect {
            height: 1,
            ..section
        },
    );
    frame.render_widget(
        Paragraph::new(command_registry::help_bar())
            .style(Style::default().add_modifier(Modifier::DIM)),
        Rect {
            y: section.y.saturating_add(1),
            height: 1,
            ..section
        },
    );
}

fn draw_menu(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, area: Rect, prompt_area: Rect) {
    if let Some(menu) = view.menu {
        let width = area.width.clamp(1, 72);
        let height = u16::try_from(menu.lines().count().saturating_add(2))
            .unwrap_or(10)
            .min(10);
        let menu_area = Rect::new(area.x, prompt_area.y.saturating_sub(height), width, height);
        frame.render_widget(Clear, menu_area);
        frame.render_widget(
            Paragraph::new(menu).block(Block::default().title(" Commands ").borders(Borders::ALL)),
            menu_area,
        );
    }
}

fn draw_overlay(frame: &mut ratatui::Frame<'_>, view: &CaseFrame<'_>, area: Rect) {
    if let Some(overlay) = view.overlay {
        let width = area.width.saturating_sub(4).clamp(1, 90);
        let height = area.height.saturating_sub(4).clamp(1, 20);
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
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false })
                .scroll((view.overlay_scroll, 0)),
            box_area,
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn screen(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn narrow_terminal_keeps_prompt_and_new_content_indicator() {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let id = CaseId::parse("00000000-0000-0000-0000-000000000000").unwrap();
        let lines = vec![
            Line::from("Analyst: synthetic alert"),
            Line::from("IRMind: finding"),
        ];
        let view = CaseFrame {
            id: &id,
            title: "Synthetic",
            messages: "",
            visible_lines: Some(&lines),
            input: "first line\nsecond line",
            input_focused: true,
            panel: "timeline",
            overlay: None,
            menu: Some("> /verify verify custody"),
            tab: 0,
            sidebar_visible: false,
            sidebar_scroll: 0,
            overlay_scroll: 0,
            new_content: true,
            model: "fake",
            tokens: 12,
            cost: "$0",
            pending: 1,
            detections: 1,
            status: "idle",
        };
        draw_case(&mut terminal, &view).unwrap();
        let shown = screen(&terminal);
        assert!(shown.contains("new content"));
        assert!(shown.contains("Analyst: synthetic alert"));
        assert!(shown.contains("second line"));
        assert!(shown.contains("/verify"));
        assert!(shown.contains("fake"));
        assert_eq!(
            conversation_area(Rect::new(0, 0, 80, 24), view.input, false).width,
            80
        );
    }

    #[test]
    fn expanded_card_and_scrolled_sidebar_are_visible_in_test_backend() {
        use crate::case::conversation::{Card, CardKind, Conversation};
        let mut chat = Conversation::new(false);
        chat.set_viewport(48, 12);
        chat.push(Card::new(
            CardKind::ToolResult,
            "Tool result",
            "x".repeat(2_000),
            false,
        ));
        let id = CaseId::parse("00000000-0000-0000-0000-000000000000").unwrap();
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        let lines = chat.visible_lines();
        let mut view = CaseFrame {
            id: &id,
            title: "Synthetic",
            messages: "",
            visible_lines: Some(&lines),
            input: "",
            input_focused: false,
            panel: "line zero\nline one\nline two",
            overlay: None,
            menu: None,
            tab: 0,
            sidebar_visible: true,
            sidebar_scroll: 1,
            overlay_scroll: 0,
            new_content: false,
            model: "fake",
            tokens: 0,
            cost: "n/a",
            pending: 0,
            detections: 0,
            status: "idle",
        };
        draw_case(&mut terminal, &view).unwrap();
        assert!(screen(&terminal).contains("hidden"));
        assert!(screen(&terminal).contains("line one"));
        chat.toggle_selected();
        let expanded_lines = chat.visible_lines();
        view.visible_lines = Some(&expanded_lines);
        draw_case(&mut terminal, &view).unwrap();
        assert!(!screen(&terminal).contains("hidden"));
        assert!(screen(&terminal).contains("xxxxxxxx"));
    }
}
