use super::{HomeState, HomeVisual, Rect, Theme};
use ratatui::{
    style::Style,
    text::Line,
    widgets::{Block, BorderType, Borders, Paragraph},
};

const REMOTE: [(usize, &str, &str); 7] = [
    (2, "Sources", "siem-splunk,cloud-aws"),
    (3, "Accounts", "123456789012"),
    (4, "Projects", "security-project"),
    (5, "Hosts", "host.example"),
    (6, "Object prefixes", "s3://bucket/logs/"),
    (7, "From UTC", "2026-10-23T00:00:00Z"),
    (8, "To UTC", "2026-10-24T00:00:00Z"),
];

pub(super) fn draw(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    visual: &HomeVisual<'_>,
    theme: Theme,
) {
    if state.remote_scope_step.is_remote() {
        draw_remote(frame, area, state, visual, theme);
    } else {
        draw_local(frame, area, state, visual, theme);
    }
}

fn field_block(label: &str, focused: bool, theme: Theme) -> Block<'static> {
    Block::default()
        .title(label.to_owned())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if focused { theme.accent } else { theme.border }))
}

fn draw_local(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    visual: &HomeVisual<'_>,
    theme: Theme,
) {
    draw_line(
        frame,
        area,
        0,
        "Local case · remote scope is optional",
        theme.muted(),
    );
    let title = if visual.form[0].is_empty() {
        "For example: unusual role assumption"
    } else {
        &visual.form[0]
    };
    frame.render_widget(
        Paragraph::new(title)
            .style(if visual.form[0].is_empty() {
                theme.muted()
            } else {
                Style::default().fg(theme.text)
            })
            .block(field_block("Title *", state.form_field == 0, theme)),
        Rect::new(area.x, area.y.saturating_add(2), area.width, 3),
    );
    if let Some(issue) = visual.form_check.issues[0] {
        draw_line(frame, area, 5, issue, Style::default().fg(theme.error));
    }
    draw_severity(frame, area, state, theme);
    draw_line(
        frame,
        area,
        14,
        "Remote scope (optional) › Enter to edit",
        if state.form_field == 2 {
            theme.accent()
        } else {
            theme.muted()
        },
    );
    draw_line(
        frame,
        area,
        16,
        "Enter creates a local case.",
        theme.muted(),
    );
    if !visual.notice.is_empty() {
        draw_line(
            frame,
            area,
            18,
            visual.notice,
            Style::default().fg(theme.error),
        );
    }
}

fn draw_severity(frame: &mut ratatui::Frame<'_>, area: Rect, state: &HomeState, theme: Theme) {
    let lines = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (value, label))| {
        let selected = state.form[1] == value;
        let row = format!(
            "{} {}. {label}",
            if selected { ">" } else { " " },
            index + 1
        );
        Line::styled(
            row,
            if selected {
                theme.accent()
            } else {
                theme.muted()
            },
        )
    })
    .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(field_block("Severity · ↑/↓", state.form_field == 1, theme)),
        Rect::new(area.x, area.y.saturating_add(7), area.width, 6),
    );
}

fn draw_remote(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    state: &HomeState,
    visual: &HomeVisual<'_>,
    theme: Theme,
) {
    draw_line(
        frame,
        area,
        0,
        "Remote scope · Esc returns to local case",
        theme.muted(),
    );
    let left_width = area.width / 2;
    for (position, (index, label, example)) in REMOTE.into_iter().enumerate() {
        let column = position % 2;
        let row = position / 2;
        let x = area.x + if column == 0 { 0 } else { left_width };
        let width = if column == 0 {
            left_width.saturating_sub(1)
        } else {
            area.width.saturating_sub(left_width)
        };
        let y = area
            .y
            .saturating_add(1 + u16::try_from(row).unwrap_or(0) * 4);
        let text = if visual.form[index].is_empty() {
            example
        } else {
            &visual.form[index]
        };
        frame.render_widget(
            Paragraph::new(text)
                .style(if visual.form[index].is_empty() {
                    theme.muted()
                } else {
                    Style::default().fg(theme.text)
                })
                .block(field_block(label, state.form_field == index, theme)),
            Rect::new(x, y, width, 3),
        );
        if let Some(issue) = visual.form_check.issues[index] {
            frame.render_widget(
                Paragraph::new(issue).style(Style::default().fg(theme.error)),
                Rect::new(x, y.saturating_add(3), width, 1),
            );
        }
    }
    if let Some(issue) = visual.form_check.scope_issue {
        draw_line(frame, area, 18, issue, Style::default().fg(theme.error));
    } else if !visual.notice.is_empty() {
        draw_line(
            frame,
            area,
            18,
            visual.notice,
            Style::default().fg(theme.error),
        );
    }
}

fn draw_line(frame: &mut ratatui::Frame<'_>, area: Rect, row: u16, text: &str, style: Style) {
    if row >= area.height {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::styled(text.to_owned(), style)),
        Rect::new(area.x, area.y + row, area.width, 1),
    );
}
