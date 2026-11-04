use crate::{case::markdown, theme::Theme};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    widgets::{Block, BorderType, Borders, Paragraph},
};

pub(in crate::case) fn supported(area: Rect) -> bool {
    area.width >= 80 && area.height >= 24
}

pub(in crate::case) fn compact(area: Rect) -> bool {
    area.width < 100 || area.height < 40
}

pub(super) fn height(area: Rect, visible: bool) -> u16 {
    if !visible {
        0
    } else if compact(area) {
        9
    } else {
        14
    }
}

pub(super) fn draw_compact(
    frame: &mut ratatui::Frame<'_>,
    guide: &str,
    area: Rect,
    scroll: u16,
    theme: Theme,
) {
    let mut lines = guide.lines().collect::<Vec<_>>();
    let title = lines.first().copied().unwrap_or("Demo presentation");
    let controls = lines.pop().unwrap_or("");
    let (body, choices) = contents(lines.get(1..).unwrap_or_default());
    let controls = if controls.starts_with("Presentation complete") {
        "↑/↓ choose · Enter select · Backspace back · Esc exit
PgUp/PgDn read · Space pause/play"
    } else if controls.starts_with("Auto playing") {
        "Auto · Enter next · Backspace back · Space pause/play · Esc exit
PgUp/PgDn read"
    } else {
        "Paused · Enter next · Backspace back · Space pause/play · Esc exit
PgUp/PgDn read"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.accent())
        .title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(u16::try_from(choices.len()).unwrap_or(3)),
        Constraint::Length(2),
    ])
    .split(inner);
    let wrapped = markdown::render(&body, usize::from(inner.width), false);
    let max_scroll = wrapped.len().saturating_sub(usize::from(rows[0].height));
    let offset = usize::from(scroll).min(max_scroll);
    frame.render_widget(
        Paragraph::new(
            wrapped
                .into_iter()
                .skip(offset)
                .take(usize::from(rows[0].height))
                .collect::<Vec<_>>(),
        )
        .style(ratatui::style::Style::default().fg(theme.text)),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(choices.join("\n")).style(ratatui::style::Style::default().fg(theme.text)),
        rows[1],
    );
    frame.render_widget(Paragraph::new(controls).style(theme.muted()), rows[2]);
}

fn contents<'a>(lines: &[&'a str]) -> (String, Vec<&'a str>) {
    let mut body = Vec::new();
    let mut choices = Vec::new();
    for line in lines {
        let option = line.trim_start_matches([' ', '›']).trim_start();
        if ["1.", "2.", "3."]
            .iter()
            .any(|prefix| option.starts_with(prefix))
        {
            choices.push(*line);
        } else if line.starts_with("Presentation stopped:")
            || line.starts_with("Exit demo, run irmind")
        {
            body.insert(0, *line);
        } else if !line.is_empty() {
            body.push(*line);
        }
    }
    (body.join("\n"), choices)
}
