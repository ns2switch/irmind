use anyhow::Result;
use irmind_app::CaseId;
use ratatui::{
    Terminal,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(crate) struct CaseFrame<'a> {
    pub id: &'a CaseId,
    pub title: &'a str,
    pub messages: &'a str,
    pub input: &'a str,
    pub panel: &'a str,
    pub overlay: Option<&'a str>,
    pub tab: usize,
    pub tokens: u64,
    pub cost: &'a str,
    pub pending: usize,
    pub status: &'a str,
}

pub(crate) fn draw_case<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    view: &CaseFrame<'_>,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    terminal.draw(|frame| {
        let sections = Layout::vertical([
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());
        let columns =
            Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
                .split(sections[0]);
        let conversation = Paragraph::new(view.messages)
            .block(
                Block::default()
                    .title(format!(" Conversation · {} ", view.title))
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false })
            .scroll((
                u16::try_from(
                    view.messages
                        .lines()
                        .count()
                        .saturating_sub(usize::from(columns[0].height.saturating_sub(2))),
                )
                .unwrap_or(u16::MAX),
                0,
            ));
        frame.render_widget(conversation, columns[0]);
        let right =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(columns[1]);
        let titles = ["Timeline", "Evidence", "Audit", "Case", "Approvals", "IOCs", "Hypotheses", "ATT&CK", "All findings"];
        let title = titles.get(view.tab).copied().unwrap_or("Case");
        frame.render_widget(
            Paragraph::new(format!("{}  ({}/{}) · Tab next", title, view.tab + 1, titles.len()))
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL)),
            right[0],
        );
        let mut detail = Paragraph::new(view.overlay.unwrap_or(view.panel))
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        if view.tab == 4 && view.overlay.is_none() {
            detail = detail.style(Style::default().fg(Color::Yellow));
        }
        frame.render_widget(detail, right[1]);
        frame.render_widget(
            Paragraph::new(view.input)
                .block(Block::default().title(" Prompt ").borders(Borders::ALL)),
            sections[1],
        );
        frame.render_widget(
            Paragraph::new(Line::from(format!(
                "{} | {} tokens | {} | {} pending | {} | Tab panels | c confirm | Ctrl+K | /pause | Esc home",
                view.id.as_str(),
                view.tokens,
                view.cost,
                view.pending,
                view.status
            ))),
            sections[2],
        );
    })?;
    Ok(())
}
