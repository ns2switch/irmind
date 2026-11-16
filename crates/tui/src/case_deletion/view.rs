use super::{CaseDeletionInventory, Form, Result, Terminal};
use crate::{case::escape_display, theme::Theme};
use ratatui::{
    backend::Backend,
    layout::{Constraint, Layout},
    style::Style,
    text::Line,
    widgets::{Block, BorderType, Paragraph, Wrap},
};
pub(super) fn message<B: Backend>(terminal: &mut Terminal<B>, title: &str, body: &str) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    terminal.draw(|frame| {
        let theme = Theme::detect();
        let area =
            Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(frame.area());
        frame.render_widget(
            Paragraph::new(escape_display(title)).style(Style::default().fg(theme.text)),
            area[0],
        );
        frame.render_widget(
            Paragraph::new(escape_display(body))
                .wrap(Wrap { trim: false })
                .style(theme.muted()),
            area[1],
        );
    })?;
    Ok(())
}
pub(super) fn form<B: Backend>(
    terminal: &mut Terminal<B>,
    safe: &impl Fn(&str) -> Result<String>,
    inventory: &CaseDeletionInventory,
    form: &Form,
    confirm_exit: bool,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let title = safe(&inventory.title)?;
    let confirmation = safe(&form.confirmation)?;
    let reason = safe(&form.reason)?;
    let created = i64::try_from(inventory.created_at)
        .ok()
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
        .map_or_else(
            || format!("UTC epoch {}", inventory.created_at),
            |value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
    let notice = safe(if confirm_exit {
        "Exit IRMind? Enter confirms; Esc cancels."
    } else {
        &form.notice
    })?;
    terminal.draw(|frame| {
        let theme = Theme::detect();
        let areas = Layout::vertical([Constraint::Length(1),Constraint::Min(5),Constraint::Length(3),Constraint::Length(3),Constraint::Length(1),Constraint::Length(2),Constraint::Length(1)]).split(frame.area());
        frame.render_widget(Paragraph::new("Delete unsealed case · Analyst signature required").style(theme.warning()),areas[0]);
        frame.render_widget(Paragraph::new(format!("{title}\n{} · created {}\n{} entries · {} sources · {} owned bytes\n{} shared blob bytes · {} logical metadata bytes\nDeletes chain, Parquet, spools, proofs, skill snapshots and branches.\nExternal originals stay. Shared blobs stay while another case uses them.\nLogical deletion only; use disk encryption for sensitive evidence.",inventory.case_id.as_str(),created,inventory.entry_count,inventory.source_count,inventory.owned_file_bytes,inventory.shared_blob_bytes,inventory.logical_metadata_bytes)).wrap(Wrap{trim:false}).style(Style::default().fg(theme.text)),areas[1]);
        for (index, (name,value)) in [("Exact title or case ID",confirmation.as_str()),("Reason (optional)",reason.as_str())].into_iter().enumerate() {
            let border = if form.focus == index { theme.accent() } else { theme.muted() };
            frame.render_widget(Paragraph::new(value).style(Style::default().fg(theme.text)).block(Block::bordered().border_type(BorderType::Rounded).title(name).border_style(border)), areas[index+2]);
        }
        let option = |text: &'static str,selected: bool| if form.focus == 2 && selected { ratatui::text::Span::styled(text,theme.accent()) } else { ratatui::text::Span::styled(text,theme.muted()) };
        frame.render_widget(Paragraph::new(Line::from(vec![option("1. Cancel",!form.delete), ratatui::text::Span::raw("     "), option("2. Sign and delete",form.delete)])),areas[4]);
        frame.render_widget(Paragraph::new(notice).wrap(Wrap{trim:false}).style(theme.warning()),areas[5]);
        frame.render_widget(Paragraph::new("Tab fields · ←/→ choose · Enter confirm · Esc cancel").style(Style::default().fg(theme.muted)),areas[6]);
    })?;
    Ok(())
}
