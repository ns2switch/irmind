use super::{Fields, Screen, State};
use crate::skills::state::SourceKind;
use crate::theme::Theme;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
pub(super) fn source(frame: &mut Frame<'_>, area: Rect, state: &State, theme: Theme) {
    let index = match state.source {
        SourceKind::Local => 0,
        SourceKind::Catalog => 1,
        SourceKind::Offline => 2,
    };
    let list = List::new([
        ListItem::new("1. Local folder · SKILL.md and optional resources; no network"),
        ListItem::new("2. Catalog release · explicitly download, verify and review"),
        ListItem::new("3. Offline catalog · downloaded index, signature and package"),
    ])
    .highlight_style(theme.accent());
    frame.render_stateful_widget(
        list,
        area,
        &mut ListState::default().with_selected(Some(index)),
    );
}
pub(super) fn fields(
    frame: &mut Frame<'_>,
    body: Rect,
    footer: Rect,
    state: &State,
    fields: &Fields,
    theme: Theme,
) {
    let offline = state.screen == Screen::Offline;
    let rows = Layout::vertical(if offline {
        vec![Constraint::Length(3); 3]
    } else {
        vec![Constraint::Length(3); 2]
    })
    .split(body);
    let values = if offline {
        vec![
            (
                "Downloaded catalog folder",
                fields.folder.as_str(),
                "downloads/catalog-release",
            ),
            ("Skill name", fields.name.as_str(), "community-triage"),
            ("Frozen release tag", fields.tag.as_str(), "v1.2.3"),
        ]
    } else {
        vec![
            ("Skill name", fields.name.as_str(), "community-triage"),
            (
                "Release tag · empty means latest",
                fields.tag.as_str(),
                "v1.2.3",
            ),
        ]
    };
    for (index, (label, value, placeholder)) in values.into_iter().enumerate() {
        let style = if state.field == index {
            theme.accent()
        } else {
            theme.muted()
        };
        frame.render_widget(
            Paragraph::new(if value.is_empty() { placeholder } else { value })
                .style(if value.is_empty() {
                    theme.muted()
                } else {
                    ratatui::style::Style::default().fg(theme.text)
                })
                .block(Block::bordered().title(label).border_style(style)),
            rows[index],
        );
    }
    frame.render_widget(Paragraph::new(if offline {
        "No network. Select index.json, index.ed25519 and the package from the same downloaded release. Offline freshness is not guaranteed."
    } else { "Enter explicitly downloads a bounded package for review. Nothing installs until your signed confirmation." })
        .wrap(Wrap { trim: false }).style(theme.muted()), footer);
}
