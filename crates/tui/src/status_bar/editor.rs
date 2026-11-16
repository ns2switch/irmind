use super::{StatusData, render};
use crate::theme::Theme;
use crossterm::event::KeyCode;
use irmind_app::{StatusBarTemplate, StatusColor, StatusItem, StatusSegment};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Block, BorderType, Borders, List, ListState, Paragraph},
};

#[derive(Clone, Copy)]
enum Page {
    Main,
    Presets,
    Segments,
    Item(StatusSegment),
    Color(StatusSegment),
    Priority(StatusSegment),
    Separator,
}
pub(crate) enum Action {
    Keep,
    Cancel,
    Save(Option<StatusBarTemplate>),
}
pub(crate) struct Editor {
    pub template: StatusBarTemplate,
    page: Page,
    selected: usize,
    input: String,
    replace: bool,
    reset: bool,
    notice: String,
}
impl Editor {
    pub(crate) fn new(template: Option<&StatusBarTemplate>) -> Self {
        Self {
            template: template.cloned().unwrap_or_default(),
            page: Page::Main,
            selected: 0,
            input: String::new(),
            replace: false,
            reset: false,
            notice: String::new(),
        }
    }
    fn segments(&self) -> Vec<StatusSegment> {
        let mut result = self
            .template
            .segments
            .iter()
            .map(|i| i.segment)
            .collect::<Vec<_>>();
        result.extend(
            StatusSegment::ALL
                .into_iter()
                .filter(|s| !self.template.segments.iter().any(|i| i.segment == *s)),
        );
        result
    }
    fn rows(&self) -> Vec<String> {
        let values = match self.page {
            Page::Main => vec![
                "Choose preset".into(),
                "Segments and order".into(),
                format!("Separator: {}", self.template.separator),
                "Restore default".into(),
                "Save and sign".into(),
                "Cancel".into(),
            ],
            Page::Presets => ["Minimal", "Investigation", "Costs"]
                .map(str::to_owned)
                .to_vec(),
            Page::Segments => self
                .segments()
                .iter()
                .map(|s| {
                    let item = self.template.segments.iter().find(|i| i.segment == *s);
                    format!(
                        "[{}] {}{}",
                        if item.is_some() { "x" } else { " " },
                        s.label(),
                        item.map_or_else(String::new, |i| format!(
                            " · priority {} · {}",
                            i.priority,
                            i.color.label()
                        ))
                    )
                })
                .collect(),
            Page::Item(segment) => vec![
                format!("Enable/disable {}", segment.label()),
                "Move earlier".into(),
                "Move later".into(),
                "Priority (0–100)".into(),
                "Theme color".into(),
                "Back".into(),
            ],
            Page::Color(_) => StatusColor::ALL
                .iter()
                .map(|c| c.label().to_owned())
                .collect(),
            Page::Priority(_) | Page::Separator => Vec::new(),
        };
        values
            .into_iter()
            .enumerate()
            .map(|(i, row)| format!("{}. {row}", i + 1))
            .collect()
    }
    fn go(&mut self, page: Page) {
        self.page = page;
        self.selected = 0;
        self.input.clear();
        self.replace = false;
    }
    pub(crate) fn report(&mut self, notice: &str) {
        self.notice = super::flat(notice);
    }
    pub(crate) fn clear(&mut self) {
        self.input.clear();
        self.replace = false;
    }
    pub(crate) fn update(&mut self, key: KeyCode) -> Action {
        let editing = matches!(self.page, Page::Priority(_) | Page::Separator);
        match key {
            KeyCode::Esc => {
                if matches!(self.page, Page::Main) {
                    return Action::Cancel;
                }
                self.go(match self.page {
                    Page::Color(s) | Page::Priority(s) => Page::Item(s),
                    Page::Item(_) => Page::Segments,
                    _ => Page::Main,
                });
            }
            KeyCode::Up | KeyCode::BackTab if !editing => {
                self.selected = self.selected.saturating_sub(1);
                self.input.clear();
            }
            KeyCode::Down | KeyCode::Tab if !editing => {
                self.selected = (self.selected + 1).min(self.rows().len().saturating_sub(1));
                self.input.clear();
            }
            KeyCode::PageUp if !editing => self.selected = self.selected.saturating_sub(5),
            KeyCode::PageDown if !editing => {
                self.selected = (self.selected + 5).min(self.rows().len().saturating_sub(1));
            }
            KeyCode::Backspace => {
                self.replace = false;
                self.input.pop();
            }
            KeyCode::Char(ch) if !ch.is_control() && self.input.len() < 64 => {
                if self.replace {
                    self.input.clear();
                    self.replace = false;
                }
                self.input.push(ch);
            }
            KeyCode::Enter if editing => self.finish_field(),
            KeyCode::Enter => {
                let choice = if self.input.is_empty() {
                    Some(self.selected)
                } else {
                    self.input
                        .parse::<usize>()
                        .ok()
                        .and_then(|n| n.checked_sub(1))
                };
                self.input.clear();
                if let Some(choice) = choice.filter(|n| *n < self.rows().len()) {
                    return self.choose(choice);
                }
                self.notice = "Choose with arrows, or type an option number and Enter.".into();
            }
            _ => {}
        }
        Action::Keep
    }
    fn choose(&mut self, choice: usize) -> Action {
        self.notice.clear();
        match self.page {
            Page::Main => match choice {
                0 => self.go(Page::Presets), 1 => self.go(Page::Segments),
                2 => { self.go(Page::Separator); self.input = self.template.separator.clone(); self.replace = true; }
                3 => { self.template = StatusBarTemplate::default(); self.reset = true; self.notice = "Default restored in preview; save to sign it.".into(); }
                4 => match self.template.validate() {
                    Ok(()) => return Action::Save(if self.reset { None } else { Some(self.template.clone()) }),
                    Err(_) => self.notice = "Choose at least one segment and a separator of at most four printable characters.".into(),
                },
                _ => return Action::Cancel,
            },
            Page::Presets => { self.template = match choice { 0 => StatusBarTemplate::minimal(), 1 => StatusBarTemplate::investigation(), _ => StatusBarTemplate::costs() }; self.reset = false; self.go(Page::Main); }
            Page::Segments => { if let Some(segment) = self.segments().get(choice) { self.go(Page::Item(*segment)); } }
            Page::Item(segment) => self.choose_item(segment, choice),
            Page::Color(segment) => { if let Some(item) = self.template.segments.iter_mut().find(|i| i.segment == segment) { item.color = StatusColor::ALL[choice]; self.reset = false; } self.go(Page::Item(segment)); }
            _ => {}
        }
        Action::Keep
    }
    fn choose_item(&mut self, segment: StatusSegment, choice: usize) {
        let position = self
            .template
            .segments
            .iter()
            .position(|i| i.segment == segment);
        match (choice, position) {
            (0, Some(_)) if self.template.segments.len() == 1 => {
                self.notice = "Keep at least one segment.".into();
            }
            (0, Some(i)) => {
                self.template.segments.remove(i);
                self.reset = false;
            }
            (0, None) => {
                self.template.segments.push(StatusItem {
                    segment,
                    priority: 50,
                    color: StatusColor::Muted,
                });
                self.reset = false;
            }
            (1, Some(i)) if i > 0 => {
                self.template.segments.swap(i, i - 1);
                self.reset = false;
            }
            (2, Some(i)) if i + 1 < self.template.segments.len() => {
                self.template.segments.swap(i, i + 1);
                self.reset = false;
            }
            (3, Some(i)) => {
                let value = self.template.segments[i].priority;
                self.go(Page::Priority(segment));
                self.input = value.to_string();
                self.replace = true;
            }
            (4, Some(_)) => self.go(Page::Color(segment)),
            (5, _) => self.go(Page::Segments),
            (_, None) => self.notice = "Enable this segment before editing it.".into(),
            _ => {}
        }
    }
    fn finish_field(&mut self) {
        match self.page {
            Page::Priority(segment) => {
                if let Ok(value @ 0..=100) = self.input.parse::<u8>() {
                    if let Some(item) = self
                        .template
                        .segments
                        .iter_mut()
                        .find(|i| i.segment == segment)
                    {
                        item.priority = value;
                    }
                    self.reset = false;
                    self.go(Page::Item(segment));
                } else {
                    self.notice = "Enter an integer priority from 0 to 100.".into();
                }
            }
            Page::Separator => {
                let mut candidate = self.template.clone();
                candidate.separator.clone_from(&self.input);
                if candidate.validate().is_ok() {
                    self.template = candidate;
                    self.reset = false;
                    self.go(Page::Main);
                } else {
                    self.notice = "Use at most four printable separator characters.".into();
                }
            }
            _ => {}
        }
    }
    pub(crate) fn draw(&self, frame: &mut Frame<'_>, area: Rect) {
        let theme = Theme::detect();
        let parts = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area);
        frame.render_widget(
            Paragraph::new("Status bar · signed declarative preferences").style(theme.accent()),
            parts[0],
        );
        frame.render_widget(
            Paragraph::new(render(
                &self.template,
                &StatusData::preview(),
                usize::from(parts[1].width.saturating_sub(2)),
                theme,
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" Live preview · example values "),
            ),
            parts[1],
        );
        let mut selected = ListState::default();
        selected.select(Some(self.selected));
        frame.render_stateful_widget(
            List::new(self.rows())
                .highlight_symbol("› ")
                .highlight_style(theme.accent()),
            parts[2],
            &mut selected,
        );
        let label = match self.page {
            Page::Priority(_) => "Priority",
            Page::Separator => "Separator",
            _ => "Option number (optional)",
        };
        frame.render_widget(
            Paragraph::new(super::flat(&self.input))
                .block(Block::default().borders(Borders::ALL).title(label)),
            parts[3],
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{}\n↑/↓ choose · Enter confirm · Esc back",
                self.notice
            ))
            .style(theme.muted()),
            parts[4],
        );
    }
}
