use super::markdown;
use crate::theme::Theme;
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};
use unicode_width::UnicodeWidthStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CardKind {
    Welcome,
    Analyst,
    Model,
    Proposal,
    Approval(String),
    ToolResult,
    Finding,
    Notice,
}

pub(super) struct Card {
    pub kind: CardKind,
    title: String,
    body: String,
    summary: Option<String>,
    markdown: bool,
    collapsed: bool,
    approval_option: usize,
    lines: Vec<Line<'static>>,
}

impl Card {
    pub(super) fn new(
        kind: CardKind,
        title: impl Into<String>,
        body: impl Into<String>,
        markdown: bool,
    ) -> Self {
        let body = body.into();
        let collapsed = matches!(kind, CardKind::Proposal | CardKind::ToolResult)
            || matches!(kind, CardKind::Notice)
                && (body.len() > 1_200 || body.lines().count() > 10);
        Self {
            kind,
            title: title.into(),
            body,
            summary: None,
            markdown,
            collapsed,
            approval_option: 0,
            lines: Vec::new(),
        }
    }

    pub(super) fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    fn preview(&self) -> String {
        if !self.collapsed {
            return self.body.clone();
        }
        let summary = self.summary.as_deref().unwrap_or("Detail available");
        format!("⎿ {summary}  (ctrl+o to expand)")
    }

    fn layout(&mut self, width: usize, color: bool) {
        let theme = if color {
            Theme::detect()
        } else {
            Theme::plain()
        };
        if matches!(self.kind, CardKind::Approval(_)) {
            self.layout_approval(width, theme);
            return;
        }
        if matches!(self.kind, CardKind::Welcome) {
            self.layout_welcome(width, theme);
            return;
        }
        if matches!(self.kind, CardKind::Analyst | CardKind::Model) {
            self.layout_message(width, theme);
            return;
        }
        let (heading, style) = match self.kind {
            CardKind::Analyst | CardKind::Model => (String::new(), theme.muted()),
            CardKind::Welcome => (
                format!("╭─ {} ─", self.title),
                theme.accent().add_modifier(Modifier::BOLD),
            ),
            CardKind::Approval(_) => ("Approval".into(), theme.warning()),
            CardKind::Proposal | CardKind::ToolResult => {
                (format!("⏺ {}", self.title), theme.accent())
            }
            CardKind::Notice => (self.body.lines().next().unwrap_or("").into(), theme.muted()),
            CardKind::Finding => (format!("⏺ {}", self.title), theme.muted()),
        };
        self.lines = vec![Line::from(Span::styled(heading, style))];
        if matches!(self.kind, CardKind::Notice) {
            self.lines.push(Line::default());
            return;
        }
        if matches!(self.kind, CardKind::Proposal | CardKind::ToolResult) {
            if self.collapsed {
                self.lines.push(Line::styled(self.preview(), theme.muted()));
            } else {
                if let Some(summary) = &self.summary {
                    self.lines
                        .push(Line::styled(format!("⎿ {summary}"), theme.muted()));
                }
                for line in markdown::render(&self.body, width.saturating_sub(2), false) {
                    self.lines
                        .push(Line::styled(format!("  {line}"), theme.muted()));
                }
            }
            self.lines.push(Line::default());
            return;
        }
        self.lines.extend(markdown::render(
            &self.preview(),
            width,
            self.markdown && !self.collapsed,
        ));
        self.lines.push(Line::default());
    }

    fn layout_message(&mut self, width: usize, theme: Theme) {
        let analyst = matches!(self.kind, CardKind::Analyst);
        let prefix = if analyst { "> " } else { "⏺ " };
        let base = Style::default().fg(theme.text).bg(theme.user_background);
        self.lines = markdown::render(&self.body, width.saturating_sub(2), self.markdown)
            .into_iter()
            .enumerate()
            .map(|(index, line)| {
                let marker = if index == 0 { prefix } else { "  " };
                let mut spans = vec![Span::styled(
                    marker,
                    if analyst { base } else { theme.accent() },
                )];
                spans.extend(line.spans);
                let mut output = Line::from(spans);
                if analyst {
                    let padding =
                        width.saturating_sub(UnicodeWidthStr::width(output.to_string().as_str()));
                    output.spans.push(Span::raw(" ".repeat(padding)));
                    output = output.style(base);
                }
                output
            })
            .collect();
        self.lines.push(Line::default());
    }

    fn layout_approval(&mut self, width: usize, theme: Theme) {
        let width = width.max(20);
        let heading = " Approval required ";
        self.lines = vec![Line::from(Span::styled(
            format!(
                "╭─{heading}{}╮",
                "─".repeat(width.saturating_sub(UnicodeWidthStr::width(heading) + 3))
            ),
            theme.warning(),
        ))];
        for line in markdown::render(&self.body, width.saturating_sub(4), false) {
            self.lines
                .push(bordered_line(&line.to_string(), width, theme));
        }
        let labels = ["Approve", "Deny with reason", "Edit arguments"];
        for (index, label) in labels.iter().enumerate() {
            let marker = if index == self.approval_option {
                "›"
            } else {
                " "
            };
            self.lines.push(bordered_line(
                &format!("{marker} {}. {label}", index + 1),
                width,
                theme,
            ));
        }
        self.lines.push(Line::from(Span::styled(
            format!("╰{}╯", "─".repeat(width.saturating_sub(2))),
            theme.warning(),
        )));
        self.lines.push(Line::default());
    }

    fn layout_welcome(&mut self, width: usize, theme: Theme) {
        let width = width.max(20);
        let heading = format!(" {} ", self.title);
        self.lines = vec![Line::from(Span::styled(
            format!(
                "╭─{heading}{}╮",
                "─".repeat(width.saturating_sub(UnicodeWidthStr::width(heading.as_str()) + 3))
            ),
            theme.accent(),
        ))];
        for line in markdown::render(&self.body, width.saturating_sub(4), false) {
            let text = line.to_string();
            let padding = width.saturating_sub(UnicodeWidthStr::width(text.as_str()) + 4);
            self.lines.push(Line::from(vec![
                Span::styled("│ ", theme.accent()),
                Span::raw(text),
                Span::styled(format!("{} │", " ".repeat(padding)), theme.accent()),
            ]));
        }
        self.lines.push(Line::from(Span::styled(
            format!("╰{}╯", "─".repeat(width.saturating_sub(2))),
            theme.accent(),
        )));
        self.lines.push(Line::default());
    }

    fn toggle(&mut self, width: usize, color: bool) {
        self.collapsed = !self.collapsed;
        self.layout(width, color);
    }
}

fn bordered_line(text: &str, width: usize, theme: Theme) -> Line<'static> {
    let visible = text.replace(['⟦', '⟧'], "");
    let padding = width.saturating_sub(UnicodeWidthStr::width(visible.as_str()).saturating_add(4));
    let mut spans = vec![Span::styled("│ ", theme.warning())];
    if let Some((before, rest)) = text.split_once('⟦')
        && let Some((value, after)) = rest.split_once('⟧')
    {
        spans.push(Span::raw(before.to_owned()));
        spans.push(Span::styled(
            value.to_owned(),
            theme.warning().add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(after.to_owned()));
    } else {
        spans.push(Span::raw(text.to_owned()));
    }
    spans.push(Span::styled(
        format!("{} │", " ".repeat(padding)),
        theme.warning(),
    ));
    Line::from(spans)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SelectionState {
    Passive,
    Navigating,
}

pub(super) struct Conversation {
    cards: Vec<Card>,
    offsets: Vec<usize>,
    total_lines: usize,
    width: usize,
    viewport: usize,
    scroll: usize,
    selected: Option<usize>,
    selection_state: SelectionState,
    preview: Option<usize>,
    follow_tail: bool,
    new_content: bool,
    color: bool,
}

impl Conversation {
    pub(super) fn new(color: bool) -> Self {
        Self {
            cards: Vec::new(),
            offsets: Vec::new(),
            total_lines: 0,
            width: 80,
            viewport: 20,
            scroll: 0,
            selected: None,
            selection_state: SelectionState::Passive,
            preview: None,
            follow_tail: true,
            new_content: false,
            color,
        }
    }

    pub(super) fn push(&mut self, mut card: Card) {
        card.layout(self.width, self.color);
        self.offsets.push(self.total_lines);
        self.total_lines += card.lines.len();
        self.cards.push(card);
        if self.follow_tail {
            self.scroll = self.max_scroll();
            self.selected = Some(self.cards.len() - 1);
            self.selection_state = SelectionState::Passive;
        } else {
            self.new_content = true;
        }
    }

    pub(super) fn begin_preview(&mut self) {
        self.push(Card::new(
            CardKind::Model,
            "IRMind · streaming",
            "Thinking…",
            true,
        ));
        self.preview = Some(self.cards.len() - 1);
    }

    pub(super) fn set_preview(&mut self, text: String) {
        let Some(index) = self.preview else { return };
        if let Some(card) = self.cards.get_mut(index) {
            card.body = if text.is_empty() {
                "Thinking…".into()
            } else {
                text
            };
            card.layout(self.width, self.color);
            self.recalculate_from(index);
            self.content_changed();
        }
    }

    pub(super) fn discard_preview(&mut self) {
        let Some(index) = self.preview.take() else {
            return;
        };
        self.cards.remove(index);
        self.offsets.remove(index);
        self.recalculate_from(index);
        self.selected = self.cards.len().checked_sub(1);
        self.content_changed();
    }

    pub(super) fn finish_preview(&mut self) {
        self.preview = None;
    }

    fn content_changed(&mut self) {
        if self.follow_tail {
            self.scroll = self.max_scroll();
        } else {
            self.new_content = true;
        }
    }

    fn recalculate_from(&mut self, index: usize) {
        let mut cursor = self.offsets.get(index).copied().unwrap_or_else(|| {
            self.offsets
                .last()
                .zip(self.cards.last())
                .map_or(0, |(offset, card)| offset + card.lines.len())
        });
        for current in index..self.cards.len() {
            self.offsets[current] = cursor;
            cursor += self.cards[current].lines.len();
        }
        self.total_lines = cursor;
    }

    pub(super) fn set_viewport(&mut self, width: usize, height: usize) {
        let width = width.max(1);
        self.viewport = height.max(1);
        if width != self.width {
            self.width = width;
            self.total_lines = 0;
            for (index, card) in self.cards.iter_mut().enumerate() {
                card.layout(width, self.color);
                self.offsets[index] = self.total_lines;
                self.total_lines += card.lines.len();
            }
        }
        self.scroll = if self.follow_tail {
            self.max_scroll()
        } else {
            self.scroll.min(self.max_scroll())
        };
    }

    pub(super) fn scroll_by(&mut self, delta: isize) {
        self.selection_state = SelectionState::Navigating;
        self.scroll = self
            .scroll
            .saturating_add_signed(delta)
            .min(self.max_scroll());
        self.follow_tail = self.scroll == self.max_scroll();
        if self.follow_tail {
            self.new_content = false;
        }
        self.selected = self.card_at(self.scroll);
    }

    pub(super) fn jump_start(&mut self) {
        self.selection_state = SelectionState::Navigating;
        self.scroll = 0;
        self.follow_tail = self.max_scroll() == 0;
        self.selected = (!self.cards.is_empty()).then_some(0);
    }

    pub(super) fn jump_end(&mut self) {
        self.selection_state = SelectionState::Navigating;
        self.scroll = self.max_scroll();
        self.follow_tail = true;
        self.new_content = false;
        self.selected = self.cards.len().checked_sub(1);
    }

    pub(super) fn select_by(&mut self, delta: isize) {
        if self.cards.is_empty() {
            return;
        }
        self.selection_state = SelectionState::Navigating;
        let current = self.selected.unwrap_or(0);
        let next = current
            .saturating_add_signed(delta)
            .min(self.cards.len() - 1);
        self.selected = Some(next);
        let top = self.offsets[next];
        let bottom = top + self.cards[next].lines.len();
        if top < self.scroll {
            self.scroll = top;
        } else if bottom > self.scroll + self.viewport {
            self.scroll = bottom.saturating_sub(self.viewport);
        }
        self.follow_tail = self.scroll == self.max_scroll();
    }

    pub(super) fn toggle_selected(&mut self) {
        let Some(index) = self.selected else { return };
        self.selection_state = SelectionState::Navigating;
        if let Some(card) = self.cards.get_mut(index) {
            card.toggle(self.width, self.color);
            self.recalculate_from(index);
            self.scroll = self.scroll.min(self.max_scroll());
        }
    }

    pub(super) fn selected_approval(&self) -> Option<&str> {
        match &self.selected.and_then(|index| self.cards.get(index))?.kind {
            CardKind::Approval(id) => Some(id),
            _ => None,
        }
    }

    pub(super) fn set_approval_option(&mut self, option: usize) {
        let Some(index) = self.selected else {
            return;
        };
        let Some(card) = self.cards.get_mut(index) else {
            return;
        };
        if matches!(card.kind, CardKind::Approval(_)) && card.approval_option != option {
            card.approval_option = option.min(2);
            card.layout(self.width, self.color);
            self.recalculate_from(index);
        }
    }

    pub(super) fn visible_lines(&self) -> Vec<Line<'static>> {
        let mut lines = Vec::with_capacity(self.viewport);
        let Some(mut card_index) = self.card_at(self.scroll) else {
            return lines;
        };
        let mut line_index = self.scroll - self.offsets[card_index];
        while lines.len() < self.viewport && card_index < self.cards.len() {
            let card = &self.cards[card_index];
            while line_index < card.lines.len() && lines.len() < self.viewport {
                let mut line = card.lines[line_index].clone();
                if line_index == 0
                    && self.selection_state == SelectionState::Navigating
                    && self.selected == Some(card_index)
                {
                    let modifier = if self.color {
                        Modifier::REVERSED
                    } else {
                        Modifier::BOLD
                    };
                    line = line.style(Style::default().add_modifier(modifier));
                }
                lines.push(line);
                line_index += 1;
            }
            card_index += 1;
            line_index = 0;
        }
        lines
    }

    pub(super) fn has_new_content(&self) -> bool {
        self.new_content
    }

    pub(super) fn viewport(&self) -> usize {
        self.viewport
    }

    fn card_at(&self, line: usize) -> Option<usize> {
        if self.cards.is_empty() {
            return None;
        }
        Some(
            self.offsets
                .partition_point(|offset| *offset <= line)
                .saturating_sub(1),
        )
    }

    fn max_scroll(&self) -> usize {
        self.total_lines.saturating_sub(self.viewport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_follows_tail_only_while_reader_is_at_tail() {
        let mut chat = Conversation::new(false);
        chat.set_viewport(25, 4);
        for index in 0..8 {
            chat.push(Card::new(
                CardKind::Notice,
                format!("{index}"),
                "body",
                false,
            ));
        }
        chat.scroll_by(-3);
        let before = chat.scroll;
        chat.push(Card::new(CardKind::Model, "IRMind", "new reply", true));
        assert_eq!(chat.scroll, before);
        assert!(chat.has_new_content());
        chat.jump_end();
        assert!(!chat.has_new_content());
        assert!(
            chat.visible_lines()
                .iter()
                .any(|line| line.to_string().contains("new reply"))
        );
    }

    #[test]
    fn long_tool_card_folds_and_expands_without_losing_other_cards() {
        let mut chat = Conversation::new(false);
        chat.set_viewport(40, 8);
        chat.push(Card::new(
            CardKind::ToolResult,
            "Tool",
            "x".repeat(2_000),
            false,
        ));
        assert!(chat.cards[0].collapsed);
        let folded = chat.total_lines;
        chat.toggle_selected();
        assert!(!chat.cards[0].collapsed);
        assert!(chat.total_lines > folded);
        chat.push(Card::new(CardKind::Notice, "Next", "done", false));
        assert_eq!(chat.cards.len(), 2);
    }

    #[test]
    fn messages_start_on_marker_line_and_selection_appears_only_after_navigation() {
        let mut chat = Conversation::new(false);
        chat.set_viewport(60, 12);
        chat.push(Card::new(
            CardKind::Analyst,
            "Analyst",
            "What happened?",
            false,
        ));
        chat.push(Card::new(
            CardKind::Model,
            "IRMind",
            "The role changed.",
            true,
        ));
        let lines = chat.visible_lines();
        assert!(
            lines
                .iter()
                .any(|line| line.to_string().starts_with("> What happened?"))
        );
        assert!(
            lines
                .iter()
                .filter(|line| line.to_string().starts_with("> What happened?"))
                .all(|line| UnicodeWidthStr::width(line.to_string().as_str()) == 60)
        );
        assert!(
            lines
                .iter()
                .any(|line| line.to_string().starts_with("⏺ The role changed."))
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.to_string().contains("⏺ IRMind"))
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.style.add_modifier.contains(Modifier::BOLD))
        );
        chat.select_by(-1);
        assert!(chat.visible_lines().iter().any(|line| {
            line.to_string().starts_with("> What happened?")
                && line.style.add_modifier.contains(Modifier::BOLD)
        }));
    }

    #[test]
    fn folded_tool_uses_status_and_keeps_exact_arguments_in_detail() {
        let mut card = Card::new(
            CardKind::Proposal,
            "VirusTotal lookup(example.com)",
            r#"ti_lookup_external {"ioc":"example.com"}"#,
            false,
        )
        .with_summary("waiting for approval");
        card.layout(80, false);
        let folded = card.lines.iter().map(Line::to_string).collect::<String>();
        assert!(folded.contains("⎿ waiting for approval"));
        assert!(!folded.contains("{\"ioc\""));
        card.toggle(80, false);
        let expanded = card.lines.iter().map(Line::to_string).collect::<String>();
        assert!(expanded.contains(r#"{"ioc":"example.com"}"#));
    }
}
