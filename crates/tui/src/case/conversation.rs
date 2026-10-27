use super::markdown;
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CardKind {
    Analyst,
    Model,
    Proposal,
    Approval(String),
    ToolResult,
    Finding,
    Evidence,
    Notice,
}

pub(super) struct Card {
    pub kind: CardKind,
    title: String,
    body: String,
    markdown: bool,
    collapsed: bool,
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
        let collapsed = matches!(
            kind,
            CardKind::ToolResult | CardKind::Evidence | CardKind::Notice
        ) && (body.len() > 1_200 || body.lines().count() > 10);
        Self {
            kind,
            title: title.into(),
            body,
            markdown,
            collapsed,
            lines: Vec::new(),
        }
    }

    fn preview(&self) -> String {
        if !self.collapsed {
            return self.body.clone();
        }
        let excerpt = self.body.chars().take(220).collect::<String>();
        format!(
            "{excerpt}…\n[{} bytes hidden · Enter/Space to expand]",
            self.body.len().saturating_sub(excerpt.len())
        )
    }

    fn layout(&mut self, width: usize, color: bool) {
        let mut style = Style::default().add_modifier(Modifier::BOLD);
        if color && matches!(self.kind, CardKind::Approval(_)) {
            style = style.add_modifier(Modifier::REVERSED);
        }
        let marker = if self.collapsed { "▸" } else { "▾" };
        self.lines = vec![Line::from(Span::styled(
            format!("{marker} {}", self.title),
            style,
        ))];
        self.lines.extend(markdown::render(
            &self.preview(),
            width,
            self.markdown && !self.collapsed,
        ));
        self.lines.push(Line::default());
    }

    fn toggle(&mut self, width: usize, color: bool) {
        self.collapsed = !self.collapsed;
        self.layout(width, color);
    }
}

pub(super) struct Conversation {
    cards: Vec<Card>,
    offsets: Vec<usize>,
    total_lines: usize,
    width: usize,
    viewport: usize,
    scroll: usize,
    selected: Option<usize>,
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
        self.scroll = 0;
        self.follow_tail = self.max_scroll() == 0;
        self.selected = (!self.cards.is_empty()).then_some(0);
    }

    pub(super) fn jump_end(&mut self) {
        self.scroll = self.max_scroll();
        self.follow_tail = true;
        self.new_content = false;
        self.selected = self.cards.len().checked_sub(1);
    }

    pub(super) fn select_by(&mut self, delta: isize) {
        if self.cards.is_empty() {
            return;
        }
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
                if line_index == 0 && self.selected == Some(card_index) {
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
}
