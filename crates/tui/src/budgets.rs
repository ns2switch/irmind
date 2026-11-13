//! Shared analyst-only numeric form; no slash command is evaluated here.
use crossterm::event::KeyCode;
use irmind_app::{CaseBudgetLimits, CaseBudgetStatus, CaseBudgetUsage};

#[derive(Default)]
pub(crate) struct BudgetView {
    pub(crate) editor: Option<BudgetEditor>,
    pub(crate) warning: String,
    pub(crate) cost: String,
    pub(crate) usage_known: bool,
    pub(crate) warning_issued: bool,
}

pub(crate) enum BudgetAction {
    Keep,
    Cancel,
    Save(CaseBudgetLimits),
}
pub(crate) struct BudgetEditor {
    fields: [String; 3],
    selected: usize,
    replace: bool,
    review: bool,
    option: usize,
    typed_option: Option<usize>,
    ceiling: CaseBudgetLimits,
    usage: Option<CaseBudgetUsage>,
    initializing: bool,
    pub(crate) error: String,
}
impl BudgetEditor {
    pub(crate) fn new(
        limits: CaseBudgetLimits,
        ceiling: CaseBudgetLimits,
        usage: Option<CaseBudgetUsage>,
    ) -> Self {
        Self {
            fields: [
                limits.model_tokens.to_string(),
                limits.tool_calls.to_string(),
                limits.cloud_bytes.to_string(),
            ],
            selected: 0,
            replace: true,
            review: false,
            option: 0,
            typed_option: None,
            ceiling,
            usage,
            initializing: false,
            error: String::new(),
        }
    }
    pub(crate) fn for_case(status: CaseBudgetStatus) -> Self {
        let limits = status
            .allocated
            .unwrap_or_else(|| CaseBudgetLimits::default().intersection(status.organization));
        let mut editor = Self::new(limits, status.organization, Some(status.usage));
        editor.initializing = status.allocated.is_none();
        editor
    }
    pub(crate) fn clear(&mut self) {
        if !self.review {
            self.fields[self.selected].clear();
            self.replace = false;
        }
    }
    pub(crate) fn paste(&mut self, value: &str) {
        for ch in value.chars().filter(|ch| !ch.is_control()).take(32) {
            let _ = self.update(KeyCode::Char(ch));
        }
    }
    fn validate(&self) -> Result<CaseBudgetLimits, String> {
        let [tokens, calls, bytes] = &self.fields;
        let number = |s: &str| {
            s.parse::<u64>()
                .map_err(|_| "Enter a positive whole number in every field.".to_owned())
        };
        let limits = CaseBudgetLimits {
            model_tokens: number(tokens)?,
            tool_calls: number(calls)?,
            cloud_bytes: number(bytes)?,
        };
        limits.validate().map_err(|e| e.to_string())?;
        if !limits.within(self.ceiling) {
            return Err("An allocation cannot exceed the organization ceiling shown below.".into());
        }
        if self.usage.is_some_and(|used| !used.fits(limits)) {
            return Err("An allocation cannot be reduced below recorded consumption.".into());
        }
        Ok(limits)
    }
    pub(crate) fn update(&mut self, key: KeyCode) -> BudgetAction {
        if self.review {
            return self.review_key(key);
        }
        match key {
            KeyCode::Esc => return BudgetAction::Cancel,
            KeyCode::Tab | KeyCode::Down => {
                self.selected = (self.selected + 1) % 3;
                self.replace = true;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.selected = (self.selected + 2) % 3;
                self.replace = true;
            }
            KeyCode::Backspace => {
                self.fields[self.selected].pop();
                self.replace = false;
            }
            KeyCode::Char(ch) if !ch.is_control() => {
                if self.replace {
                    self.fields[self.selected].clear();
                    self.replace = false;
                }
                if self.fields[self.selected].len() + ch.len_utf8() <= 32 {
                    self.fields[self.selected].push(ch);
                }
            }
            KeyCode::Enter => match self.validate() {
                Ok(_) => {
                    self.review = true;
                    self.option = 0;
                    self.error.clear();
                }
                Err(error) => self.error = error,
            },
            _ => {}
        }
        BudgetAction::Keep
    }
    fn review_key(&mut self, key: KeyCode) -> BudgetAction {
        match key {
            KeyCode::Esc => {
                self.review = false;
                self.typed_option = None;
            }
            KeyCode::Up | KeyCode::BackTab => {
                self.option = 0;
                self.typed_option = None;
            }
            KeyCode::Down | KeyCode::Tab => {
                self.option = 1;
                self.typed_option = None;
            }
            KeyCode::Char('1') => self.typed_option = Some(0),
            KeyCode::Char('2') => self.typed_option = Some(1),
            KeyCode::Enter if self.typed_option.unwrap_or(self.option) == 0 => {
                return BudgetAction::Cancel;
            }
            KeyCode::Enter => match self.validate() {
                Ok(limits) => return BudgetAction::Save(limits),
                Err(error) => {
                    self.error = error;
                    self.review = false;
                }
            },
            _ => {}
        }
        BudgetAction::Keep
    }
    pub(crate) fn text(&self) -> String {
        let title = if self.initializing {
            "No signed case allocation · review and confirm"
        } else if self.usage.is_some() {
            "Case allocation · changes are signed"
        } else {
            "Effective defaults for new cases · signed configuration"
        };
        let mut lines = vec![title.to_owned()];
        if let Some(used) = self.usage {
            let tokens = if used.provider_usage_available {
                used.model_tokens.to_string()
            } else {
                format!("unavailable; reported at least {}", used.model_tokens)
            };
            lines.push(format!("Consumed: tokens {tokens}"));
            lines.push(format!(
                "Calls {} · reserved cloud bytes {}",
                used.tool_calls, used.cloud_bytes
            ));
            if used.provider_usage_available
                && let Some(cost) = used.cost_microusd
            {
                lines.push(format!(
                    "Estimated cost: ${}.{:06} USD",
                    cost / 1_000_000,
                    cost % 1_000_000
                ));
            }
        }
        for (i, (label, cap)) in [
            ("Model tokens", self.ceiling.model_tokens),
            ("Tool calls", self.ceiling.tool_calls),
            ("Cloud bytes", self.ceiling.cloud_bytes),
        ]
        .iter()
        .enumerate()
        {
            lines.push(format!(
                "{} {label} · organization ceiling {cap}",
                if i == self.selected { ">" } else { " " }
            ));
            lines.push(format!("┌──────────────────────────────────┐\n│ {:<32} │\n└──────────────────────────────────┘", self.fields[i]));
        }
        if self.review {
            lines.push("Confirm the allocation with your Analyst signature?".into());
            let selected = self.typed_option.unwrap_or(self.option);
            lines.push(format!(
                "{} 1. Cancel   {} 2. Confirm and sign",
                if selected == 0 { ">" } else { " " },
                if selected == 1 { ">" } else { " " }
            ));
        } else {
            lines.push("Tab / Shift+Tab choose field · Enter review · Esc back".into());
        }
        if !self.error.is_empty() {
            lines.push(self.error.clone());
        }
        crate::case::escape_display(&lines.join("\n"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend, widgets::Paragraph};
    fn editor() -> BudgetEditor {
        let limits = CaseBudgetLimits::default();
        BudgetEditor::new(limits, limits, None)
    }
    #[test]
    fn an_increase_requires_review_and_explicit_number_then_enter() {
        let mut form = editor();
        form.clear();
        form.paste("1000");
        assert!(matches!(form.update(KeyCode::Enter), BudgetAction::Keep));
        assert!(matches!(
            form.update(KeyCode::Char('2')),
            BudgetAction::Keep
        ));
        assert!(
            matches!(form.update(KeyCode::Enter), BudgetAction::Save(limits) if limits.model_tokens == 1000)
        );
    }
    #[test]
    fn pasted_slashes_and_newlines_are_field_data_and_invalid_limits_stay_visible() {
        let mut form = editor();
        form.paste("https://example.invalid/\n/budget");
        assert!(matches!(form.update(KeyCode::Enter), BudgetAction::Keep));
        assert!(!form.error.is_empty());
        assert!(form.text().contains("https://example.invalid//budget"));
        form.clear();
        form.paste("2000001");
        form.update(KeyCode::Enter);
        assert!(form.error.contains("ceiling"));
        assert!(matches!(form.update(KeyCode::Esc), BudgetAction::Cancel));
    }
    #[test]
    fn budget_form_at_80_columns() {
        let status = CaseBudgetStatus {
            allocated: Some(CaseBudgetLimits::default()),
            organization: CaseBudgetLimits::default(),
            effective: Some(CaseBudgetLimits::default()),
            usage: CaseBudgetUsage {
                model_tokens: 1_600_000,
                tool_calls: 800,
                cloud_bytes: 0,
                cost_microusd: None,
                provider_usage_available: true,
            },
        };
        assert!(status.warning());
        let form = BudgetEditor::for_case(status);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| frame.render_widget(Paragraph::new(form.text()), frame.area()))
            .unwrap();
        let rendered = (0..24)
            .map(|y| {
                (0..80)
                    .map(|x| terminal.backend().buffer()[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!("case_budget", rendered);
    }
}
