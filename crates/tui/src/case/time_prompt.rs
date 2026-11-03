use crossterm::event::{KeyCode, KeyModifiers};
use irmind_app::{
    AppError, ContentGuard, ParserTimeBasis, ParserTimeContext, ParserTimeRequirement,
    ParserTimeSuggestion,
};

pub(super) struct TimePrompt {
    pub source: String,
    year: String,
    offset: String,
    rollover: bool,
    all_files: bool,
    basis: ParserTimeBasis,
    focus: usize,
    suggestion: usize,
    suggestions: Vec<ParserTimeSuggestion>,
    requirement: ParserTimeRequirement,
    error: Option<String>,
}

pub(super) enum TimePromptAction {
    Keep,
    Cancel,
    Confirm {
        context: ParserTimeContext,
        all_files: bool,
    },
}

impl TimePrompt {
    pub(super) fn new(
        source: String,
        requirement: ParserTimeRequirement,
        suggestions: Vec<ParserTimeSuggestion>,
    ) -> Self {
        Self {
            source,
            year: String::new(),
            offset: String::new(),
            rollover: true,
            all_files: true,
            basis: ParserTimeBasis::Analyst,
            focus: 0,
            suggestion: 0,
            suggestions,
            requirement,
            error: None,
        }
    }
    pub(super) fn paste(&mut self, value: &str) {
        let limit = if self.focus == 0 { 4 } else { 6 };
        let target = match self.focus {
            0 => &mut self.year,
            1 => &mut self.offset,
            _ => return,
        };
        for ch in value.chars().filter(|ch| !ch.is_control()).take(limit) {
            if target.len() < limit {
                target.push(ch);
            }
        }
        self.basis = ParserTimeBasis::Analyst;
    }
    pub(super) fn update(&mut self, key: KeyCode, modifiers: KeyModifiers) -> TimePromptAction {
        match key {
            KeyCode::Esc => return TimePromptAction::Cancel,
            KeyCode::Tab => self.focus = (self.focus + 1) % 6,
            KeyCode::BackTab => self.focus = (self.focus + 5) % 6,
            KeyCode::Up if self.focus == 4 => self.suggestion = self.suggestion.saturating_sub(1),
            KeyCode::Down if self.focus == 4 => {
                self.suggestion =
                    (self.suggestion + 1).min(self.suggestions.len().saturating_sub(1));
            }
            KeyCode::Up => self.focus = self.focus.saturating_sub(1),
            KeyCode::Down => self.focus = (self.focus + 1).min(5),
            KeyCode::Backspace => {
                if self.focus == 0 {
                    self.year.pop();
                } else if self.focus == 1 {
                    self.offset.pop();
                }
                self.basis = ParserTimeBasis::Analyst;
            }
            KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                if self.focus == 0 {
                    self.year.clear();
                } else if self.focus == 1 {
                    self.offset.clear();
                }
                self.basis = ParserTimeBasis::Analyst;
            }
            KeyCode::Char(ch) if !ch.is_control() && !modifiers.contains(KeyModifiers::CONTROL) => {
                self.paste(&ch.to_string());
            }
            KeyCode::Enter => return self.enter(),
            _ => {}
        }
        TimePromptAction::Keep
    }
    fn enter(&mut self) -> TimePromptAction {
        match self.focus {
            0 | 1 => self.focus += 1,
            2 => {
                self.rollover = !self.rollover;
                self.basis = ParserTimeBasis::Analyst;
            }
            3 => self.all_files = !self.all_files,
            4 => {
                if let Some(suggestion) = self.suggestions.get(self.suggestion) {
                    self.year = format!("{:04}", suggestion.context.year());
                    self.offset = suggestion.context.offset_text();
                    self.basis = ParserTimeBasis::ConfirmedSuggestion;
                    self.focus = 5;
                }
            }
            5 => match ParserTimeContext::from_fields(
                &self.year,
                &self.offset,
                self.rollover,
                self.basis,
            ) {
                Ok(context) => {
                    return TimePromptAction::Confirm {
                        context,
                        all_files: self.all_files,
                    };
                }
                Err(error) => self.error = Some(error.to_string()),
            },
            _ => {}
        }
        TimePromptAction::Keep
    }
    pub(super) fn screened_text(&self, guard: &dyn ContentGuard) -> Result<String, AppError> {
        let mut rows = vec![
            format!("Confirm source time · {}", self.source),
            "No machine clock or file mtime is used. Confirm before ingestion.".into(),
        ];
        let mut hosts = Vec::new();
        for host in &self.requirement.hosts {
            host.inspect(|host| hosts.push(host.clone()));
        }
        if !hosts.is_empty() {
            rows.push(format!(
                "Logged host: {} (untrusted source data)",
                hosts.join(", ")
            ));
        }
        rows.extend([
            self.field(0, "First record year", &self.year, "YYYY"),
            self.field(1, "Fixed UTC offset", &self.offset, "+01:00"),
            format!(
                "{} December → January rollover: {} (inferred and signed)",
                self.marker(2),
                if self.rollover { "enabled" } else { "disabled" }
            ),
            format!(
                "{} Apply confirmed context: {}",
                self.marker(3),
                if self.all_files {
                    "all files in this ingestion"
                } else {
                    "this file only"
                }
            ),
        ]);
        if self.suggestions.is_empty() {
            rows.push("No verified same-host temporal suggestion is available.".into());
        }
        for (index, suggestion) in self.suggestions.iter().take(4).enumerate() {
            rows.push(format!(
                "{} Suggested {:04} {} · signed {}#{} · Enter copies, never auto-applies",
                if self.focus == 4 && index == self.suggestion {
                    ">"
                } else {
                    " "
                },
                suggestion.context.year(),
                suggestion.context.offset_text(),
                &suggestion.source_hash[..8.min(suggestion.source_hash.len())],
                suggestion.record_index
            ));
        }
        rows.push(format!(
            "{} Confirm and ingest · basis: {}",
            self.marker(5),
            self.basis.as_str()
        ));
        if let Some(error) = &self.error {
            rows.push(error.clone());
        }
        rows.push("Tab/Shift+Tab fields · ↑/↓ choose · Enter select · Esc cancel".into());
        Ok(guard.screen(&rows.join("\n"))?.text)
    }
    fn marker(&self, field: usize) -> &str {
        if self.focus == field { ">" } else { " " }
    }
    fn field(&self, focus: usize, label: &str, value: &str, placeholder: &str) -> String {
        format!(
            "{} ╭─ {label} ─────────╮\n  │ {}\n  ╰──────────────────────╯",
            self.marker(focus),
            if value.is_empty() { placeholder } else { value }
        )
    }
}

#[cfg(test)]
mod tests;
