use super::panel::{digest, label};
use crossterm::event::KeyCode;
use irmind_app::{
    CaseId,
    subagents::{PlanReview, SubagentRecord, SubagentTypeSnapshotV1},
};

pub(super) struct Review {
    pub(super) request: PlanReview,
    input: ReviewInput,
    pub(super) displayed: bool,
}
impl Review {
    pub(super) fn new(request: PlanReview) -> Self {
        Self {
            request,
            input: ReviewInput::default(),
            displayed: false,
        }
    }
    pub(super) fn text(&self) -> String {
        let preview = self.request.preview();
        let reservation = preview.reservation();
        let remaining = preview.remaining();
        let mut lines = vec![
            "Subagent plan".into(),
            format!(
                "{} tasks · reserve {} / {} remaining tokens · {} / {} calls",
                preview.tasks().len(),
                reservation.tokens,
                remaining.tokens,
                reservation.calls,
                remaining.calls
            ),
            format!(
                "{} rounds · {} cloud bytes",
                reservation.rounds, reservation.cloud_bytes
            ),
            String::new(),
        ];
        for task in preview.tasks() {
            let kind = CaseId::parse(preview.case_id())
                .ok()
                .and_then(|case| {
                    irmind_app::subagents::bundled_subagent_types()
                        .ok()
                        .and_then(|types| {
                            types
                                .into_iter()
                                .find(|kind| {
                                    SubagentTypeSnapshotV1::new(&case, kind.id()).is_ok_and(
                                        |value| {
                                            value.identity().ok() == Some(task.type_snapshot_sha256)
                                        },
                                    )
                                })
                                .map(|kind| kind.id().to_owned())
                        })
                })
                .unwrap_or_else(|| "Subagent".into());
            lines.push(format!(
                "{}. {} · {}",
                task.ordinal + 1,
                label(&kind),
                task.objective
            ));
            lines.push(format!(
                "   Source set {} · {} tokens · {} calls · {}",
                &digest(task.source_set_sha256)[..8],
                task.budget.tokens,
                task.budget.calls,
                task.remote_scope
                    .as_deref()
                    .unwrap_or("local evidence only")
            ));
        }
        lines.push(String::new());
        if preview.confirmation_required() {
            lines.push("Analyst confirmation required before any child starts.".into());
            lines.push(format!(
                "{} 1. Start",
                if self.input.selected == 0 { "›" } else { " " }
            ));
            lines.push(format!(
                "{} 2. Cancel",
                if self.input.selected == 1 { "›" } else { " " }
            ));
            lines.push(format!("Choice: {}", self.input.typed));
            if !self.input.error.is_empty() {
                lines.push(self.input.error.clone());
            }
            lines.push("↑/↓ choose · Enter confirm · Esc cancel".into());
        } else {
            lines.push("Starting automatically within the reviewed budget. Esc cancels.".into());
        }
        lines.push(format!("Plan {}", &digest(preview.plan_id())[..8]));
        lines.join("\n")
    }
    pub(super) fn key(&mut self, code: KeyCode) -> Option<bool> {
        self.input.key(code)
    }
    pub(super) fn paste(&mut self, value: &str) {
        self.input.paste(value);
    }
}
#[derive(Default)]
struct ReviewInput {
    selected: u8,
    typed: String,
    error: String,
}
impl ReviewInput {
    pub(super) fn key(&mut self, code: KeyCode) -> Option<bool> {
        match code {
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                self.selected = 1 - self.selected;
            }
            KeyCode::Enter => {
                return match self.typed.as_str() {
                    "" => Some(self.selected == 0),
                    "1" => Some(true),
                    "2" => Some(false),
                    _ => {
                        self.error = "Choose 1 or 2, then press Enter.".into();
                        None
                    }
                };
            }
            KeyCode::Esc => return Some(false),
            KeyCode::Char(value)
                if !value.is_control() && self.typed.len() + value.len_utf8() <= 32 =>
            {
                self.typed.push(value);
            }
            KeyCode::Backspace => {
                self.typed.pop();
            }
            _ => {}
        }
        None
    }
    pub(super) fn paste(&mut self, value: &str) {
        for ch in value.chars().filter(|ch| !ch.is_control()) {
            if self.typed.len() + ch.len_utf8() <= 32 {
                self.typed.push(ch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_printable_keys_and_paste_require_enter_and_invalid_choices_stay_open() {
        let mut input = ReviewInput::default();
        for key in ['a', 'd', '1', '/'] {
            assert_eq!(input.key(KeyCode::Char(key)), None);
        }
        assert_eq!(input.typed, "ad1/");
        assert_eq!(input.key(KeyCode::Enter), None);
        assert!(!input.error.is_empty());
        let mut input = ReviewInput::default();
        input.paste("1\n2\r");
        assert_eq!(input.typed, "12");
        assert_eq!(input.key(KeyCode::Enter), None);
        input.key(KeyCode::Backspace);
        assert_eq!(input.key(KeyCode::Enter), Some(true));
        let mut input = ReviewInput::default();
        assert_eq!(input.key(KeyCode::Down), None);
        assert_eq!(input.key(KeyCode::Enter), Some(false));
        assert_eq!(input.key(KeyCode::Esc), Some(false));
        input.paste(&"x".repeat(100));
        assert_eq!(input.typed.len(), 32);
    }
}
