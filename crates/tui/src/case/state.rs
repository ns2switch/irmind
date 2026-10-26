use super::{Confirmation, Instant, KeyCode, PathPicker};
use irmind_app::{ApprovalRequest, Case, Finding, SignedEntry, SignedOperation, TimelineEvent};

pub(super) struct CaseState {
    pub case: Case,
    pub input: String,
    pub messages: Vec<String>,
    pub approvals: Vec<ApprovalRequest>,
    pub findings: Vec<Finding>,
    pub tab: usize,
    pub selected_approval: usize,
    pub palette: Option<String>,
    pub picker: Option<PathPicker>,
    pub confirmation: Option<Confirmation>,
    pub confirmed_action: Option<Confirmation>,
    pub hashes: Vec<String>,
    pub entries: Vec<SignedEntry>,
    pub operations: Vec<SignedOperation>,
    pub timeline: Vec<TimelineEvent>,
    pub needs_refresh: bool,
    pub running_since: Option<Instant>,
}

pub(super) enum CaseMessage {
    Key(KeyCode, bool),
    Progress(String),
    TaskFinished(String),
}

pub(super) enum CaseAction {
    None,
    Exit,
    Submit(String),
    Approve(String),
}

/// Only updates screen state. I/O and tool execution follow the returned action.
pub(super) fn update(state: &mut CaseState, message: CaseMessage) -> CaseAction {
    match message {
        CaseMessage::Progress(text) | CaseMessage::TaskFinished(text) => {
            state.messages.push(text);
            if state.messages.len() > 30 {
                state.messages.drain(..state.messages.len() - 30);
            }
            CaseAction::None
        }
        CaseMessage::Key(code, busy) => match code {
            KeyCode::Esc => CaseAction::Exit,
            KeyCode::Tab => {
                state.tab = (state.tab + 1) % 6;
                CaseAction::None
            }
            KeyCode::Up if state.tab == 4 => {
                state.selected_approval = state.selected_approval.saturating_sub(1);
                CaseAction::None
            }
            KeyCode::Down
                if state.tab == 4 && state.selected_approval + 1 < state.approvals.len() =>
            {
                state.selected_approval += 1;
                CaseAction::None
            }
            KeyCode::Char('a') if state.tab == 4 && state.input.is_empty() && !busy => state
                .approvals
                .get(state.selected_approval)
                .map_or(CaseAction::None, |request| {
                    CaseAction::Approve(request.id.clone())
                }),
            KeyCode::Char('d') if state.tab == 4 && state.input.is_empty() && !busy => {
                if let Some(request) = state.approvals.get(state.selected_approval) {
                    state.input = format!("/deny {} ", request.id);
                }
                CaseAction::None
            }
            KeyCode::Char('e') if state.tab == 4 && state.input.is_empty() && !busy => {
                if let Some(request) = state.approvals.get(state.selected_approval) {
                    state.input = format!("/edit {} ", request.id);
                }
                CaseAction::None
            }
            KeyCode::Backspace => {
                state.input.pop();
                CaseAction::None
            }
            KeyCode::Char(ch) if state.input.len() < 20_000 => {
                state.input.push(ch);
                CaseAction::None
            }
            KeyCode::Enter => CaseAction::Submit(std::mem::take(&mut state.input)),
            _ => CaseAction::None,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::CaseId;

    #[test]
    fn input_update_is_pure_and_submits_exact_text() {
        let mut state = CaseState {
            case: irmind_app::Case {
                id: CaseId::parse("00000000-0000-0000-0000-000000000000").unwrap(),
                title: "Synthetic".into(),
                severity: irmind_app::Severity::Medium,
                scope: "local evidence only".into(),
                sealed: false,
            },
            input: String::new(),
            messages: Vec::new(),
            approvals: Vec::new(),
            findings: Vec::new(),
            tab: 0,
            selected_approval: 0,
            palette: None,
            picker: None,
            confirmation: None,
            confirmed_action: None,
            hashes: Vec::new(),
            entries: Vec::new(),
            operations: Vec::new(),
            timeline: Vec::new(),
            needs_refresh: false,
            running_since: None,
        };
        update(&mut state, CaseMessage::Key(KeyCode::Char('x'), false));
        assert!(
            matches!(update(&mut state, CaseMessage::Key(KeyCode::Enter, false)), CaseAction::Submit(value) if value == "x")
        );
        assert!(state.input.is_empty());
    }
}
