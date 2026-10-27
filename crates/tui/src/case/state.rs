use super::{Confirmation, Instant, KeyCode, PathPicker};
use irmind_app::{
    ApprovalRequest, ApprovalSource, Case, Finding, FindingKind, SignedEntry, SignedOperation,
    TimelineEvent,
};
use std::collections::BTreeMap;

pub(super) struct CaseState {
    pub case: Case,
    pub input: String,
    pub messages: Vec<String>,
    pub model_preview: String,
    pub approvals: Vec<ApprovalRequest>,
    pub approval_sources: BTreeMap<String, ApprovalSource>,
    pub findings: Vec<Finding>,
    pub tab: usize,
    pub selected_approval: usize,
    pub selected_finding: usize,
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
    ModelDelta(String),
    TaskFinished(String),
}

pub(super) enum CaseAction {
    None,
    Exit,
    Submit(String),
    Approve(String),
    ConfirmFinding(String),
}

pub(super) const TAB_COUNT: usize = 9;

pub(super) fn panel_findings(state: &CaseState) -> Vec<&Finding> {
    panel_findings_for(&state.findings, state.tab)
}

pub(crate) fn panel_findings_for(findings: &[Finding], tab: usize) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|finding| match tab {
            5 => finding.kind == FindingKind::Ioc,
            6 => finding.kind == FindingKind::Hypothesis,
            7 => finding.kind == FindingKind::Technique,
            8 => true,
            _ => false,
        })
        .collect()
}

/// Only updates screen state. I/O and tool execution follow the returned action.
pub(super) fn update(state: &mut CaseState, message: CaseMessage) -> CaseAction {
    match message {
        CaseMessage::ModelDelta(text) => {
            if state.model_preview.len().saturating_add(text.len()) <= 200_000 {
                state.model_preview.push_str(&text);
            }
            CaseAction::None
        }
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
                state.tab = (state.tab + 1) % TAB_COUNT;
                state.selected_finding = 0;
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
            KeyCode::Up if state.tab >= 5 => {
                state.selected_finding = state.selected_finding.saturating_sub(1);
                CaseAction::None
            }
            KeyCode::Down if state.tab >= 5 => {
                state.selected_finding =
                    (state.selected_finding + 1).min(panel_findings(state).len().saturating_sub(1));
                CaseAction::None
            }
            KeyCode::Char('c') if state.tab >= 5 && state.input.is_empty() && !busy => {
                panel_findings(state)
                    .get(state.selected_finding)
                    .filter(|finding| !finding.confirmed && !finding.dismissed)
                    .map_or(CaseAction::None, |finding| {
                        CaseAction::ConfirmFinding(finding.id.clone())
                    })
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
            model_preview: String::new(),
            approvals: Vec::new(),
            approval_sources: BTreeMap::new(),
            findings: Vec::new(),
            tab: 0,
            selected_approval: 0,
            selected_finding: 0,
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
        state.tab = 5;
        state.findings = vec![Finding {
            id: "ioc-1".into(),
            kind: FindingKind::Ioc,
            value: "203.0.113.9".into(),
            evidence_hash: "a".repeat(64),
            confirmed: false,
            dismissed: false,
            details: None,
        }];
        assert!(matches!(
            update(&mut state, CaseMessage::Key(KeyCode::Char('c'), false)),
            CaseAction::ConfirmFinding(id) if id == "ioc-1"
        ));
        state.findings[0].confirmed = true;
        assert!(matches!(
            update(&mut state, CaseMessage::Key(KeyCode::Char('c'), false)),
            CaseAction::None
        ));
        update(&mut state, CaseMessage::ModelDelta("partial answer".into()));
        assert_eq!(state.model_preview, "partial answer");
    }
}
