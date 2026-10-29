use super::command_registry;
use super::conversation::Conversation;
use super::{Confirmation, Instant, KeyCode, KeyModifiers, PathPicker};
use irmind_app::{
    ApprovalRequest, ApprovalSource, Case, Finding, FindingKind, SignedEntry, SignedOperation,
    TimelineEvent,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Focus {
    Composer,
    Conversation,
    Sidebar,
}

pub(super) struct CaseState {
    pub case: Case,
    pub input: String,
    pub input_history: Vec<String>,
    pub history_index: Option<usize>,
    pub messages: Vec<String>,
    pub result_cards: Vec<(&'static str, String)>,
    pub conversation: Conversation,
    pub audit_cursor: usize,
    pub live_reply_cutoff_seq: Option<u64>,
    pub pending_final_reply: Option<String>,
    pub usage_cache_seq: u64,
    pub usage_cache_tokens: u64,
    pub usage_cache_cost: String,
    pub turn_detection_count: usize,
    pub sidebar_visible: bool,
    pub sidebar_scroll: usize,
    pub overlay_scroll: usize,
    pub focus: Focus,
    pub menu_open: bool,
    pub menu_selected: usize,
    pub menu_query: Option<String>,
    pub model_preview: String,
    pub approvals: Vec<ApprovalRequest>,
    pub approval_sources: BTreeMap<String, ApprovalSource>,
    pub findings: Vec<Finding>,
    pub tab: usize,
    pub selected_approval: usize,
    pub approval_option: usize,
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
    pub progress_status: Option<String>,
}

pub(super) enum CaseMessage {
    Key(KeyCode, KeyModifiers, bool),
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
            if state.model_preview.len().saturating_add(text.len()) <= 16_384 {
                state.model_preview.push_str(&text);
            }
            CaseAction::None
        }
        CaseMessage::Progress(text) => {
            state.progress_status = Some(text);
            CaseAction::None
        }
        CaseMessage::TaskFinished(text) => {
            state.messages.push(text);
            CaseAction::None
        }
        CaseMessage::Key(code, modifiers, busy) => update_key(state, code, modifiers, busy),
    }
}

fn update_key(
    state: &mut CaseState,
    code: KeyCode,
    modifiers: KeyModifiers,
    busy: bool,
) -> CaseAction {
    if code == KeyCode::Esc {
        return CaseAction::Exit;
    }
    if code == KeyCode::Tab {
        state.sidebar_visible = true;
        state.focus = Focus::Sidebar;
        state.tab = (state.tab + 1) % TAB_COUNT;
        state.selected_finding = 0;
        return CaseAction::None;
    }
    if state.focus == Focus::Sidebar
        && let Some(action) = sidebar_action(state, code, modifiers, busy)
    {
        return action;
    }
    input_action(state, code, modifiers)
}

fn sidebar_action(
    state: &mut CaseState,
    code: KeyCode,
    modifiers: KeyModifiers,
    busy: bool,
) -> Option<CaseAction> {
    let shortcut = command_registry::shortcut_name(code, modifiers);
    match code {
        KeyCode::Up if state.tab == 4 => {
            state.selected_approval = state.selected_approval.saturating_sub(1);
        }
        KeyCode::Down if state.tab == 4 => {
            state.selected_approval =
                (state.selected_approval + 1).min(state.approvals.len().saturating_sub(1));
        }
        KeyCode::Up if state.tab >= 5 => {
            state.selected_finding = state.selected_finding.saturating_sub(1);
        }
        KeyCode::Down if state.tab >= 5 => {
            state.selected_finding =
                (state.selected_finding + 1).min(panel_findings(state).len().saturating_sub(1));
        }
        KeyCode::Char(_)
            if shortcut == Some("confirm") && state.tab >= 5 && state.input.is_empty() && !busy =>
        {
            return Some(
                panel_findings(state)
                    .get(state.selected_finding)
                    .filter(|finding| !finding.confirmed && !finding.dismissed)
                    .map_or(CaseAction::None, |finding| {
                        CaseAction::ConfirmFinding(finding.id.clone())
                    }),
            );
        }
        KeyCode::Char(_)
            if shortcut == Some("approve") && state.tab == 4 && state.input.is_empty() && !busy =>
        {
            return Some(
                state
                    .approvals
                    .get(state.selected_approval)
                    .map_or(CaseAction::None, |request| {
                        CaseAction::Approve(request.id.clone())
                    }),
            );
        }
        KeyCode::Char(_)
            if matches!(shortcut, Some("deny" | "edit"))
                && state.tab == 4
                && state.input.is_empty()
                && !busy =>
        {
            if let Some(request) = state.approvals.get(state.selected_approval) {
                let action = shortcut.unwrap_or("edit");
                state.input = format!("/{action} {} ", request.id);
                state.focus = Focus::Composer;
            }
        }
        _ => return None,
    }
    Some(CaseAction::None)
}

fn input_action(state: &mut CaseState, code: KeyCode, modifiers: KeyModifiers) -> CaseAction {
    match code {
        KeyCode::Backspace => {
            state.input.pop();
            state.menu_open = state.input.starts_with('/');
            CaseAction::None
        }
        KeyCode::Enter if modifiers.intersects(KeyModifiers::ALT | KeyModifiers::SHIFT) => {
            if state.input.len() < 20_000 {
                state.input.push('\n');
            }
            CaseAction::None
        }
        KeyCode::Up if state.input.is_empty() || !state.input.contains('\n') => {
            if !state.input_history.is_empty() {
                let next = state
                    .history_index
                    .unwrap_or(state.input_history.len())
                    .saturating_sub(1);
                state.history_index = Some(next);
                state.input = state.input_history[next].clone();
            }
            CaseAction::None
        }
        KeyCode::Down if state.history_index.is_some() => {
            let next = state.history_index.unwrap_or(0) + 1;
            if let Some(value) = state.input_history.get(next) {
                state.input = value.clone();
                state.history_index = Some(next);
            } else {
                state.input.clear();
                state.history_index = None;
            }
            CaseAction::None
        }
        KeyCode::Char(ch) if state.input.len() < 20_000 => {
            state.input.push(ch);
            state.history_index = None;
            state.menu_open = state.input.starts_with('/');
            CaseAction::None
        }
        KeyCode::Enter => {
            let input = std::mem::take(&mut state.input);
            if !input.is_empty() && state.input_history.last() != Some(&input) {
                state.input_history.push(input.clone());
            }
            state.history_index = None;
            state.menu_open = false;
            CaseAction::Submit(input)
        }
        _ => CaseAction::None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::CaseId;

    #[test]
    #[allow(clippy::too_many_lines)]
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
            input_history: Vec::new(),
            history_index: None,
            messages: Vec::new(),
            result_cards: Vec::new(),
            conversation: Conversation::new(false),
            audit_cursor: 0,
            live_reply_cutoff_seq: None,
            pending_final_reply: None,
            usage_cache_seq: 0,
            usage_cache_tokens: 0,
            usage_cache_cost: String::new(),
            turn_detection_count: 0,
            sidebar_visible: false,
            sidebar_scroll: 0,
            overlay_scroll: 0,
            focus: Focus::Composer,
            menu_open: false,
            menu_selected: 0,
            menu_query: None,
            model_preview: String::new(),
            approvals: Vec::new(),
            approval_sources: BTreeMap::new(),
            findings: Vec::new(),
            tab: 0,
            selected_approval: 0,
            approval_option: 0,
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
            progress_status: None,
        };
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Char('x'), KeyModifiers::NONE, false),
        );
        assert!(
            matches!(update(&mut state, CaseMessage::Key(KeyCode::Enter, KeyModifiers::NONE, false)), CaseAction::Submit(value) if value == "x")
        );
        assert!(state.input.is_empty());
        state.tab = 5;
        state.focus = Focus::Sidebar;
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
            update(&mut state, CaseMessage::Key(KeyCode::Char('c'), KeyModifiers::NONE, false)),
            CaseAction::ConfirmFinding(id) if id == "ioc-1"
        ));
        state.findings[0].confirmed = true;
        assert!(matches!(
            update(
                &mut state,
                CaseMessage::Key(KeyCode::Char('c'), KeyModifiers::NONE, false)
            ),
            CaseAction::None
        ));
        update(&mut state, CaseMessage::ModelDelta("partial answer".into()));
        assert_eq!(state.model_preview, "partial answer");
        state.model_preview.clear();
        update(&mut state, CaseMessage::ModelDelta("enrichment.".into()));
        update(&mut state, CaseMessage::ModelDelta(" The".into()));
        assert_eq!(state.model_preview, "enrichment. The");
        update(&mut state, CaseMessage::Progress("Ingested 1/1".into()));
        assert_eq!(state.progress_status.as_deref(), Some("Ingested 1/1"));
        assert!(state.messages.is_empty());
        state.focus = Focus::Composer;
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Char('a'), KeyModifiers::NONE, false),
        );
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Enter, KeyModifiers::ALT, false),
        );
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Char('b'), KeyModifiers::NONE, false),
        );
        assert!(matches!(
            update(&mut state, CaseMessage::Key(KeyCode::Enter, KeyModifiers::NONE, false)),
            CaseAction::Submit(value) if value == "a\nb"
        ));
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Up, KeyModifiers::NONE, false),
        );
        assert_eq!(state.input, "a\nb");
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Down, KeyModifiers::NONE, false),
        );
        assert!(state.input.is_empty());
        update(
            &mut state,
            CaseMessage::Key(KeyCode::Char('/'), KeyModifiers::NONE, false),
        );
        assert!(state.menu_open);
        assert!(crate::case::command_registry::matches(&state.input).len() > 5);
    }
}
