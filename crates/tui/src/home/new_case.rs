use super::{HomeState, KeyCode, Mode, RemoteScopeStep, state::HomeAction};
use irmind_app::{Engine, FixedAppError};

const SEVERITIES: [&str; 4] = ["low", "medium", "high", "critical"];

pub(super) fn update(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc if state.remote_scope_step.is_remote() => {
            state.remote_scope_step = RemoteScopeStep::Local;
            state.form_field = 2;
        }
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Tab => move_focus(state, true),
        KeyCode::BackTab => move_focus(state, false),
        KeyCode::Up | KeyCode::Down
            if !state.remote_scope_step.is_remote() && state.form_field == 1 =>
        {
            let current = SEVERITIES
                .iter()
                .position(|value| *value == state.form[1])
                .unwrap_or(1);
            let next = if key == KeyCode::Down {
                (current + 1) % SEVERITIES.len()
            } else {
                (current + SEVERITIES.len() - 1) % SEVERITIES.len()
            };
            state.form[1] = SEVERITIES[next].into();
        }
        KeyCode::Backspace if editable(state) => {
            state.form[state.form_field].pop();
        }
        KeyCode::Char(ch) if editable(state) && state.form[state.form_field].len() < 200 => {
            state.form[state.form_field].push(ch);
        }
        KeyCode::Enter if !state.remote_scope_step.is_remote() && state.form_field == 2 => {
            state.remote_scope_step = RemoteScopeStep::Remote;
        }
        KeyCode::Enter => return HomeAction::CreateCase,
        _ => {}
    }
    HomeAction::None
}

fn editable(state: &HomeState) -> bool {
    state.form_field == 0 || state.remote_scope_step.is_remote() && state.form_field >= 2
}

fn move_focus(state: &mut HomeState, forward: bool) {
    let (first, last) = if state.remote_scope_step.is_remote() {
        (2, 8)
    } else {
        (0, 2)
    };
    state.form_field = if forward {
        if state.form_field >= last {
            first
        } else {
            state.form_field + 1
        }
    } else if state.form_field <= first {
        last
    } else {
        state.form_field - 1
    };
}

#[derive(Default)]
pub(super) struct FormCheck {
    pub issues: [Option<&'static str>; 9],
    pub scope_issue: Option<&'static str>,
}

impl FormCheck {
    pub(super) fn first_issue(&self) -> Option<(usize, &'static str)> {
        self.issues
            .iter()
            .enumerate()
            .find_map(|(index, issue)| issue.map(|message| (index, message)))
            .or_else(|| self.scope_issue.map(|message| (2, message)))
    }
}

pub(super) fn check(state: &HomeState, engine: &Engine<'_>) -> FormCheck {
    let mut result = FormCheck::default();
    if state.form[0].trim().is_empty() {
        result.issues[0] = Some("A title is required.");
    }
    let remote = state.remote_scope_step.is_remote()
        || state.form[2..].iter().any(|value| !value.is_empty());
    if !remote {
        return result;
    }
    if state.form[2].trim().is_empty() {
        result.issues[2] = Some("Add at least one source.");
    }
    if state.form[3..=6].iter().all(String::is_empty) {
        result.issues[3] = Some("Add an account, project, host, or prefix.");
    }
    for index in [7, 8] {
        if !valid_utc(&state.form[index]) {
            result.issues[index] = Some("Use UTC, for example 2026-10-23T00:00:00Z.");
        }
    }
    if result.issues.iter().all(Option::is_none)
        && let Err(error) = engine.validate_case_scope(&state.scope())
    {
        result.scope_issue = Some(
            if matches!(
                error,
                irmind_app::AppError::Fixed(FixedAppError::PolicyScopeExceedsOrganizationCeiling)
            ) {
                "Remote scope exceeds the organization policy ceiling."
            } else {
                "Check the remote scope values, object prefixes, and UTC window."
            },
        );
    }
    result
}

fn valid_utc(value: &str) -> bool {
    value.len() == 20 && value.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{SEVERITIES, move_focus, update, valid_utc};
    use crate::home::HomeState;
    use crossterm::event::KeyCode;

    #[test]
    fn main_step_creates_locally_and_remote_step_is_optional() {
        let mut state = HomeState::new(Vec::new(), false);
        state.form[0] = "Synthetic case".into();
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            crate::home::HomeAction::CreateCase
        ));
        move_focus(&mut state, true);
        update(&mut state, KeyCode::Down);
        assert_eq!(state.form[1], SEVERITIES[2]);
        move_focus(&mut state, true);
        update(&mut state, KeyCode::Enter);
        assert!(state.remote_scope_step.is_remote());
        assert_eq!(state.form_field, 2);
        update(&mut state, KeyCode::Esc);
        assert!(!state.remote_scope_step.is_remote());
    }

    #[test]
    fn utc_field_rejects_non_utc_and_invalid_dates() {
        assert!(valid_utc("2026-10-23T00:00:00Z"));
        assert!(!valid_utc("2026-02-30T00:00:00Z"));
        assert!(!valid_utc("2026-10-23T00:00:00+01:00"));
    }
}
