use super::{HomeState, Mode};

pub(super) fn help_line(state: &HomeState) -> &'static str {
    match state.mode {
        Mode::List => "↑/↓ choose · Enter open · /new create · /model AI · Ctrl+K commands",
        Mode::New if state.remote_scope_step.is_remote() => {
            "Tab/Shift+Tab field · Enter create · Esc local step"
        }
        Mode::New => "Tab/Shift+Tab field · ↑/↓ severity · Enter create or expand · Esc back",
        Mode::Config => "Enter toggle resume · Esc back",
        Mode::Modules => {
            if state.pending_module_change.is_some() {
                "↑/↓ choose · Enter confirm · Esc back"
            } else if state.module_edit.is_some() {
                "Type parameter · Enter save · Esc back"
            } else {
                "↑/↓ choose · Tab field · Enter select · Esc back"
            }
        }
        Mode::Setup => "Enter optional model setup · Esc continue without a model",
        Mode::Help => "PgUp/PgDn scroll · Esc back · type a /command to run it",
        Mode::Model => "↑/↓ choose · Enter continue · Esc back",
        Mode::Keystore => {
            if state.confirm_credential_delete || state.pending_migration.is_some() {
                "↑/↓ choose · Enter confirm · Esc back"
            } else if state.restart_required {
                "/restart session · connectors may hold old credentials · Esc back"
            } else {
                "↑/↓ choose · Enter continue · Esc back · /cred-add · /cred-delete"
            }
        }
        Mode::VerifyExport => "Tab next field · Enter verify · Esc back",
    }
}

#[cfg(test)]
mod help_tests {
    use super::{HomeState, Mode, help_line};

    #[test]
    fn keystore_offers_session_restart_after_credentials_change() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Keystore;
        assert!(!help_line(&state).contains("restart session"));
        state.restart_required = true;
        assert!(help_line(&state).contains("/restart session"));
        assert!(help_line(&state).contains("connectors may hold old credentials"));
    }
}
