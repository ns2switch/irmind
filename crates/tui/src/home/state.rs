use super::{CaseId, ConfigChange, HomeState, KeyCode, Mode, modules};

pub(crate) enum HomeAction {
    None,
    Quit,
    Restart,
    OpenCase(CaseId),
    CreateCase,
    LoadKeystore,
    VerifyExport(std::path::PathBuf, String),
    AddCredential,
    DeleteCredential,
    Migrate(&'static str),
    ChangePassphrase,
    ChangeModule(ConfigChange, bool),
}

/// A screen transition does not perform I/O. The event loop applies the returned action.
pub(crate) fn update(state: &mut HomeState, key: KeyCode) -> HomeAction {
    if state.restart_required
        && matches!(state.mode, Mode::List | Mode::Setup | Mode::Modules)
        && matches!(key, KeyCode::Enter | KeyCode::Char('n'))
    {
        state.notice =
            "Restart IRMind before opening a case so changed credentials take effect".into();
        return HomeAction::None;
    }
    match state.mode {
        Mode::List => update_list(state, key),
        Mode::Search => update_search(state, key),
        Mode::New => update_new_case(state, key),
        Mode::VerifyExport => update_verify_export(state, key),
        Mode::Modules => modules::update_module_screen(state, key),
        Mode::Setup => update_setup(state, key),
        Mode::Keystore => update_keystore(state, key),
    }
}

fn update_list(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Char('q') => HomeAction::Quit,
        KeyCode::Char('n') => {
            state.form = HomeState::new(Vec::new(), false).form;
            state.form_field = 0;
            state.mode = Mode::New;
            HomeAction::None
        }
        KeyCode::Char('/') => {
            state.mode = Mode::Search;
            HomeAction::None
        }
        KeyCode::Char('f') => {
            state.cycle_filter();
            HomeAction::None
        }
        KeyCode::Char('m') => {
            state.mode = Mode::Modules;
            HomeAction::None
        }
        KeyCode::Char('k') => {
            state.keystore_selected = 0;
            state.mode = Mode::Keystore;
            HomeAction::LoadKeystore
        }
        KeyCode::Char('v') => {
            state.verify_form = Default::default();
            state.verify_field = 0;
            state.mode = Mode::VerifyExport;
            HomeAction::None
        }
        KeyCode::Char('?') => {
            state.mode = Mode::Setup;
            HomeAction::None
        }
        KeyCode::Up => {
            state.selected = state.selected.saturating_sub(1);
            HomeAction::None
        }
        KeyCode::Down => {
            state.selected = (state.selected + 1).min(state.visible().len().saturating_sub(1));
            HomeAction::None
        }
        KeyCode::Enter => state
            .visible()
            .get(state.selected)
            .map_or(HomeAction::None, |row| HomeAction::OpenCase(row.id.clone())),
        _ => HomeAction::None,
    }
}

fn update_search(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc | KeyCode::Enter => {
            state.mode = Mode::List;
            state.selected = 0;
        }
        KeyCode::Backspace => {
            state.search.pop();
            state.selected = 0;
        }
        KeyCode::Char(ch) if state.search.len() < 200 => {
            state.search.push(ch);
            state.selected = 0;
        }
        _ => {}
    }
    HomeAction::None
}

fn update_new_case(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Tab => state.form_field = (state.form_field + 1) % state.form.len(),
        KeyCode::BackTab => {
            state.form_field = (state.form_field + state.form.len() - 1) % state.form.len();
        }
        KeyCode::Backspace => {
            state.form[state.form_field].pop();
        }
        KeyCode::Char(ch) if state.form[state.form_field].len() < 200 => {
            state.form[state.form_field].push(ch);
        }
        KeyCode::Enter => return HomeAction::CreateCase,
        _ => {}
    }
    HomeAction::None
}

fn update_verify_export(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Tab => state.verify_field = (state.verify_field + 1) % 2,
        KeyCode::Backspace => {
            state.verify_form[state.verify_field].pop();
        }
        KeyCode::Char(ch) if state.verify_form[state.verify_field].len() < 4096 => {
            state.verify_form[state.verify_field].push(ch);
        }
        KeyCode::Enter => {
            let path = std::path::PathBuf::from(&state.verify_form[0]);
            let fingerprint = state.verify_form[1].clone();
            if path.as_os_str().is_empty()
                || fingerprint.len() != 64
                || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                state.notice = "Enter a package path and 64-character key fingerprint".into();
            } else {
                return HomeAction::VerifyExport(path, fingerprint);
            }
        }
        _ => {}
    }
    HomeAction::None
}

fn update_setup(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Char('m') => state.mode = Mode::Modules,
        KeyCode::Char('k') => {
            state.mode = Mode::Keystore;
            return HomeAction::LoadKeystore;
        }
        KeyCode::Char('n') => {
            state.form = HomeState::new(Vec::new(), false).form;
            state.mode = Mode::New;
        }
        KeyCode::Char('q') => return HomeAction::Quit,
        _ => {}
    }
    HomeAction::None
}

fn update_keystore(state: &mut HomeState, key: KeyCode) -> HomeAction {
    if key == KeyCode::Char('r') && state.restart_required {
        return HomeAction::Restart;
    }
    if let Some(capability) = state.pending_migration {
        match key {
            KeyCode::Esc => state.pending_migration = None,
            KeyCode::Char('y') => {
                state.pending_migration = None;
                return HomeAction::Migrate(capability);
            }
            _ => {}
        }
        return HomeAction::None;
    }
    if state.confirm_credential_delete {
        match key {
            KeyCode::Esc => state.confirm_credential_delete = false,
            KeyCode::Char('y') => {
                state.confirm_credential_delete = false;
                return HomeAction::DeleteCredential;
            }
            _ => {}
        }
        return HomeAction::None;
    }
    match key {
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Up => state.keystore_selected = state.keystore_selected.saturating_sub(1),
        KeyCode::Down => {
            let count = state
                .keystore
                .as_ref()
                .map_or(0, |item| item.credentials.len());
            state.keystore_selected = (state.keystore_selected + 1).min(count.saturating_sub(1));
        }
        KeyCode::Char('a') => return HomeAction::AddCredential,
        KeyCode::Char('d') => state.confirm_credential_delete = true,
        KeyCode::Char('s') => {
            state.pending_migration = Some("signer");
            state.notice =
                "Copy the analyst key to the other backend; its fingerprint must remain unchanged"
                    .into();
        }
        KeyCode::Char('x') => {
            state.pending_migration = Some("secrets");
            state.notice =
                "Copy module credentials to the other backend; source credentials remain".into();
        }
        KeyCode::Char('p')
            if state
                .keystore
                .as_ref()
                .is_some_and(|item| item.file_backend_active) =>
        {
            return HomeAction::ChangePassphrase;
        }
        _ => {}
    }
    HomeAction::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_case_form_starts_with_a_valid_severity_and_local_scope() {
        let mut state = HomeState::new(Vec::new(), false);
        update(&mut state, KeyCode::Char('n'));
        assert!(irmind_app::Severity::parse(&state.form[1]).is_ok());
        assert!(state.form[2].is_empty());
        assert_eq!(state.scope(), "local evidence only");
    }

    #[test]
    fn update_moves_between_list_search_and_new_case_without_io() {
        let mut state = HomeState::new(Vec::new(), false);
        assert!(matches!(
            update(&mut state, KeyCode::Char('/')),
            HomeAction::None
        ));
        assert_eq!(state.mode, Mode::Search);
        update(&mut state, KeyCode::Char('x'));
        assert_eq!(state.search, "x");
        update(&mut state, KeyCode::Enter);
        update(&mut state, KeyCode::Char('n'));
        assert_eq!(state.mode, Mode::New);
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            HomeAction::CreateCase
        ));
    }
}
