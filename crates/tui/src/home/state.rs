use super::{
    CaseId, ConfigChange, HomeState, KeyCode, Mode, SettingsSection, case, model, modules, new_case,
};

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
    DiscoverModels,
    ProbeModel(model::ModelDraft),
    SaveModel(model::ModelDraft),
}

/// A screen transition does not perform I/O. The event loop applies the returned action.
pub(crate) fn update(state: &mut HomeState, key: KeyCode) -> HomeAction {
    if state.confirm_exit == crate::ExitConfirmation::Pending {
        return match key {
            KeyCode::Enter => HomeAction::Quit,
            KeyCode::Esc => {
                state.confirm_exit = crate::ExitConfirmation::Inactive;
                HomeAction::None
            }
            _ => HomeAction::None,
        };
    }
    if state.restart_required
        && matches!(state.mode, Mode::List | Mode::Setup | Mode::Modules)
        && key == KeyCode::Enter
        && state.input.is_empty()
    {
        state.notice =
            "Restart IRMind before opening a case so changed credentials take effect".into();
        return HomeAction::None;
    }
    if state.mode == Mode::List && state.input.starts_with('/') {
        match key {
            KeyCode::Tab | KeyCode::BackTab => {
                complete_command(state, key == KeyCode::Tab);
                return HomeAction::None;
            }
            KeyCode::Up => {
                state.menu_selected = state.menu_selected.saturating_sub(1);
                return HomeAction::None;
            }
            KeyCode::Down => {
                state.menu_selected =
                    (state.menu_selected + 1).min(command_options(state).len().saturating_sub(1));
                return HomeAction::None;
            }
            KeyCode::Enter => {
                let source = state.menu_query.as_deref().unwrap_or(&state.input);
                if let Some(value) = command_options_for(state, source).get(state.menu_selected) {
                    state.input.clone_from(value);
                }
                state.menu_query = None;
                return execute_command(state);
            }
            KeyCode::Esc => {
                state.input.clear();
                if let Some(previous) = state.palette_return.take() {
                    state.mode = previous;
                }
                return HomeAction::None;
            }
            _ => {}
        }
    }
    match state.mode {
        Mode::List => update_list(state, key),
        Mode::Settings => update_settings(state, key),
        Mode::New => update_new_case(state, key),
        Mode::Model => update_model(state, key),
        Mode::VerifyExport => update_verify_export(state, key),
        Mode::Modules => modules::update_module_screen(state, key),
        Mode::Config => update_config(state, key),
        Mode::Setup => update_setup(state, key),
        Mode::Help => update_help(state, key),
        Mode::Keystore => update_keystore(state, key),
    }
}

pub(crate) fn paste(state: &mut HomeState, value: &str) {
    for ch in value.chars().filter(|ch| !ch.is_control()).take(4096) {
        let _ = update(state, KeyCode::Char(ch));
    }
}

pub(crate) fn clear_active_field(state: &mut HomeState) {
    match state.mode {
        Mode::New => state.form[state.form_field].clear(),
        Mode::VerifyExport => state.verify_form[state.verify_field].clear(),
        Mode::Model => match state.model_setup.step {
            model::ModelStep::Url => {
                state.model_setup.url.clear();
                state.model_setup.url_edited = true;
            }
            model::ModelStep::Name => state.model_setup.name.clear(),
            model::ModelStep::Key => {
                state.model_setup.key = secrecy::SecretString::from(String::new());
            }
            _ => {}
        },
        Mode::Modules => {
            if let Some(edit) = &mut state.module_edit {
                edit.value.clear();
                edit.replace_on_type = false;
            }
        }
        Mode::List => state.input.clear(),
        _ => {}
    }
}

fn update_list(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => {
            state.input.clear();
            if let Some(previous) = state.palette_return.take() {
                state.mode = previous;
            }
        }
        KeyCode::Backspace => {
            state.input.pop();
            state.menu_query = None;
            state.selected = 0;
        }
        KeyCode::Char(ch) if !ch.is_control() && state.input.len() < 4096 => {
            state.input.push(ch);
            state.menu_query = None;
            state.menu_selected = 0;
            state.selected = 0;
        }
        KeyCode::Tab | KeyCode::BackTab if state.input.starts_with('/') => {
            complete_command(state, key == KeyCode::Tab);
        }
        KeyCode::Up => {
            if state.input.starts_with('/') {
                state.menu_selected = state.menu_selected.saturating_sub(1);
            } else {
                state.selected = state.selected.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if state.input.starts_with('/') {
                state.menu_selected =
                    (state.menu_selected + 1).min(command_options(state).len().saturating_sub(1));
            } else {
                state.selected = (state.selected + 1).min(state.visible().len().saturating_sub(1));
            }
        }
        KeyCode::Enter if state.input.starts_with('/') => {
            if state.input.starts_with('/') {
                let source = state.menu_query.as_deref().unwrap_or(&state.input);
                let options = command_options_for(state, source);
                if let Some(value) = options.get(state.menu_selected) {
                    state.input.clone_from(value);
                }
            }
            state.menu_query = None;
            return execute_command(state);
        }
        KeyCode::Enter => {
            return state
                .visible()
                .get(state.selected)
                .map_or(HomeAction::None, |row| HomeAction::OpenCase(row.id.clone()));
        }
        _ => {}
    }
    HomeAction::None
}

pub(super) fn command_options(state: &HomeState) -> Vec<String> {
    command_options_for(state, state.menu_query.as_deref().unwrap_or(&state.input))
}

fn command_options_for(state: &HomeState, source: &str) -> Vec<String> {
    if let Some(query) = source.strip_prefix("/open ") {
        return state
            .rows
            .iter()
            .filter(|row| {
                row.title.to_lowercase().contains(&query.to_lowercase())
                    || row.id.as_str().starts_with(query)
            })
            .take(20)
            .map(|row| format!("/open {}", row.title))
            .collect();
    }
    if let Some(query) = source.strip_prefix("/cases ") {
        return ["all", "open", "sealed", "inconsistent"]
            .into_iter()
            .filter(|value| value.starts_with(&query.to_lowercase()))
            .map(|value| format!("/cases {value}"))
            .collect();
    }
    if let Some(query) = source.strip_prefix("/settings ") {
        return ["model", "connectors", "keystore", "preferences"]
            .into_iter()
            .filter(|value| value.starts_with(&query.to_ascii_lowercase()))
            .map(|value| format!("/settings {value}"))
            .collect();
    }
    if source.contains(' ') {
        return Vec::new();
    }
    case::command_registry::matches(source)
        .into_iter()
        .filter(|command| {
            matches!(
                command.name,
                "new"
                    | "open"
                    | "cases"
                    | "home"
                    | "settings"
                    | "help"
                    | "quit"
                    | "verify-export"
                    | "restart"
            )
        })
        .map(|command| format!("/{}", command.name))
        .collect()
}

fn complete_command(state: &mut HomeState, forward: bool) {
    let started = state.menu_query.is_some();
    if !started {
        state.menu_query = Some(state.input.clone());
    }
    let options = command_options(state);
    if options.is_empty() {
        return;
    }
    state.menu_selected =
        case::command_registry::cycle(options.len(), state.menu_selected, started, forward);
    state.input.clone_from(&options[state.menu_selected]);
}

pub(super) fn execute_command(state: &mut HomeState) -> HomeAction {
    let input = std::mem::take(&mut state.input);
    state.palette_return = None;
    match input.trim() {
        "/new" => {
            state.form = HomeState::new(Vec::new(), false).form;
            state.form_field = 0;
            state.remote_scope_step = super::RemoteScopeStep::Local;
            state.mode = Mode::New;
        }
        "/cases" | "/home" => {
            state.mode = Mode::List;
            state.status_filter = None;
            state.selected = 0;
        }
        "/settings" => state.mode = Mode::Settings,
        "/model" | "/modules" | "/keystore" | "/config" | "/edit-param" => {
            state.notice = "Now in /settings".into();
            let section = match input.trim() {
                "/model" => SettingsSection::Model,
                "/modules" | "/edit-param" => SettingsSection::Connectors,
                "/keystore" => SettingsSection::Keystore,
                _ => SettingsSection::Preferences,
            };
            return open_settings_section(state, section);
        }
        "/help" => {
            state.help_return = state.mode;
            state.help_selected = 0;
            state.mode = Mode::Help;
        }
        "/quit" => state.confirm_exit = crate::ExitConfirmation::Pending,
        "/verify-export" => state.mode = Mode::VerifyExport,
        "/restart" if state.restart_required => return HomeAction::Restart,
        "/cred-add" | "/cred-delete" | "/passphrase" | "/migrate-signer" | "/migrate-secrets" => {
            state.notice = "Now in /settings".into();
            return open_settings_section(state, SettingsSection::Keystore);
        }
        value if value.starts_with("/settings ") => {
            let Some(section) = SettingsSection::parse(value[10..].trim()) else {
                state.notice = "Choose model, connectors, keystore, or preferences".into();
                return HomeAction::None;
            };
            return open_settings_section(state, section);
        }
        value if value.starts_with("/open ") => return open_named_case(state, &value[6..]),
        value if value.starts_with("/cases ") => {
            match value[7..].trim().to_ascii_lowercase().as_str() {
                "all" => state.status_filter = None,
                "open" => state.status_filter = Some(super::CaseStatus::Open),
                "sealed" => state.status_filter = Some(super::CaseStatus::Sealed),
                "inconsistent" => state.status_filter = Some(super::CaseStatus::Inconsistent),
                _ => {
                    state.notice = "Use /cases all|open|sealed|inconsistent".into();
                    return HomeAction::None;
                }
            }
            state.mode = Mode::List;
            state.selected = 0;
        }
        _ => state.notice = "Unknown command; use /help".into(),
    }
    HomeAction::None
}

fn open_settings_section(state: &mut HomeState, section: SettingsSection) -> HomeAction {
    state.settings_selected = SettingsSection::ALL
        .iter()
        .position(|item| *item == section)
        .unwrap_or(0);
    state.settings_return = Mode::Settings;
    state.mode = section.mode();
    match section {
        SettingsSection::Model => state.model_setup = model::ModelSetup::new(),
        SettingsSection::Keystore => return HomeAction::LoadKeystore,
        _ => {}
    }
    HomeAction::None
}

fn update_settings(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Up => state.settings_selected = state.settings_selected.saturating_sub(1),
        KeyCode::Down => {
            state.settings_selected =
                (state.settings_selected + 1).min(SettingsSection::ALL.len() - 1);
        }
        KeyCode::Enter => {
            return open_settings_section(state, SettingsSection::ALL[state.settings_selected]);
        }
        _ => {}
    }
    HomeAction::None
}

fn open_named_case(state: &mut HomeState, query: &str) -> HomeAction {
    let query = query.trim();
    let matches = state
        .rows
        .iter()
        .filter(|row| row.id.as_str() == query || row.title.eq_ignore_ascii_case(query))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        HomeAction::OpenCase(matches[0].id.clone())
    } else {
        state.notice = if matches.is_empty() {
            "No matching case; use /cases to list cases".into()
        } else {
            "Several cases have that title; use the case ID".into()
        };
        HomeAction::None
    }
}

fn update_new_case(state: &mut HomeState, key: KeyCode) -> HomeAction {
    new_case::update(state, key)
}

fn update_config(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => {
            state.mode = state.settings_return;
            HomeAction::None
        }
        KeyCode::Up => {
            state.preference_selected = state.preference_selected.saturating_sub(1);
            HomeAction::None
        }
        KeyCode::Down => {
            state.preference_selected = (state.preference_selected + 1).min(2);
            HomeAction::None
        }
        KeyCode::Enter => {
            let change = match state.preference_selected {
                0 => ConfigChange::SetResumeLastCase(!state.resume_last_case.enabled()),
                1 => ConfigChange::SetMouseCapture(!state.ui_selection.mouse_capture),
                _ => ConfigChange::SetTheme(
                    match state.theme_choice.as_str() {
                        "auto" => "light",
                        "light" => "dark",
                        _ => "auto",
                    }
                    .into(),
                ),
            };
            HomeAction::ChangeModule(change, true)
        }
        _ => HomeAction::None,
    }
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
        KeyCode::Enter if !state.input.is_empty() => return execute_command(state),
        KeyCode::Enter => state.mode = Mode::Model,
        KeyCode::Char(ch) if !ch.is_control() && state.input.len() < 4096 => state.input.push(ch),
        _ => {}
    }
    HomeAction::None
}

fn update_help(state: &mut HomeState, key: KeyCode) -> HomeAction {
    match key {
        KeyCode::Esc => state.mode = state.help_return,
        KeyCode::PageUp | KeyCode::Up => {
            state.help_selected = state.help_selected.saturating_sub(10);
        }
        KeyCode::PageDown | KeyCode::Down => {
            state.help_selected = (state.help_selected + 10).min(80);
        }
        KeyCode::Backspace => {
            state.input.pop();
        }
        KeyCode::Char(ch) if !ch.is_control() && state.input.len() < 4096 => state.input.push(ch),
        KeyCode::Enter if !state.input.is_empty() => return execute_command(state),
        _ => {}
    }
    HomeAction::None
}

fn update_model(state: &mut HomeState, key: KeyCode) -> HomeAction {
    model::update_model(state, key)
}

fn update_keystore(state: &mut HomeState, key: KeyCode) -> HomeAction {
    if let Some(action) = update_keystore_confirmation(state, key) {
        return action;
    }
    match key {
        KeyCode::Esc => {
            state.mode = state.settings_return;
            state.input.clear();
        }
        KeyCode::Tab | KeyCode::BackTab => {
            state.ui_selection.keystore_action_focus = !state.ui_selection.keystore_action_focus;
        }
        KeyCode::Up if state.ui_selection.keystore_action_focus => {
            state.keystore_action_selected = state.keystore_action_selected.saturating_sub(1);
        }
        KeyCode::Down if state.ui_selection.keystore_action_focus => {
            state.keystore_action_selected = (state.keystore_action_selected + 1).min(5);
        }
        KeyCode::Up => state.keystore_selected = state.keystore_selected.saturating_sub(1),
        KeyCode::Down => {
            let count = state
                .keystore
                .as_ref()
                .map_or(0, |item| item.credentials.len());
            state.keystore_selected = (state.keystore_selected + 1).min(count.saturating_sub(1));
        }
        KeyCode::Enter if state.ui_selection.keystore_action_focus => {
            return match state.keystore_action_selected {
                0 => HomeAction::AddCredential,
                1 => {
                    state.confirm_credential_delete = true;
                    state.selected_option = 0;
                    HomeAction::None
                }
                2 => HomeAction::ChangePassphrase,
                3 | 4 => {
                    state.pending_migration = Some(if state.keystore_action_selected == 3 {
                        "signer"
                    } else {
                        "secrets"
                    });
                    state.selected_option = 0;
                    HomeAction::None
                }
                _ if state.restart_required => HomeAction::Restart,
                _ => HomeAction::None,
            };
        }
        KeyCode::Enter => return HomeAction::AddCredential,
        _ => {}
    }
    HomeAction::None
}

fn update_keystore_confirmation(state: &mut HomeState, key: KeyCode) -> Option<HomeAction> {
    let migration = state.pending_migration;
    if migration.is_none() && !state.confirm_credential_delete {
        return None;
    }
    match key {
        KeyCode::Up | KeyCode::Down => state.selected_option = 1 - state.selected_option,
        KeyCode::Char(ch) if !ch.is_control() && state.input.len() < 4 => state.input.push(ch),
        KeyCode::Backspace => {
            state.input.pop();
        }
        KeyCode::Esc | KeyCode::Enter => {
            let confirm = if key == KeyCode::Esc {
                false
            } else {
                match state.input.as_str() {
                    "2" => true,
                    "1" => false,
                    "" => state.selected_option == 1,
                    _ => return Some(HomeAction::None),
                }
            };
            state.input.clear();
            state.pending_migration = None;
            state.confirm_credential_delete = false;
            if confirm {
                return Some(migration.map_or(HomeAction::DeleteCredential, HomeAction::Migrate));
            }
        }
        _ => {}
    }
    Some(HomeAction::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModuleKind, ModuleParameter, ModuleSelectionSource, ModuleStatus};

    fn deepseek() -> ModuleStatus {
        ModuleStatus {
            id: "llm-deepseek".into(),
            compiled: true,
            enabled: false,
            configuration: "disabled".into(),
            kind: ModuleKind::Llm,
            selected: false,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: vec![ModuleParameter {
                name: "IRMIND_DEEPSEEK_BASE_URL".into(),
                value: "https://api.deepseek.com/".into(),
                defaulted: true,
                required: false,
                overridden: false,
            }],
            credentials: vec!["IRMIND_DEEPSEEK_API_KEY".into()],
            missing: Vec::new(),
        }
    }

    fn connector() -> ModuleStatus {
        let mut module = deepseek();
        module.id = "siem-splunk".into();
        module.kind = ModuleKind::Connector;
        module.parameters[0].name = "SPLUNK_BASE_URL".into();
        module
    }

    #[test]
    fn connector_url_uses_form_for_typed_and_pasted_slashes() {
        let mut state = HomeState::new(Vec::new(), false);
        state.set_modules(&[connector()]);
        state.mode = Mode::Modules;
        update(&mut state, KeyCode::Tab);
        for ch in "https://api.deepseek.com//v1".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        assert!(state.input.is_empty());
        let action = update(&mut state, KeyCode::Enter);
        assert!(matches!(action, HomeAction::ChangeModule(
            ConfigChange::SetValue { value, .. }, false) if value == "https://api.deepseek.com/v1/"));

        update(&mut state, KeyCode::Enter);
        clear_active_field(&mut state);
        paste(&mut state, "https://api.deepseek.com//v1\nignored");
        assert_eq!(
            state.module_edit.as_ref().map(|edit| edit.value.as_str()),
            Some("https://api.deepseek.com//v1ignored")
        );
        let action = update(&mut state, KeyCode::Enter);
        assert!(matches!(action, HomeAction::ChangeModule(
            ConfigChange::SetValue { value, .. }, false) if value == "https://api.deepseek.com/v1ignored/"));
    }

    #[test]
    fn connector_default_can_be_accepted_and_legacy_commands_redirect() {
        let mut state = HomeState::new(Vec::new(), false);
        state.set_modules(&[connector()]);
        state.mode = Mode::Modules;
        update(&mut state, KeyCode::Tab);
        update(&mut state, KeyCode::Enter);
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            HomeAction::None
        ));
        assert_eq!(state.notice, "Current value accepted");
        for (command, mode) in [
            ("/model", Mode::Model),
            ("/modules", Mode::Modules),
            ("/keystore", Mode::Keystore),
            ("/config", Mode::Config),
            ("/edit-param", Mode::Modules),
        ] {
            state.mode = Mode::List;
            state.input = command.into();
            let _ = execute_command(&mut state);
            assert_eq!(state.mode, mode);
            assert_eq!(state.notice, "Now in /settings");
        }
        assert_eq!(
            command_options_for(&state, "/settings mo"),
            ["/settings model"]
        );
    }

    #[test]
    fn model_form_accepts_url_and_secret_slashes_from_paste() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Model;
        state.model_setup.provider = 6;
        state.model_setup.step = model::ModelStep::Url;
        state.model_setup.url = "https://api.deepseek.com/".into();
        paste(&mut state, "https://api.deepseek.com//v1\n");
        assert_eq!(state.model_setup.url, "https://api.deepseek.com//v1");
        update(&mut state, KeyCode::Enter);
        assert_eq!(state.model_setup.url, "https://api.deepseek.com/v1/");
        paste(&mut state, "key/with/slashes\nignored");
        assert_eq!(
            secrecy::ExposeSecret::expose_secret(&state.model_setup.key),
            "key/with/slashesignored"
        );
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            HomeAction::None
        ));
        assert!(matches!(
            state.model_setup.step,
            model::ModelStep::ConfirmDiscovery
        ));
    }

    #[test]
    fn numeric_provider_choice_opens_deepseek_url_form() {
        let mut state = HomeState::new(Vec::new(), false);
        state.set_modules(&[deepseek()]);
        state.mode = Mode::Model;
        update(&mut state, KeyCode::Char('7'));
        update(&mut state, KeyCode::Enter);
        assert!(matches!(state.model_setup.step, model::ModelStep::Url));
        assert_eq!(state.model_setup.url, "https://api.deepseek.com/");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn slash_open_completes_case_title_and_help_lists_reserved_keys() {
        let mut state = HomeState::new(
            vec![super::super::CaseRow {
                id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
                title: "Synthetic CloudTrail".into(),
                severity: "high".into(),
                status: super::super::CaseStatus::Open,
                last_activity: 0,
            }],
            false,
        );
        for ch in "/open Synth".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        update(&mut state, KeyCode::Tab);
        assert_eq!(state.input, "/open Synthetic CloudTrail");
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            HomeAction::OpenCase(_)
        ));
        for ch in "/help".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        update(&mut state, KeyCode::Enter);
        assert_eq!(state.mode, Mode::Help);
        assert!(case::command_registry::help().contains("Ctrl+K commands"));
        update(&mut state, KeyCode::Esc);
        assert_eq!(state.mode, Mode::List);
    }

    #[test]
    fn new_case_form_starts_with_a_valid_severity_and_local_scope() {
        let mut state = HomeState::new(Vec::new(), false);
        for ch in "/new".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        update(&mut state, KeyCode::Enter);
        assert!(irmind_app::Severity::parse(&state.form[1]).is_ok());
        assert!(state.form[2].is_empty());
        assert_eq!(state.scope(), "local evidence only");
    }

    #[test]
    fn printable_keys_only_edit_the_home_command_field() {
        let mut state = HomeState::new(Vec::new(), false);
        assert!(matches!(
            update(&mut state, KeyCode::Char('/')),
            HomeAction::None
        ));
        assert_eq!(state.mode, Mode::List);
        for ch in "zzzz".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        assert_eq!(state.input, "/zzzz");
        update(&mut state, KeyCode::Enter);
        assert_eq!(state.mode, Mode::List);
        for ch in "/new".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        update(&mut state, KeyCode::Enter);
        assert_eq!(state.mode, Mode::New);
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            HomeAction::CreateCase
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn plain_text_filters_cases_live_and_cases_command_filters_status() {
        let mut state = HomeState::new(
            vec![
                super::super::CaseRow {
                    id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
                    title: "CloudTrail alert".into(),
                    severity: "high".into(),
                    status: super::super::CaseStatus::Open,
                    last_activity: 0,
                },
                super::super::CaseRow {
                    id: CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap(),
                    title: "Sealed export".into(),
                    severity: "low".into(),
                    status: super::super::CaseStatus::Sealed,
                    last_activity: 0,
                },
            ],
            false,
        );
        for ch in "Cloud".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].title, "CloudTrail alert");
        assert!(matches!(
            update(&mut state, KeyCode::Enter),
            HomeAction::OpenCase(_)
        ));
        state.input.clear();
        for ch in "/cases sealed".chars() {
            update(&mut state, KeyCode::Char(ch));
        }
        update(&mut state, KeyCode::Enter);
        assert_eq!(state.visible().len(), 1);
        assert_eq!(state.visible()[0].title, "Sealed export");
    }
}
