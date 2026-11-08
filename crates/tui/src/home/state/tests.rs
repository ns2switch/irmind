use super::*;
use crate::{ModuleKind, ModuleParameter, ModuleSelectionSource, ModuleStatus};

#[test]
fn demo_is_a_home_command_and_needs_enter() {
    let mut state = HomeState::new(Vec::new(), false);
    for ch in "/demo".chars() {
        assert!(matches!(
            update(&mut state, KeyCode::Char(ch)),
            HomeAction::None
        ));
    }
    assert!(matches!(
        update(&mut state, KeyCode::Enter),
        HomeAction::Demo
    ));
}

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
fn preference_can_disable_context_hints() {
    let mut state = HomeState::new(Vec::new(), false);
    state.mode = Mode::Config;
    state.preference_selected = 2;
    assert!(matches!(
        update(&mut state, KeyCode::Enter),
        HomeAction::ChangeModule(ConfigChange::SetShowHints(false), true)
    ));
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

#[test]
fn experimental_writer_requires_a_visible_confirmation() {
    let mut state = HomeState::new(Vec::new(), false);
    state.mode = Mode::Config;
    state.preference_selected = 4;
    state.common_writer = crate::home::CommonWriterState::Disabled;
    assert!(matches!(
        update(&mut state, KeyCode::Enter),
        HomeAction::None
    ));
    assert!(matches!(
        state.pending_module_change,
        Some(ConfigChange::SetExperimentalCommonWriter(true))
    ));
    update(&mut state, KeyCode::Down);
    assert!(matches!(
        update(&mut state, KeyCode::Enter),
        HomeAction::ChangeModule(ConfigChange::SetExperimentalCommonWriter(true), true)
    ));
    assert!(state.pending_module_change.is_none());
    update(&mut state, KeyCode::Enter);
    update(&mut state, KeyCode::Esc);
    assert!(state.pending_module_change.is_none());
}
