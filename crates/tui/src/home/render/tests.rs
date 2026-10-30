use super::{
    CaseStatus, Constraint, HomeState, HomeVisual, Layout, ListItem, Mode, Paragraph, Theme,
    draw_case_list, draw_dialog_screen, draw_list_screen, draw_settings_screen, help_line,
    home_list_state, home_menu_rows, items,
};
use crate::{
    CredentialStatus, KeystoreStatus, ModuleKind, ModuleParameter, ModuleSelectionSource,
    ModuleStatus,
};
use ratatui::{Terminal, backend::TestBackend, layout::Rect, style::Color};

fn snapshot_screen(state: &HomeState, content: Vec<ListItem<'static>>) -> String {
    snapshot_screen_with_check(
        state,
        content,
        &super::super::new_case::FormCheck::default(),
    )
}

fn snapshot_screen_with_check(
    state: &HomeState,
    content: Vec<ListItem<'static>>,
    check: &super::super::new_case::FormCheck,
) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test backend");
    terminal
        .draw(|frame| {
            let theme = Theme::plain();
            let areas =
                Layout::vertical([Constraint::Min(4), Constraint::Length(1)]).split(frame.area());
            let module_detail =
                items::module_detail(state, &state.modules, &|value| Ok(value.to_owned()))
                    .expect("module detail");
            let visual = HomeVisual {
                title: "IRMind v0.1.0",
                summary: "Keystore: file / file · Model: No model · /settings model to configure",
                notice: "",
                input: &state.input,
                has_model: false,
                form: &state.form,
                form_check: check,
                module_detail: &module_detail,
            };
            if state.mode == Mode::List {
                let menu = home_menu_rows(state, &|value| Ok(value.to_owned())).expect("home menu");
                draw_list_screen(frame, areas[0], state, &visual, content, &menu, theme);
            } else if state.mode == Mode::Settings {
                let mut selected = home_list_state(state);
                draw_settings_screen(frame, areas[0], &visual, content, &mut selected, theme);
            } else {
                let mut selected = home_list_state(state);
                draw_dialog_screen(
                    frame,
                    areas[0],
                    state,
                    &visual,
                    content,
                    &mut selected,
                    theme,
                );
            }
            frame.render_widget(
                Paragraph::new(help_line(state)).style(theme.muted()),
                areas[1],
            );
        })
        .expect("draw screen");
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end_matches(' ')
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn remote_scope_shows_fields_and_inline_validation() {
    let mut state = HomeState::new(Vec::new(), false);
    state.mode = Mode::New;
    state.remote_scope_step = super::super::RemoteScopeStep::Remote;
    state.form_field = 7;
    state.form[0] = "Synthetic remote case".into();
    state.form[7] = "2026-02-30T00:00:00Z".into();
    let mut check = super::super::new_case::FormCheck::default();
    check.issues[7] = Some("Use UTC, for example 2026-10-23T00:00:00Z.");
    let screen = snapshot_screen_with_check(&state, Vec::new(), &check);
    assert!(screen.contains("Object prefixes"));
    assert!(screen.contains("From UTC"));
    assert!(screen.contains("Use UTC"));
    insta::assert_snapshot!("home_new_remote", screen);
}

fn synthetic_module(id: &str, compiled: bool, selected: bool) -> ModuleStatus {
    ModuleStatus {
        id: id.into(),
        compiled,
        enabled: false,
        configuration: if selected {
            "missing API key"
        } else {
            "disabled"
        }
        .into(),
        kind: ModuleKind::Connector,
        selected,
        selection_source: ModuleSelectionSource::Persistent,
        parameters: vec![ModuleParameter {
            name: "base_url".into(),
            value: "https://example.invalid".into(),
            defaulted: false,
            required: true,
            overridden: false,
        }],
        credentials: vec!["API_KEY".into()],
        missing: if selected {
            vec!["API_KEY".into()]
        } else {
            Vec::new()
        },
    }
}

#[test]
fn empty_home_has_one_composer_and_no_search_panel() {
    let state = HomeState::new(Vec::new(), false);
    let screen = snapshot_screen(&state, Vec::new());
    assert!(screen.contains("No cases yet · /new to create one"));
    assert!(screen.contains("No model · /settings model to configure"));
    assert!(!screen.contains("Search:"));
    insta::assert_snapshot!("home_empty", screen);
}

#[test]
fn case_list_and_command_menu_use_accent_selection() {
    let mut state = HomeState::new(
        vec![super::super::CaseRow {
            id: irmind_app::CaseId::parse("00000000-0000-0000-0000-000000000001").expect("case id"),
            title: "Synthetic alert".into(),
            severity: "high".into(),
            status: CaseStatus::Open,
            last_activity: 0,
        }],
        false,
    );
    let cases = vec![ListItem::new(
        "> Synthetic alert  ·  high  ·  open  ·  2026-10-29 12:00 UTC",
    )];
    insta::assert_snapshot!("home_cases", snapshot_screen(&state, cases.clone()));
    state.input = "/".into();
    let menu = snapshot_screen(&state, cases);
    assert!(menu.contains("Commands"));
    insta::assert_snapshot!("home_commands", menu);
}

#[test]
fn selected_case_uses_accent_color() {
    let state = HomeState::new(
        vec![super::super::CaseRow {
            id: irmind_app::CaseId::parse("00000000-0000-0000-0000-000000000001").expect("case id"),
            title: "Synthetic alert".into(),
            severity: "high".into(),
            status: CaseStatus::Open,
            last_activity: 0,
        }],
        false,
    );
    let mut theme = Theme::plain();
    theme.accent = Color::Blue;
    let mut terminal = Terminal::new(TestBackend::new(80, 8)).expect("test backend");
    terminal
        .draw(|frame| {
            draw_case_list(
                frame,
                Rect::new(0, 0, 80, 8),
                &state,
                vec![ListItem::new("Synthetic alert · high · open · 2026-10-29")],
                false,
                theme,
            );
        })
        .expect("draw case list");
    assert_eq!(terminal.backend().buffer()[(0, 1)].fg, Color::Blue);
}

#[test]
fn settings_sections_have_versioned_snapshots() {
    let mut state = HomeState::new(Vec::new(), false);
    state.mode = Mode::Settings;
    insta::assert_snapshot!(
        "settings_sections",
        snapshot_screen(
            &state,
            super::super::SettingsSection::ALL
                .iter()
                .enumerate()
                .map(|(index, section)| ListItem::new(format!(
                    "{} {}",
                    if index == 0 { ">" } else { " " },
                    section.label()
                )))
                .collect()
        )
    );

    state.mode = Mode::Config;
    insta::assert_snapshot!(
        "settings_preferences",
        snapshot_screen(
            &state,
            vec![
                ListItem::new("Resume last case: on"),
                ListItem::new("Mouse capture: on"),
                ListItem::new("Theme: auto"),
            ]
        )
    );

    state.mode = Mode::Modules;
    state.set_modules(&[synthetic_module("siem-splunk", true, true)]);
    state.module_selected = 0;
    let modules = items::module_items(&state, &state.modules, &|value| Ok(value.to_owned()))
        .expect("module rows");
    insta::assert_snapshot!("settings_connectors", snapshot_screen(&state, modules));

    state.mode = Mode::Keystore;
    state.keystore = Some(KeystoreStatus {
        signer_backend: "file".into(),
        secrets_backend: "file".into(),
        analyst_fingerprint: "ab".repeat(32),
        credentials: vec![CredentialStatus {
            name: "DEEPSEEK_API_KEY".into(),
            present: true,
        }],
        file_backend_active: true,
    });
    insta::assert_snapshot!(
        "settings_keystore",
        snapshot_screen(&state, items::keystore_items(&state))
    );

    state.mode = Mode::Model;
    let models = items::model_items(&state, &|value| Ok(value.to_owned())).expect("model options");
    insta::assert_snapshot!("settings_model", snapshot_screen(&state, models));
}

#[test]
fn deepseek_default_is_visible_in_escaped_connector_detail() {
    let mut state = HomeState::new(Vec::new(), false);
    state.mode = Mode::Modules;
    state.set_modules(&[ModuleStatus {
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
        credentials: Vec::new(),
        missing: Vec::new(),
    }]);
    let detail = items::module_detail(&state, &state.modules, &|value| {
        Ok(crate::case::escape_display(value))
    })
    .expect("safe detail");
    assert!(
        detail
            .iter()
            .any(|line| line.contains("https://api.deepseek.com/ (default)"))
    );
}

#[test]
fn assistants_hide_the_background_composer() {
    let mut state = HomeState::new(Vec::new(), false);
    for (mode, name, lines) in [
        (
            Mode::New,
            "home_new_case",
            vec!["Title: Synthetic alert", "Severity: high"],
        ),
        (
            Mode::Keystore,
            "home_keystore",
            vec!["Signer: file", "Secrets: file"],
        ),
        (Mode::Modules, "home_modules", Vec::new()),
    ] {
        state.mode = mode;
        let content = if mode == Mode::Modules {
            state.set_modules(&[
                synthetic_module("storage-gcs", false, false),
                synthetic_module("siem-splunk", true, true),
                synthetic_module("llm-anthropic", true, false),
            ]);
            state.module_selected = state
                .modules
                .iter()
                .position(|module| module.id == "siem-splunk")
                .expect("SIEM module");
            items::module_items(&state, &state.modules, &|value| Ok(value.to_owned()))
                .expect("module rows")
        } else {
            lines.into_iter().map(ListItem::new).collect()
        };
        let screen = snapshot_screen(&state, content);
        assert!(!screen.contains("Find cases or type /"));
        if mode == Mode::Modules {
            assert!(screen.contains("AI model"));
            assert!(screen.contains("SIEM"));
            assert!(screen.contains("Storage"));
            assert!(screen.contains("Missing: API_KEY"));
            assert!(screen.contains("Technical ID: siem-splunk"));
            assert!(screen.contains("/settings keystore"));
        }
        insta::assert_snapshot!(name, screen);
    }
    state.module_selected = state
        .modules
        .iter()
        .position(|module| module.id == "storage-gcs")
        .expect("storage module");
    let detail = items::module_detail(&state, &state.modules, &|value| Ok(value.to_owned()))
        .expect("module detail");
    assert!(
        detail
            .iter()
            .any(|line| line.contains("--features storage-gcs"))
    );
    state.mode = Mode::Model;
    let content = items::model_items(&state, &|value| Ok(value.to_owned())).expect("model options");
    let screen = snapshot_screen(&state, content);
    assert!(screen.contains("1. Ollama"));
    assert!(screen.contains("DeepSeek"));
    assert_eq!(
        super::super::model::PROVIDERS.last().map(|item| item.name),
        Some("Later")
    );
    insta::assert_snapshot!("home_model_provider", screen);
}
