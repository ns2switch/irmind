use super::{
    CaseStatus, Constraint, HomeState, HomeVisual, Layout, ListItem, Mode, Paragraph, Theme,
    draw_case_list, draw_dialog_screen, draw_list_screen, help_line, home_list_state,
    home_menu_rows, items,
};
use ratatui::{Terminal, backend::TestBackend, layout::Rect, style::Color};

fn snapshot_screen(state: &HomeState, content: Vec<ListItem<'static>>) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test backend");
    terminal
        .draw(|frame| {
            let theme = Theme::plain();
            let areas =
                Layout::vertical([Constraint::Min(4), Constraint::Length(1)]).split(frame.area());
            let visual = HomeVisual {
                title: "IRMind v0.1.0",
                summary: "Keystore: file / file · Model: No model · /model to configure",
                notice: "",
                input: &state.input,
                has_model: false,
            };
            if state.mode == Mode::List {
                let menu = home_menu_rows(state, &|value| Ok(value.to_owned())).expect("home menu");
                draw_list_screen(frame, areas[0], state, &visual, content, &menu, theme);
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
fn empty_home_has_one_composer_and_no_search_panel() {
    let state = HomeState::new(Vec::new(), false);
    let screen = snapshot_screen(&state, Vec::new());
    assert!(screen.contains("No cases yet · /new to create one"));
    assert!(screen.contains("No model · /model to configure"));
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
        (
            Mode::Modules,
            "home_modules",
            vec!["llm-openai-compatible · compiled · disabled"],
        ),
    ] {
        state.mode = mode;
        let content = lines.into_iter().map(ListItem::new).collect();
        let screen = snapshot_screen(&state, content);
        assert!(!screen.contains("Find cases or type /"));
        insta::assert_snapshot!(name, screen);
    }
    state.mode = Mode::Model;
    let content = items::model_items(&state, &|value| Ok(value.to_owned())).expect("model options");
    let screen = snapshot_screen(&state, content);
    assert!(screen.find("1. Ollama local") < screen.find("6. Later"));
    insta::assert_snapshot!("home_model_provider", screen);
}
