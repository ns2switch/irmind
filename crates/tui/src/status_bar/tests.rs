#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::StatusItem;
use ratatui::style::Color;

#[test]
fn presets_fit_eighty_one_hundred_and_two_hundred_columns() {
    let data = StatusData::preview();
    for template in [
        StatusBarTemplate::minimal(),
        StatusBarTemplate::investigation(),
        StatusBarTemplate::costs(),
    ] {
        for width in [0, 1, 80, 100, 200] {
            let line = render(&template, &data, width, Theme::plain());
            assert!(line.width() <= width, "{line} at width {width}");
        }
    }
}
#[test]
fn low_priority_segments_are_removed_before_high_priority_segments() {
    let template = StatusBarTemplate {
        version: 1,
        separator: " | ".into(),
        segments: vec![
            StatusItem {
                segment: StatusSegment::CaseTitle,
                priority: 1,
                color: StatusColor::Text,
            },
            StatusItem {
                segment: StatusSegment::Model,
                priority: 80,
                color: StatusColor::Accent,
            },
            StatusItem {
                segment: StatusSegment::Cost,
                priority: 100,
                color: StatusColor::Muted,
            },
        ],
    };
    let mut data = StatusData::default();
    data.insert(StatusSegment::CaseTitle, "case title");
    data.insert(StatusSegment::Model, "long model name");
    data.insert(StatusSegment::Cost, "$0.10");
    assert_eq!(
        render(&template, &data, 12, Theme::plain()).to_string(),
        "$0.10"
    );
}
#[test]
fn plain_theme_and_untrusted_titles_cannot_emit_color_or_terminal_controls() {
    let mut data = StatusData::preview();
    data.insert(StatusSegment::CaseTitle, "bad\x1b[2J\r\n\0\u{202e}title");
    let line = render(&StatusBarTemplate::minimal(), &data, 200, Theme::plain());
    assert!(!line.to_string().chars().any(char::is_control));
    assert!(!line.to_string().contains('\u{202e}'));
    assert!(
        line.spans
            .iter()
            .all(|span| span.style.fg == Some(Color::Reset))
    );
}
#[test]
fn mandatory_warnings_survive_customization_and_take_priority_over_all_segments() {
    let mut data = StatusData::preview();
    data.warnings = vec!["FULL INSTANCE SCOPE".into(), "BUDGET ≥80%".into()];
    let line = render(&StatusBarTemplate::minimal(), &data, 80, Theme::plain());
    assert!(
        line.to_string()
            .starts_with("FULL INSTANCE SCOPE · BUDGET ≥80%")
    );
    assert!(line.width() <= 80);
}

fn screen(editor: &editor::Editor, width: u16) -> String {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, 24)).unwrap();
    terminal
        .draw(|frame| editor.draw(frame, frame.area()))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..24)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
#[test]
fn editor_changes_only_the_preview_until_save_and_restores_default_explicitly() {
    use crossterm::event::KeyCode;
    let original = StatusBarTemplate::minimal();
    let mut editor = editor::Editor::new(Some(&original));
    assert!(matches!(
        editor.update(KeyCode::Enter),
        editor::Action::Keep
    ));
    editor.update(KeyCode::Char('3'));
    editor.update(KeyCode::Enter);
    assert_eq!(editor.template, StatusBarTemplate::costs());
    assert_eq!(original, StatusBarTemplate::minimal());
    insta::assert_snapshot!("status_bar_editor_80", screen(&editor, 80));
    editor.update(KeyCode::Char('4'));
    editor.update(KeyCode::Enter);
    assert_eq!(editor.template, StatusBarTemplate::default());
    editor.update(KeyCode::Char('5'));
    assert!(matches!(
        editor.update(KeyCode::Enter),
        editor::Action::Save(None)
    ));
}
#[test]
fn editor_cancel_and_separator_validation_preserve_the_signed_template() {
    use crossterm::event::KeyCode;
    let mut editor = editor::Editor::new(None);
    editor.update(KeyCode::Char('3'));
    editor.update(KeyCode::Enter);
    for c in "too long".chars() {
        editor.update(KeyCode::Char(c));
    }
    editor.update(KeyCode::Enter);
    assert_eq!(editor.template.separator, " · ");
    assert!(screen(&editor, 80).contains("at most four"));
    editor.clear();
    editor.update(KeyCode::Char('|'));
    editor.update(KeyCode::Enter);
    assert_eq!(editor.template.separator, "|");
    assert!(matches!(
        editor.update(KeyCode::Esc),
        editor::Action::Cancel
    ));
}
