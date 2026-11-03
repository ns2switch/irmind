#![allow(clippy::unwrap_used)]
use super::*;
fn empty() -> TimePrompt {
    TimePrompt::new(
        "source.log".into(),
        ParserTimeRequirement {
            required: true,
            hosts: vec![],
            observed: None,
        },
        vec![],
    )
}
#[test]
fn keyboard_and_paste_require_explicit_confirmation_without_defaults() {
    let mut prompt = empty();
    for ch in "2026".chars() {
        prompt.update(KeyCode::Char(ch), KeyModifiers::NONE);
    }
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.paste("+01:00\r\n");
    for _ in 0..4 {
        prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    }
    let (context, all_files) = match prompt.update(KeyCode::Enter, KeyModifiers::NONE) {
        TimePromptAction::Confirm { context, all_files } => Some((context, all_files)),
        _ => None,
    }
    .unwrap();
    assert_eq!(context.year(), 2026);
    assert_eq!(context.offset_minutes(), 60);
    assert_eq!(context.basis(), ParserTimeBasis::Analyst);
    assert!(context.rollover() && all_files);
}
#[test]
fn missing_values_and_invalid_offsets_stay_in_the_form() {
    let mut prompt = empty();
    prompt.focus = 5;
    assert!(matches!(
        prompt.update(KeyCode::Enter, KeyModifiers::NONE),
        TimePromptAction::Keep
    ));
    assert!(prompt.error.is_some());
    assert!(matches!(
        prompt.update(KeyCode::Esc, KeyModifiers::NONE),
        TimePromptAction::Cancel
    ));
}

struct TestGuard;
impl ContentGuard for TestGuard {
    fn fingerprint(&self) -> String {
        "synthetic".into()
    }
    fn self_test(&self) -> Result<(), AppError> {
        Ok(())
    }
    fn screen(&self, value: &str) -> Result<irmind_app::Screened, AppError> {
        Ok(irmind_app::Screened {
            text: crate::case::escape_display(value),
            detections: vec![],
        })
    }
}
fn render(prompt: &TimePrompt) -> String {
    use ratatui::{
        Terminal,
        backend::TestBackend,
        widgets::{Block, Borders, Paragraph, Wrap},
    };
    let text = prompt.screened_text(&TestGuard).unwrap();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| {
            frame.render_widget(
                Paragraph::new(text)
                    .block(Block::default().borders(Borders::ALL))
                    .wrap(Wrap { trim: false }),
                frame.area(),
            );
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..24)
        .map(|y| {
            (0..80)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
#[test]
fn form_has_visible_fields_and_same_host_suggestions_need_confirmation() {
    let mut prompt = empty();
    insta::assert_snapshot!("syslog_time_empty", render(&prompt));
    prompt.suggestions.push(ParserTimeSuggestion {
        context: ParserTimeContext::new(2026, 60, true, ParserTimeBasis::ConfirmedSuggestion)
            .unwrap(),
        source_hash: "a".repeat(64),
        record_index: 2,
        host: irmind_app::json_time_requirement(
            "synthetic.json",
            b"{\"host\":\"synthetic-host\",\"at\":\"2026-01-01T00:00:00Z\"}",
            &irmind_app::ParserTimeFields {
                parser_id: "parser-json",
                hosts: &["/host"],
                timestamps: &["/at"],
            },
        )
        .unwrap()
        .unwrap()
        .hosts
        .remove(0),
    });
    assert!(prompt.year.is_empty() && prompt.offset.is_empty());
    for _ in 0..4 {
        prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    }
    insta::assert_snapshot!("syslog_time_suggestion", render(&prompt));
    assert!(matches!(
        prompt.update(KeyCode::Enter, KeyModifiers::NONE),
        TimePromptAction::Keep
    ));
    assert_eq!(prompt.basis, ParserTimeBasis::ConfirmedSuggestion);
    insta::assert_snapshot!("syslog_time_confirm", render(&prompt));
    let action = prompt.update(KeyCode::Enter, KeyModifiers::NONE);
    assert!(
        matches!(action, TimePromptAction::Confirm { context, all_files: true } if context.basis() == ParserTimeBasis::ConfirmedSuggestion)
    );
    prompt.focus = 0;
    prompt.update(KeyCode::Char('u'), KeyModifiers::CONTROL);
    prompt.paste("2027");
    assert_eq!(prompt.basis, ParserTimeBasis::Analyst);
}
#[test]
fn individual_file_and_rollover_are_explicit_choices_and_source_names_are_escaped() {
    let mut prompt = empty();
    prompt.source = "synthetic\u{1b}[2J.log".into();
    assert!(!render(&prompt).contains('\u{1b}'));
    prompt.paste("2026");
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.paste("+00:00");
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.update(KeyCode::Enter, KeyModifiers::NONE);
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.update(KeyCode::Enter, KeyModifiers::NONE);
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    prompt.update(KeyCode::Tab, KeyModifiers::NONE);
    assert!(
        matches!(prompt.update(KeyCode::Enter, KeyModifiers::NONE), TimePromptAction::Confirm { context, all_files: false } if !context.rollover())
    );
}
