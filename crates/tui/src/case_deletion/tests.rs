use super::*;
#[allow(clippy::expect_used)]
fn inventory() -> CaseDeletionInventory {
    CaseDeletionInventory {
        case_id: CaseId::parse("00000000-0000-4000-8000-000000000001").expect("synthetic case ID"),
        title: "Synthetic case".into(),
        created_at: 100,
        last_chain_hash: "a".repeat(64),
        entry_count: 1,
        source_count: 0,
        owned_file_bytes: 0,
        shared_blob_bytes: 0,
        logical_metadata_bytes: 0,
    }
}
#[test]
fn deletion_requires_exact_typing_and_separate_confirmation() {
    let item = inventory();
    let mut form = Form::default();
    form.paste("Synthetic cas");
    assert!(matches!(form.key(KeyCode::Enter, &item), Action::Keep));
    assert_eq!(form.focus, 0);
    form.key(KeyCode::Char('e'), &item);
    assert!(matches!(form.key(KeyCode::Enter, &item), Action::Keep));
    assert_eq!(form.focus, 2);
    assert!(matches!(form.key(KeyCode::Enter, &item), Action::Sign));
}
#[test]
fn deletion_paste_is_single_line_bounded_and_never_executes_commands() {
    let mut form = Form::default();
    form.paste("/quit\n\r\u{1b}Synthetic");
    assert_eq!(form.confirmation, "/quitSynthetic");
    form.paste(&"界".repeat(300));
    assert!(form.confirmation.len() <= 200);
    form.focus = 1;
    form.paste(&"x".repeat(2000));
    assert_eq!(form.reason.len(), 1024);
    assert!(matches!(form.key(KeyCode::Esc, &inventory()), Action::Back));
}

#[test]
#[allow(clippy::unwrap_used)]
fn deletion_inventory_is_visible_at_eighty_columns_and_escapes_titles() {
    use ratatui::backend::TestBackend;
    for width in [80, 100, 200] {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
        let mut item = inventory();
        item.title = "Synthetic\x1b[2J\u{202e} case".into();
        view::form(
            &mut terminal,
            &|s| Ok(crate::case::escape_display(s)),
            &item,
            &Form::default(),
            false,
        )
        .unwrap();
        let buffer = terminal.backend().buffer();
        let screen = (0..24)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(screen.contains("Exact title or case ID"));
        assert!(screen.contains("Sign and delete"));
        assert!(screen.contains("External originals stay"));
        assert!(!screen.contains('\x1b'));
        assert!(!screen.contains('\u{202e}'));
        if width == 80 {
            insta::assert_snapshot!("case_deletion_80", screen);
        }
    }
}

#[test]
fn deletion_number_is_only_selected_after_enter() {
    let item = inventory();
    let mut form = Form::default();
    form.paste(&item.title);
    form.key(KeyCode::Enter, &item);
    assert!(matches!(form.key(KeyCode::Char('1'), &item), Action::Keep));
    assert!(matches!(form.key(KeyCode::Enter, &item), Action::Back));
}
