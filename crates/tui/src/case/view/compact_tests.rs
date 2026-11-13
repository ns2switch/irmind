use super::*;
use ratatui::backend::TestBackend;

fn frame(guide: &str) -> CaseFrame<'_> {
    CaseFrame {
        title: "Synthetic",
        guide: Some(guide),
        guide_scroll: 0,
        messages: "Visible investigation",
        visible_lines: None,
        input: "",
        input_focused: true,
        panel: "Secondary panel must stay hidden",
        overlay: None,
        menu: None,
        tab: 4,
        sidebar_visible: true,
        sidebar_scroll: 0,
        overlay_scroll: 0,
        new_content: false,
        model: "scripted",
        tokens: Some(0),
        cost: "",
        pending: 1,
        detections: 0,
        status: "idle",
    }
}
fn text(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|row| {
            (0..buffer.area.width)
                .map(|col| buffer[(col, row)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn minimum_screen_keeps_investigation_and_controls_and_scrolls_narration() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let guide = crate::case::demo_guide::DemoGuide::new()
        .unwrap()
        .panel(None, None)
        .unwrap();
    let mut view = frame(&guide);
    draw_case(&mut terminal, &view).unwrap();
    let first = text(&terminal);
    assert!(first.contains("Visible investigation"));
    assert!(first.contains("Step 1 of 10"));
    assert!(first.contains("Enter next"));
    assert!(first.contains("Space pause/play"));
    assert!(first.contains("PgUp/PgDn read"));
    assert!(!first.contains("Secondary panel"));
    assert!(!first.contains("needs at least"));
    insta::assert_snapshot!("presentation_80x24", first);
    view.guide_scroll = 3;
    draw_case(&mut terminal, &view).unwrap();
    let scrolled = text(&terminal);
    assert_ne!(first, scrolled);
    assert!(scrolled.contains("PgUp/PgDn read"));
    assert!(scrolled.contains("Esc exit"));
}

#[test]
fn compact_final_choices_and_confirmation_stay_visible() {
    let guide = format!(
        "Step 10 of 10 · Your turn\n\n{}\n› 1. Explore this demo case\n  2. Start your own case\n  3. Exit\nPresentation complete · Enter select",
        "Long narration ".repeat(100)
    );
    let mut view = frame(&guide);
    view.overlay = Some(
        "Seal case synthetic\nAudit entries: 35\nFinal hash: full-hash\nAnalyst key fingerprint:\nexpected-key\n1. Cancel 2. Confirm\n\n1. Cancel 2. Confirm\nEnter select",
    );
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    draw_case(&mut terminal, &view).unwrap();
    let visible = text(&terminal);
    for required in [
        "expected-key",
        "Enter select",
        "1. Explore",
        "2. Start your own",
        "3. Exit",
        "PgUp/PgDn read",
    ] {
        assert!(visible.contains(required), "missing {required}");
    }
    insta::assert_snapshot!("presentation_80x24_confirmation", visible);
}
