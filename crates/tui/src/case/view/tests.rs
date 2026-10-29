use super::*;
use ratatui::backend::TestBackend;

fn screen(terminal: &Terminal<TestBackend>) -> String {
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
fn narrow_terminal_keeps_prompt_and_new_content_indicator() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let lines = vec![
        Line::from("Analyst: synthetic alert"),
        Line::from("IRMind: finding"),
    ];
    let view = CaseFrame {
        title: "Synthetic",
        messages: "",
        visible_lines: Some(&lines),
        input: "first line\nsecond line",
        input_focused: true,
        panel: "timeline",
        overlay: None,
        menu: Some("> /verify verify custody"),
        tab: 0,
        sidebar_visible: false,
        sidebar_scroll: 0,
        overlay_scroll: 0,
        new_content: true,
        model: "fake",
        tokens: 12,
        cost: "$0",
        pending: 1,
        detections: 1,
        status: "idle",
    };
    draw_case(&mut terminal, &view).unwrap();
    let shown = screen(&terminal);
    assert!(shown.contains("new content"));
    assert!(shown.contains("Analyst: synthetic alert"));
    assert!(shown.contains("second line"));
    assert!(shown.contains("/verify"));
    assert!(shown.contains("fake"));
    assert!(shown.contains("1 approval pending"));
    assert!(!shown.contains("Ctrl+B sidebar"));
    assert_eq!(
        conversation_area(Rect::new(0, 0, 80, 24), view.input, false).width,
        80
    );
}

#[test]
fn expanded_card_and_scrolled_sidebar_are_visible_in_test_backend() {
    use crate::case::conversation::{Card, CardKind, Conversation};
    let mut chat = Conversation::new(false);
    chat.set_viewport(48, 12);
    chat.push(Card::new(
        CardKind::ToolResult,
        "Evidence search",
        format!("source=synthetic#0 {}", "x".repeat(2_000)),
        false,
    ));
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    let lines = chat.visible_lines();
    let mut view = CaseFrame {
        title: "Synthetic",
        messages: "",
        visible_lines: Some(&lines),
        input: "",
        input_focused: false,
        panel: "line zero\nline one\nline two",
        overlay: None,
        menu: None,
        tab: 0,
        sidebar_visible: true,
        sidebar_scroll: 1,
        overlay_scroll: 0,
        new_content: false,
        model: "fake",
        tokens: 0,
        cost: "n/a",
        pending: 0,
        detections: 0,
        status: "idle",
    };
    draw_case(&mut terminal, &view).unwrap();
    assert!(screen(&terminal).contains("Evidence search"));
    assert!(screen(&terminal).contains("expand"));
    assert!(screen(&terminal).contains("line one"));
    assert!(!screen(&terminal).contains("n/a"));
    chat.toggle_selected();
    let expanded_lines = chat.visible_lines();
    view.visible_lines = Some(&expanded_lines);
    draw_case(&mut terminal, &view).unwrap();
    assert!(!screen(&terminal).contains("ctrl+o to expand"));
    assert!(screen(&terminal).contains("xxxxxxxx"));
}

#[test]
fn visual_states_have_versioned_terminal_snapshots() {
    use crate::case::conversation::{Card, CardKind, Conversation};
    let mut chat = Conversation::new(false);
    chat.set_viewport(80, 18);
    chat.push(Card::new(CardKind::Welcome, "IRMind v0.1.0", "Synthetic case · high\nModel: no model · Keystore: file\n/ingest adds evidence · ? opens help", false));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let lines0 = chat.visible_lines();
    let mut view = CaseFrame {
        title: "Synthetic case",
        messages: "",
        visible_lines: Some(&lines0),
        input: "",
        input_focused: true,
        panel: "",
        overlay: None,
        menu: None,
        tab: 0,
        sidebar_visible: false,
        sidebar_scroll: 0,
        overlay_scroll: 0,
        new_content: false,
        model: "no model",
        tokens: 0,
        cost: "$0",
        pending: 0,
        detections: 0,
        status: "idle",
    };
    draw_case(&mut terminal, &view).unwrap();
    insta::assert_snapshot!("welcome", screen(&terminal));

    chat.push(Card::new(
        CardKind::Analyst,
        "Analyst",
        "What does the synthetic alert show?",
        false,
    ));
    chat.begin_preview();
    chat.set_preview("Streaming answer with **bold** text.".into());
    let lines1 = chat.visible_lines();
    view.visible_lines = Some(&lines1);
    view.model = "synthetic-model";
    view.tokens = 18;
    draw_case(&mut terminal, &view).unwrap();
    insta::assert_snapshot!("streaming", screen(&terminal));

    chat.push(
        Card::new(
            CardKind::ToolResult,
            "Splunk search(user=alice, 24h)",
            "12 events · 3 hosts\nfull synthetic detail",
            false,
        )
        .with_summary("approved · 12 results"),
    );
    let lines2 = chat.visible_lines();
    view.visible_lines = Some(&lines2);
    draw_case(&mut terminal, &view).unwrap();
    insta::assert_snapshot!("tool_folded", screen(&terminal));
    chat.toggle_selected();
    let lines3 = chat.visible_lines();
    view.visible_lines = Some(&lines3);
    draw_case(&mut terminal, &view).unwrap();
    insta::assert_snapshot!("tool_expanded", screen(&terminal));

    chat.push(Card::new(CardKind::Approval("approval-synthetic".into()), "Approval required", "Allow IRMind to send example.com to VirusTotal? This value leaves this computer.\nExact arguments: {\"ioc\":\"example.com\"}\nUNTRUSTED file · evidence abcdef01…abcdef0 · record 4\n{\"ioc\":\"⟦example.com⟧\"}", false));
    let lines4 = chat.visible_lines();
    view.visible_lines = Some(&lines4);
    view.pending = 1;
    view.detections = 1;
    view.status = "OVR Thinking… 2s · esc to interrupt";
    draw_case(&mut terminal, &view).unwrap();
    insta::assert_snapshot!("tainted_approval_and_warnings", screen(&terminal));

    view.menu = Some(
        "· Case\n  /ingest <path>  Add evidence\n· Approvals\n> /approve <id>  Sign a pending call",
    );
    view.input = "/";
    draw_case(&mut terminal, &view).unwrap();
    insta::assert_snapshot!("command_menu", screen(&terminal));

    view.menu = None;
    view.pending = 2;
    draw_case(&mut terminal, &view).unwrap();
    assert!(screen(&terminal).contains("2 approvals pending"));
}
