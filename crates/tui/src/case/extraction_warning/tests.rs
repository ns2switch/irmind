#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{AppError, AuditEventKind, Screened};
use ratatui::{Terminal, backend::TestBackend};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct TestGuard(AtomicUsize);
impl ContentGuard for TestGuard {
    fn fingerprint(&self) -> String {
        "synthetic".into()
    }
    fn self_test(&self) -> Result<(), AppError> {
        Ok(())
    }
    fn screen(&self, input: &str) -> Result<Screened, AppError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(Screened {
            text: if input.contains("https://") {
                "neutralized external URL".into()
            } else {
                input.into()
            },
            detections: Vec::new(),
        })
    }
}

fn history() -> Vec<SignedEntry> {
    vec![
        serde_json::from_value(serde_json::json!({
            "seq": 1,
            "case_id": "11111111-1111-1111-1111-111111111111",
            "at": 0,
            "actor": "analyst",
            "origin": "system",
            "kind": AuditEventKind::GraphIndexed.as_str(),
            "payload": "legacy graph",
            "evidence": "a".repeat(64),
            "prev": vec![0u8; 32],
            "hash": vec![0u8; 32],
            "sig": [],
            "public_key": [],
        }))
        .unwrap(),
    ]
}

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
#[allow(clippy::too_many_lines)]
fn opening_and_verification_show_guarded_unfolded_non_blocking_warnings() {
    for label in ["open", "verify"] {
        let guard = TestGuard::default();
        let entries = history();
        let mut conversation = Conversation::new(false);
        conversation.set_viewport(80, 18);
        if label == "open" {
            append(&mut conversation, &guard, &entries).unwrap();
        } else {
            let warning = parser_extraction_warning(&entries)
                .unwrap()
                .unwrap()
                .display(&guard)
                .unwrap();
            let summary = completion(
                &mut conversation,
                "Verify",
                format!("Verified 3 audit entries\n{warning}"),
            );
            assert_eq!(summary, "Verified 3 audit entries");
            conversation.push(Card::new(CardKind::Notice, "", summary, false));
        }
        assert_eq!(guard.0.load(Ordering::Relaxed), 1);
        let visible = conversation.visible_lines();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        crate::case::draw_case(
            &mut terminal,
            &crate::case::CaseFrame {
                title: "Synthetic legacy case",
                guide: None,
                guide_scroll: 0,
                messages: "",
                visible_lines: Some(&visible),
                input: "/timeline",
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
                cost: "",
                pending: 0,
                detections: 0,
                status: "idle",
            },
        )
        .unwrap();
        let shown = screen(&terminal);
        assert!(shown.contains("Warning:"));
        assert!(shown.contains("chain is valid"));
        assert!(shown.contains("/timeline"));
        assert!(!shown.contains("/expand for detail"));
        insta::assert_snapshot!(format!("retired_parser_{label}"), shown);
    }
}
