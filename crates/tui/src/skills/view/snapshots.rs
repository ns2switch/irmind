use super::*;
use irmind_app::{SkillOrigin, SkillStatus};
use ratatui::backend::TestBackend;
#[test]
fn manager_sections_and_inline_error_have_eighty_column_snapshots() {
    let mut state = State::new(false);
    state.rows.push(SkillStatus {
        name: irmind_app::SkillName::parse("linux-triage").unwrap(),
        version: "0.1.0".into(),
        sha256: "ab".repeat(32),
        origin: SkillOrigin::Bundled,
        active: true,
        available: true,
        description: "Synthetic methodology".into(),
        warning: None,
    });
    for (name, screen) in [
        ("list", Screen::List),
        ("folder", Screen::Path),
        ("review", Screen::Review),
        ("inspect", Screen::Inspect),
        ("activation", Screen::Confirm),
    ] {
        state.screen = screen;
        state.action = 2;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame|paint(frame,&state,"Synthetic inline error · Esc returns without applying.","linux-triage · 0.1.0\nSHA-256: synthetic\nTools: text_search\n\nReview synthetic authentication evidence.","examples/skills/linux-triage",&["linux-triage · 0.1.0 · active · Bundled".into()])).unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..24)
            .map(|y| {
                (0..80)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!(format!("skill_manager_{name}"), text);
    }
}
