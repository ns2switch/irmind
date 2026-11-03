#![allow(clippy::unwrap_used)]
use super::*;

#[test]
fn script_has_ten_bounded_narrations_and_six_second_minimum() {
    let guide = DemoGuide::new().unwrap();
    assert_eq!(guide.steps.len(), 10);
    assert!(guide.reading_time() >= Duration::from_secs(6));
    assert!(guide.panel(None, None).unwrap().contains("Step 1 of 10"));
    assert!(
        guide
            .panel(None, None)
            .unwrap()
            .contains("Space pause/play")
    );
}
#[test]
fn automatic_reading_is_proportional_and_can_be_paused() {
    let mut guide = DemoGuide::new().unwrap();
    let now = Instant::now();
    assert!(matches!(guide.tick(now, false, true), Effect::None));
    assert!(matches!(
        guide.tick(now + Duration::from_secs(5), false, true),
        Effect::None
    ));
    assert!(matches!(
        guide.tick(now + Duration::from_mins(1), false, true),
        Effect::Next
    ));
    guide.pause_or_resume();
    assert!(matches!(
        guide.tick(now + Duration::from_secs(90), false, true),
        Effect::None
    ));
}
#[test]
fn back_keeps_completed_actions_and_never_replays_ingestion() {
    let mut guide = DemoGuide::new().unwrap();
    guide.next();
    assert_eq!(guide.step(), 1);
    guide.progress[1] = 1;
    guide.record(DemoEvent::ScopeViewed);
    guide.next();
    assert_eq!(guide.step(), 2);
    guide.progress[2] = 1;
    guide.record_ingest("parser-json", 90);
    guide.next();
    guide.back();
    assert_eq!(guide.progress[2], 1);
    assert!(guide.completed());
    assert!(guide.panel(None, None).unwrap().contains("90% confidence"));
}
#[test]
fn missing_requirements_and_errors_cannot_advance() {
    let mut guide = DemoGuide::new().unwrap();
    guide.next();
    guide.next();
    assert_eq!(guide.step(), 1);
    guide.fail("Synthetic failure");
    assert!(guide.panel(None, None).unwrap().contains("Enter retries"));
    assert!(matches!(
        guide.tick(Instant::now(), false, true),
        Effect::None
    ));
    guide.enter();
    assert!(matches!(
        guide.tick(Instant::now() + Duration::from_secs(1), false, true),
        Effect::Bind(_)
    ));
}

#[test]
fn back_cancels_unsubmitted_typing_but_waits_for_real_work() {
    let mut guide = DemoGuide::new().unwrap();
    guide.next();
    guide.start_typing("/scope".into());
    guide.back();
    assert_eq!(guide.step(), 0);
    assert_eq!(guide.progress[1], 0);
    guide.next();
    guide.command_sent();
    guide.back();
    assert_eq!(guide.step(), 1);
    guide.record(DemoEvent::ScopeViewed);
    guide.action_finished();
    assert_eq!(guide.step(), 0);
    assert_eq!(guide.progress[1], 1);
}

#[test]
fn hidden_and_small_screens_do_not_execute_commands() {
    let mut guide = DemoGuide::new().unwrap();
    guide.next();
    assert!(matches!(
        guide.tick(Instant::now(), false, false),
        Effect::None
    ));
    guide.hide();
    assert!(matches!(
        guide.tick(Instant::now(), false, true),
        Effect::None
    ));
}

#[test]
fn every_scene_keeps_narration_and_controls_in_the_versioned_snapshot() {
    let mut guide = DemoGuide::new().unwrap();
    let mut snapshots = String::new();
    for index in 0..10 {
        guide.step = index;
        let panel = guide.panel(None, None).unwrap();
        assert!(panel.contains(&guide.steps[index].narration));
        assert!(panel.contains("Enter"));
        assert!(panel.contains("Backspace previous"));
        assert!(panel.contains("Space pause/play"));
        assert!(panel.contains("Esc exit"));
        snapshots.push_str(&panel);
        snapshots.push_str("\n\n");
    }
    insta::assert_snapshot!("all_presentation_narrations", snapshots);
}
