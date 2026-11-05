use super::{Episode, GraphQueryFilter};

pub(super) fn episode_filter(episode: &Episode) -> GraphQueryFilter {
    let times = episode
        .events
        .iter()
        .map(|event| event["event_time"].as_str().unwrap())
        .collect::<Vec<_>>();
    // Normalized HuntEval records use an explicit provider as a region fallback.
    // The legacy AWS fixture has no such field. Its directory is attribution,
    // not evidence metadata, and must not supply a missing query predicate.
    let declared = episode.events.first().and_then(|e| e["provider"].as_str());
    let region = declared.filter(|provider| {
        episode
            .events
            .iter()
            .all(|e| e["provider"].as_str() == Some(*provider))
    });
    GraphQueryFilter::parse(
        Some(times.iter().copied().min().unwrap()),
        Some(times.iter().copied().max().unwrap()),
        None,
        None,
        region,
    )
    .unwrap()
}

#[test]
fn legacy_source_does_not_invent_a_region_from_its_directory() {
    let events = serde_json::from_slice(include_bytes!(
        "../../../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"
    ))
    .unwrap();
    let episode = fixture(events);
    let filter = episode_filter(&episode);
    assert!(filter.region().is_none());
    assert!(filter.time_range().is_some());
}

#[test]
fn explicit_fallback_is_taken_from_all_records_not_the_directory() {
    let mut episode = fixture(vec![serde_json::json!({
        "event_time": "2026-01-01T00:00:00Z", "provider": "gcp"
    })]);
    episode.provider = "aws".into();
    assert_eq!(episode_filter(&episode).region(), Some("gcp"));
}

#[test]
fn inconsistent_source_metadata_does_not_hide_part_of_an_episode() {
    let episode = fixture(vec![
        serde_json::json!({"event_time":"2026-01-01T00:00:00Z", "provider":"aws"}),
        serde_json::json!({"event_time":"2026-01-01T00:01:00Z"}),
    ]);
    assert!(episode_filter(&episode).region().is_none());
}

fn fixture(events: Vec<serde_json::Value>) -> Episode {
    Episode {
        provider: "aws".into(),
        truth: super::GroundTruth {
            episode_id: "aws-synthetic".into(),
            malicious_event_ids: Vec::new(),
            malicious_entity_ids: Vec::new(),
            expected_attack_path: Vec::new(),
        },
        events,
        source: std::path::PathBuf::new(),
        hash: "0".repeat(64),
    }
}
