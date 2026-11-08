use super::*;

#[test]
fn shared_public_sources_are_indexed_once_and_all_private_episodes_remain_evaluable() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("public.json");
    let bytes = br#"[{"event_id":"synthetic-1","provider":"aws"}]"#;
    fs::write(&original, bytes).unwrap();
    let episodes = (0..3)
        .map(|i| Episode {
            provider: "aws".into(),
            source: original.clone(),
            hash: hex(&sha256(bytes)),
            events: serde_json::from_slice(bytes).unwrap(),
            truth: GroundTruth {
                episode_id: format!("synthetic-{i}"),
                malicious_event_ids: vec![format!("private-answer-{i}")],
                malicious_entity_ids: vec![],
                expected_attack_path: vec![],
            },
        })
        .collect::<Vec<_>>();
    let output = root.path().join("staged");
    fs::create_dir(&output).unwrap();
    let names = stage_sources(&output, &episodes);
    assert_eq!(names.len(), 1);
    assert_eq!(fs::read(output.join(&names[0])).unwrap(), bytes);
    assert_eq!(episodes.len(), 3);
    assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    for episode in &episodes {
        assert!(!String::from_utf8_lossy(bytes).contains(&episode.truth.malicious_event_ids[0]));
    }
}
