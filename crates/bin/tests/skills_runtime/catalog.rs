//! Each public episode runs through the release decoder/mapping, guard and custody paths.
mod checks;
mod hostile;
mod measurement;
mod model;
mod scenarios;
mod sources;
use irmind_app::{CancellationToken, LargeCaseUseCases};
use scenarios::SCENARIOS;

struct Scenario {
    name: &'static str,
    files: &'static [(&'static str, &'static str, &'static str)],
    query: &'static str,
    conclusion: &'static str,
    technique: &'static str,
    selected_source: usize,
    filters: &'static [(&'static str, &'static str)],
}

fn episode(index: usize) {
    let scenario = &SCENARIOS[index];
    let root = tempfile::tempdir().unwrap();
    let store = sources::open(&root.path().join("data"));
    let (_, engine) = super::setup_with_store(root.path(), store.clone(), false);
    let case = engine
        .create_case("Synthetic catalog episode", "local evidence only")
        .unwrap();
    let mut hashes = vec![];
    for (name, parser, content) in scenario.files {
        std::fs::write(root.path().join(name), content).unwrap();
        let parser = crate::current_sources::parser(parser);
        let large = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: parser.as_ref(),
        };
        let ingested = large
            .ingest_local_batch(
                &case.id,
                root.path(),
                &[(*name).into()],
                false,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(ingested.len(), 1, "{} {name}", scenario.name);
        hashes.push(ingested[0].1.as_str().to_owned());
    }
    let model = model::Episode::new(scenario, hashes);
    let answer = engine.investigate(&case.id, "Use the named local method to review this synthetic episode; distinguish observation from inference.", &model).unwrap();
    assert!(answer.contains(scenario.conclusion));
    checks::requests(scenario, &model);
    measurement::record(
        scenario,
        std::slice::from_ref(&model),
        store.as_ref(),
        &case.id,
        "single",
    );
    checks::evaluate(scenario, &engine, store.as_ref(), &case.id);
    checks::export(
        &engine,
        store.as_ref(),
        &case,
        root.path(),
        scenario.files.len(),
    );
}

macro_rules! skill_tests {
    ($positive:ident, $negative:ident, $index:literal) => {
        #[test]
        fn $positive() {
            episode($index);
        }
        #[test]
        fn $negative() {
            hostile::run(&SCENARIOS[$index]);
        }
    };
}
skill_tests!(s3_episode, s3_rejects_hostile_evidence, 0);
skill_tests!(entra_episode, entra_rejects_hostile_evidence, 1);
skill_tests!(gcp_episode, gcp_rejects_hostile_evidence, 2);
skill_tests!(ransomware_episode, ransomware_rejects_hostile_evidence, 3);
skill_tests!(
    lateral_movement_episode,
    lateral_rejects_hostile_evidence,
    4
);
skill_tests!(
    windows_persistence_episode,
    windows_persistence_rejects_hostile_evidence,
    5
);
skill_tests!(malware_episode, malware_rejects_hostile_evidence, 6);
skill_tests!(webshell_episode, webshell_rejects_hostile_evidence, 7);
skill_tests!(
    linux_persistence_episode,
    linux_persistence_rejects_hostile_evidence,
    8
);
skill_tests!(network_episode, network_rejects_hostile_evidence, 9);

#[test]
fn six_turn_scripted_investigation_records_budget_inputs_without_a_provider() {
    let scenario = &SCENARIOS[0];
    let root = tempfile::tempdir().unwrap();
    let store = sources::open(&root.path().join("data"));
    let (_, engine) = super::setup_with_store(root.path(), store.clone(), false);
    let case = engine
        .create_case("Synthetic multi-turn budget profile", "local")
        .unwrap();
    let (name, parser_id, content) = scenario.files[0];
    std::fs::write(root.path().join(name), content).unwrap();
    let parser = crate::current_sources::parser(parser_id);
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    let ingested = large
        .ingest_local_batch(
            &case.id,
            root.path(),
            &[name.into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let mut models = vec![];
    for turn in 0..6 {
        let model = model::Episode::new(scenario, vec![ingested[0].1.as_str().into()]);
        engine.investigate(&case.id, &format!("Review the synthetic evidence again for follow-up {turn}; preserve uncertainty."), &model).unwrap();
        assert_eq!(model.requests.lock().unwrap().len(), 7);
        models.push(model);
    }
    measurement::record(scenario, &models, store.as_ref(), &case.id, "six-turns");
    engine.verify(&case.id).unwrap();
}
