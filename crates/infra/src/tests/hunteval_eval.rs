//! Deterministic, model-free evaluation against an externally pinned `HuntEval` checkout.
//! Only `source/events.json` is staged for ingestion. Private answers stay in this evaluator.

use super::*;
use irmind_app::LargeCaseUseCases;
use irmind_domain::GraphQueryFilter;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct GroundTruth {
    episode_id: String,
    malicious_event_ids: Vec<String>,
    malicious_entity_ids: Vec<String>,
    expected_attack_path: Vec<String>,
}

pub(super) struct Episode {
    provider: String,
    truth: GroundTruth,
    events: Vec<Value>,
    source: PathBuf,
    hash: String,
}

#[derive(Default)]
pub(super) struct ProviderMetrics {
    event_hits: usize,
    event_total: usize,
    entity_hits: usize,
    entity_total: usize,
    path_hits: usize,
    path_total: usize,
    parse_errors: usize,
    timings: BTreeMap<&'static str, Vec<Duration>>,
}

pub(super) fn root_from_environment() -> Option<PathBuf> {
    std::env::var_os("IRMIND_HUNTEVAL_ROOT").map(PathBuf::from)
}

pub(super) fn load_episodes(root: &Path) -> Vec<Episode> {
    let mut episodes = Vec::new();
    for provider in ["aws", "azure", "gcp"] {
        for number in 1..=6 {
            let id = format!("{provider}-iam-{number:03}");
            let base = root.join("datasets").join(provider).join(&id);
            let source = base.join("source/events.json");
            let bytes = fs::read(&source).unwrap();
            let events: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
            let truth: GroundTruth =
                serde_json::from_slice(&fs::read(base.join("private/ground-truth.json")).unwrap())
                    .unwrap();
            assert_eq!(truth.episode_id, id);
            episodes.push(Episode {
                provider: provider.into(),
                truth,
                events,
                source,
                hash: hex(&sha256(&bytes)),
            });
        }
    }
    episodes
}

pub(super) fn stage_sources(root: &Path, episodes: &[Episode]) -> Vec<String> {
    episodes
        .iter()
        .map(|episode| {
            let name = format!("{}.json", episode.truth.episode_id);
            fs::copy(&episode.source, root.join(&name)).unwrap();
            name
        })
        .collect()
}

pub(super) fn evaluate_case(
    store: &LocalStore,
    id: &CaseId,
    episodes: &[Episode],
    metrics: &mut BTreeMap<String, ProviderMetrics>,
) {
    for episode in episodes {
        let stats = metrics.entry(episode.provider.clone()).or_default();
        let filter = episode_filter(episode);
        evaluate_events(store, id, episode, &filter, stats);
        evaluate_entities(store, id, episode, &filter, stats);
        evaluate_path(store, id, episode, &filter, stats);
    }
}

fn episode_filter(episode: &Episode) -> GraphQueryFilter {
    let times = episode
        .events
        .iter()
        .map(|event| event["event_time"].as_str().unwrap())
        .collect::<Vec<_>>();
    GraphQueryFilter::parse(
        Some(times.iter().copied().min().unwrap()),
        Some(times.iter().copied().max().unwrap()),
        None,
        None,
        Some(&episode.provider),
    )
    .unwrap()
}

fn event_ref(episode: &Episode, event_id: &str) -> String {
    format!("{}:{event_id}", episode.hash)
}

fn event<'a>(episode: &'a Episode, event_id: &str) -> (usize, &'a Value) {
    episode
        .events
        .iter()
        .enumerate()
        .find(|(_, value)| value["event_id"] == event_id)
        .unwrap()
}

fn timed<T>(stats: &mut ProviderMetrics, name: &'static str, operation: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let result = operation();
    stats
        .timings
        .entry(name)
        .or_default()
        .push(started.elapsed());
    result
}

fn evaluate_events(
    store: &LocalStore,
    id: &CaseId,
    episode: &Episode,
    filter: &GraphQueryFilter,
    stats: &mut ProviderMetrics,
) {
    let mut times = Vec::new();
    for event_id in &episode.truth.malicious_event_ids {
        stats.event_total += 1;
        let (index, source) = event(episode, event_id);
        let searched = timed(stats, "term", || {
            store.text_search_filtered(id, filter, event_id, 20)
        })
        .unwrap();
        let pointer = format!("{}#{index}", episode.hash);
        assert!(
            searched.contains(&pointer),
            "term {event_id} in {}",
            episode.truth.episode_id
        );
        let lookup = timed(stats, "event", || {
            store.entity_lookup_filtered(id, filter, "event_id", &event_ref(episode, event_id))
        })
        .unwrap();
        assert!(!lookup.contains("count=0"), "event {event_id} missing");
        let timeline = timed(stats, "timeline", || {
            store.entity_timeline_filtered(
                id,
                filter,
                "event_id",
                &event_ref(episode, event_id),
                20,
            )
        })
        .unwrap();
        let at = source["event_time"].as_str().unwrap();
        assert!(
            timeline.contains(at),
            "timeline {event_id} in {}",
            episode.truth.episode_id
        );
        times.push((event_id, at));
        stats.event_hits += 1;
    }
    for pair in times.windows(2) {
        assert!(pair[0].1 <= pair[1].1, "attack timeline out of order");
    }
}

fn evaluate_entities(
    store: &LocalStore,
    id: &CaseId,
    episode: &Episode,
    filter: &GraphQueryFilter,
    stats: &mut ProviderMetrics,
) {
    for value in &episode.truth.malicious_entity_ids {
        stats.entity_total += 1;
        let kind = if value.contains(":resource:") {
            "resource"
        } else {
            "principal"
        };
        let found = timed(stats, "entity", || {
            store.entity_lookup_filtered(id, filter, kind, value)
        })
        .unwrap();
        assert!(!found.contains("count=0"), "entity {value} missing");
        let neighbors = timed(stats, "neighbors", || {
            store.neighbors_filtered(id, filter, kind, value, 20)
        })
        .unwrap();
        assert!(
            neighbors.contains("co-observed"),
            "neighbors of {value} missing"
        );
        stats.entity_hits += 1;
    }
}

fn evaluate_path(
    store: &LocalStore,
    id: &CaseId,
    episode: &Episode,
    filter: &GraphQueryFilter,
    stats: &mut ProviderMetrics,
) {
    for pair in episode.truth.expected_attack_path.windows(2) {
        stats.path_total += 1;
        let from = event_ref(episode, &pair[0]);
        let to = event_ref(episode, &pair[1]);
        let path = timed(stats, "path", || {
            store.graph_path_filtered(id, filter, ("event_id", &from), ("event_id", &to))
        })
        .unwrap();
        assert!(
            path.contains(&to),
            "attack path {} -> {} missing: {path}",
            pair[0],
            pair[1]
        );
        stats.path_hits += 1;
    }
}

pub(super) fn report_metrics(label: &str, metrics: &BTreeMap<String, ProviderMetrics>) {
    for (provider, stats) in metrics {
        println!(
            "HUNTEVAL_RECALL corpus={label} provider={provider} events={}/{} entities={}/{} path={}/{} parse_errors={}",
            stats.event_hits,
            stats.event_total,
            stats.entity_hits,
            stats.entity_total,
            stats.path_hits,
            stats.path_total,
            stats.parse_errors
        );
        assert_eq!(stats.event_hits, stats.event_total);
        assert_eq!(stats.entity_hits, stats.entity_total);
        assert_eq!(stats.path_hits, stats.path_total);
        assert_eq!(stats.parse_errors, 0);
        for (query, samples) in &stats.timings {
            let mut sorted = samples.clone();
            sorted.sort();
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[(sorted.len() * 95 / 100).min(sorted.len() - 1)];
            println!(
                "HUNTEVAL_QUERY corpus={label} provider={provider} query={query} samples={} p50_seconds={:.3} p95_seconds={:.3}",
                sorted.len(),
                p50.as_secs_f64(),
                p95.as_secs_f64()
            );
        }
    }
}

#[test]
fn private_answers_are_never_ingested_or_displayed() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("source");
    let private_root = root.path().join("private");
    fs::create_dir(&source_root).unwrap();
    fs::create_dir(&private_root).unwrap();
    let public = include_bytes!("../../../parser-json/tests/fixtures/hunteval-aws-iam-001.json");
    fs::write(source_root.join("events.json"), public).unwrap();
    let secret_marker = "PRIVATE_TRUTH_MUST_NOT_ENTER_CASE_12345";
    fs::write(
        private_root.join("ground-truth.json"),
        format!("{{\"acceptable_conclusions\":[\"{secret_marker}\"]}}"),
    )
    .unwrap();
    let store = Arc::new(LocalStore::open(&root.path().join("case")).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[76u8; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("public episode only", "local").unwrap();
    let ingest = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    let hash = ingest
        .ingest_local(
            &case.id,
            &source_root,
            "events.json",
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let raw = store.raw_record(&case.id, hash.as_str(), 3).unwrap();
    let visible = irmind_app::ContentGuard::screen(&MandatoryGuard::new().unwrap(), &raw).unwrap();
    assert!(!visible.text.contains(secret_marker));
    assert!(
        !store
            .graph_summary(&case.id)
            .unwrap()
            .contains(secret_marker)
    );
    let mut partitions = Vec::new();
    for entry in store.entries(&case.id).unwrap() {
        assert!(!entry.payload.contains(secret_marker));
        assert!(!entry.payload.contains("ground-truth.json"));
        if entry.kind == irmind_domain::AuditEventKind::ParquetArtifactV1 {
            let artifact = irmind_domain::ParquetArtifactV1::decode(&entry.payload).unwrap();
            assert_eq!(artifact.partition_date, "2026-01-10");
            assert_eq!(artifact.partition_region, "aws");
            partitions.push(artifact.partition_account);
        }
    }
    assert!(partitions.contains(&"111122223333".to_owned()));
    assert!(partitions.contains(&"444455556666".to_owned()));
}

#[test]
#[ignore = "weekly evaluation requires the pinned external HuntEval source and private answers"]
fn hunteval_reference_corpus() -> Result<(), String> {
    let source = root_from_environment().ok_or("IRMIND_HUNTEVAL_ROOT is required")?;
    let episodes = load_episodes(&source);
    let mut metrics = BTreeMap::new();
    for episode in &episodes {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("source");
        fs::create_dir(&input).unwrap();
        let names = stage_sources(&input, std::slice::from_ref(episode));
        let store = Arc::new(LocalStore::open(&root.path().join("case")).unwrap());
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[75u8; 32]),
            actor: Actor::Analyst,
        });
        let parser = Arc::new(JsonParser);
        let engine = Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(
                    signer.clone(),
                    Arc::new(LocalVerifier::from_signer(signer.as_ref())),
                ),
                Arc::new(MandatoryGuard::new().unwrap()),
                parser.clone(),
            ),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )
        .unwrap();
        let case = engine
            .create_case("HuntEval synthetic episode", "local")
            .unwrap();
        let ingest = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: parser.as_ref(),
        };
        let count = ingest
            .ingest_local_batch(&case.id, &input, &names, false, &CancellationToken::new())
            .unwrap();
        assert_eq!(count.len(), 1);
        assert_eq!(
            ingest
                .verify_parquet_rebuild(&case.id, &input, &CancellationToken::new())
                .unwrap(),
            1
        );
        assert!(
            !store
                .entries(&case.id)
                .unwrap()
                .iter()
                .any(|entry| entry.payload.contains("ground-truth")
                    || entry.payload.contains("acceptable_conclusions"))
        );
        evaluate_case(
            store.as_ref(),
            &case.id,
            std::slice::from_ref(episode),
            &mut metrics,
        );
    }
    report_metrics("reference", &metrics);
    Ok(())
}
