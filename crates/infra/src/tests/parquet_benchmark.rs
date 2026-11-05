use super::hunteval_eval;
use super::*;
use crate::parquet_store::ParquetProfile;
use irmind_app::LargeCaseUseCases;
use std::time::Instant;
mod corpus;
mod measurements;
mod scenario;
use corpus::{directory_bytes, representative_records, stage_worst_case_path};
use scenario::Scenario;

#[test]
#[ignore = "manual and weekly benchmark: synthetic 1 GB CloudTrail corpus"]
fn parquet_benchmark_1gb() {
    benchmark(1_000, 1, "1gb");
}

#[test]
#[ignore = "manual and weekly benchmark: synthetic 15 GB CloudTrail corpus"]
fn parquet_benchmark_15gb() {
    benchmark(1_000, 15, "15gb");
}

#[test]
#[ignore = "local diagnostic: 50 MB synthetic CloudTrail corpus"]
fn parquet_benchmark_50mb() {
    benchmark(50, 1, "50mb");
}

fn benchmark(files: usize, multiplier: usize, label: &str) {
    let scenario = Scenario::from_environment();
    run_benchmark(files, multiplier, label, &scenario);
}

#[allow(clippy::too_many_lines)]
fn run_benchmark(files: usize, multiplier: usize, label: &str, scenario: &Scenario) {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("sources");
    fs::create_dir(&source_root).unwrap();
    let mut store = LocalStore::open(&root.path().join("case")).unwrap();
    if scenario.precise {
        store.parquet = crate::ParquetStore::open_precise(&root.path().join("case")).unwrap();
    }
    let profile = Arc::new(ParquetProfile::default());
    store.parquet.attach_profile(profile.clone());
    let store = Arc::new(store);
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[74u8; 32]),
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
        .create_case("Synthetic Parquet benchmark", "local synthetic sources")
        .unwrap();
    let endpoint_parser = irmind_mod_parser_linux::LinuxParser::default();
    let source_parser: &dyn irmind_app::StreamingEventParser = if scenario.hosts.is_some() {
        &endpoint_parser
    } else {
        parser.as_ref()
    };
    let ingest = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: source_parser,
    };
    let mut total_bytes = 0u64;
    let started = Instant::now();
    for start in (0..files).step_by(4) {
        let names = (start..(start + 4).min(files))
            .map(|index| {
                let data = scenario.source(index, multiplier);
                total_bytes += data.len() as u64;
                let name = format!("source-{index:04}.json");
                fs::write(source_root.join(&name), data).unwrap();
                name
            })
            .collect::<Vec<_>>();
        ingest_selected(&ingest, &case.id, &source_root, &names);
        for name in names {
            fs::remove_file(source_root.join(name)).unwrap();
        }
        if start.is_multiple_of(100) {
            eprintln!("PARQUET_PROGRESS files={} of {files}", start + 4);
        }
    }
    if label == "15gb" && scenario.hosts.is_none() {
        total_bytes += stage_worst_case_path(&source_root, &case.id, &ingest);
    }
    let episodes = hunteval_eval::root_from_environment()
        .filter(|_| scenario.hosts.is_none())
        .map(|root| {
            let episodes = hunteval_eval::load_episodes(&root);
            let names = hunteval_eval::stage_sources(&source_root, &episodes);
            total_bytes += names
                .iter()
                .map(|name| fs::metadata(source_root.join(name)).unwrap().len())
                .sum::<u64>();
            for batch in names.chunks(4) {
                ingest_selected(&ingest, &case.id, &source_root, batch);
            }
            episodes
        });
    let bundles = ingest
        .compact_case(&case.id, &CancellationToken::new())
        .unwrap();
    println!("PARQUET_COMPACTION bundles={bundles}");
    let ingest_time = started.elapsed();
    let [hash_time, conversion_time, row_time, parquet_time, _, _] = profile.snapshot();
    let disk_bytes = directory_bytes(&root.path().join("case/parquet"));
    let coobservation_bytes = measurements::report_storage(
        store.as_ref(),
        &case.id,
        &root.path().join("case"),
        scenario,
    );
    println!(
        "PARQUET_SCENARIO name={} size={label} normalized_stage_peak_bytes={}",
        scenario.name(),
        profile.temporary_disk_peak()
    );
    println!(
        "PARQUET_INGEST bytes={total_bytes} files={files} hash_seconds={:.3} conversion_seconds={:.3} row_seconds={:.3} parquet_seconds={:.3} wall_seconds={:.3} parquet_bytes={disk_bytes} coobservation_bytes={coobservation_bytes}",
        hash_time.as_secs_f64(),
        conversion_time.as_secs_f64(),
        row_time.as_secs_f64(),
        parquet_time.as_secs_f64(),
        ingest_time.as_secs_f64()
    );
    let ingest_target = ingest_time < std::time::Duration::from_mins(15);
    let [stage, sort, replay, source_verify, publish] = profile.partition_snapshot();
    println!(
        "PARQUET_V2_PHASE stage_seconds={:.3} sort_seconds={:.3} replay_seconds={:.3} source_verify_seconds={:.3} publish_seconds={:.3}",
        stage.as_secs_f64(),
        sort.as_secs_f64(),
        replay.as_secs_f64(),
        source_verify.as_secs_f64(),
        publish.as_secs_f64()
    );
    let cold_started = Instant::now();
    let cold = store.graph_summary(&case.id);
    println!(
        "PARQUET_COLD_QUERY seconds={:.3} error={}",
        cold_started.elapsed().as_secs_f64(),
        cold.is_err()
    );
    let cold_target = cold.is_ok();
    let query_target = measurements::report_queries(store.as_ref(), &case.id, scenario);
    let [_, _, _, _, verify_time, scan_time] = profile.snapshot();
    println!(
        "PARQUET_QUERY_PHASE verify_seconds={:.3} scan_seconds={:.3}",
        verify_time.as_secs_f64(),
        scan_time.as_secs_f64()
    );
    if let Some(episodes) = episodes {
        let mut metrics = std::collections::BTreeMap::new();
        hunteval_eval::evaluate_case(store.as_ref(), &case.id, &episodes, &mut metrics);
        hunteval_eval::report_metrics(label, &metrics);
    }
    if label == "15gb" && scenario.hosts.is_none() {
        let started = Instant::now();
        let path = store
            .graph_path(&case.id, ("account", "887700000000"), ("ip", "192.0.2.250"))
            .unwrap();
        println!(
            "PARQUET_WORST_PATH seconds={:.3} truncated={} time_budget={}",
            started.elapsed().as_secs_f64(),
            path.contains("truncated"),
            path.contains("10-second time budget")
        );
        assert!(path.contains("truncated"));
    }
    assert!(
        ingest_target,
        "Parquet ingestion exceeded the 15-minute benchmark target"
    );
    assert!(cold_target, "cold graph summary failed");
    assert!(
        query_target,
        "Parquet queries failed or exceeded the 10-second benchmark target"
    );
}

#[test]
fn parquet_v2_benchmark_endpoint_smoke() {
    run_benchmark(
        4,
        1,
        "smoke",
        &Scenario {
            precise: true,
            hosts: Some(2),
            source_bytes: 2048,
            chronological: false,
        },
    );
}

#[test]
fn parquet_v1_benchmark_endpoint_smoke() {
    run_benchmark(
        4,
        1,
        "smoke",
        &Scenario {
            precise: false,
            hosts: Some(2),
            source_bytes: 2048,
            chronological: false,
        },
    );
}
