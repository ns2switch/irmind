use super::*;

#[test]
#[ignore = "manual and weekly CI benchmark: ingests over 1 GB of synthetic CloudTrail JSON"]
fn graph_benchmark_1gb() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[73u8; 32]),
        actor: Actor::Analyst,
    });
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
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("Synthetic graph benchmark", "local")
        .unwrap();
    let padding = "x".repeat(40 * 1024 * 1024);
    let mut total_bytes = 0usize;
    let start = std::time::Instant::now();
    for index in 0..25 {
        let source = format!("synthetic/cloudtrail-{index:02}.json");
        let bytes = format!(
            "{{\"Records\":[{{\"eventTime\":\"2026-10-27T12:00:00Z\",\"eventName\":\"SyntheticBenchmark\",\"sequence\":{index},\"message\":\"{padding}\"}}]}}"
        );
        total_bytes += bytes.len();
        engine.ingest(&case.id, bytes.as_bytes(), &source).unwrap();
    }
    assert!(total_bytes >= 1_000_000_000);
    let ingest_seconds = start.elapsed().as_secs_f64();
    let query_start = std::time::Instant::now();
    let result = store
        .text_search(&case.id, "SyntheticBenchmark", 20)
        .unwrap();
    let query_seconds = query_start.elapsed().as_secs_f64();
    assert!(result.contains("source="));
    let raw_tokens = total_bytes.div_ceil(4);
    let result_tokens = result.len().div_ceil(4);
    println!(
        "GRAPH_BENCHMARK bytes={total_bytes} ingest_seconds={ingest_seconds:.3} query_seconds={query_seconds:.3} raw_tokens_est={raw_tokens} indexed_tokens_est={result_tokens}"
    );
}
