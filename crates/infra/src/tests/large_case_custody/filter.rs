use super::*;
use irmind_app::GraphQueryFilter;

#[test]
fn parquet_filters_prune_partitions_and_exact_utc_window() {
    let root = tempfile::tempdir().unwrap();
    let inputs = write_source(root.path());
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
        .create_case(
            "filtered case",
            "v2;sources=local;accounts=111111111111,222222222222;projects=;hosts=;from=2026-10-27T00:00:00Z;to=2026-10-29T00:00:00Z",
        )
        .unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    }
    .ingest_local(
        &case.id,
        &inputs,
        "events.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let filter = GraphQueryFilter::parse(
        Some("2026-10-28T11:59:00Z"),
        Some("2026-10-28T12:30:00Z"),
        Some("222222222222"),
        None,
        Some("eu-west-1"),
    )
    .unwrap();
    let rows = store.timeline_filtered(&case.id, &filter, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event, "BetaEvent");
    let search = store
        .text_search_filtered(&case.id, &filter, "Event", 10)
        .unwrap();
    assert!(search.contains("BetaEvent"));
    assert!(!search.contains("AlphaEvent") && !search.contains("GammaEvent"));
    assert!(
        store
            .entity_lookup_filtered(&case.id, &filter, "ip", "203.0.113.2")
            .unwrap()
            .contains("count=1")
    );
    let out_of_scope =
        GraphQueryFilter::parse(None, None, Some("333333333333"), None, None).unwrap();
    assert!(
        store
            .text_search_filtered(&case.id, &out_of_scope, "Event", 10)
            .is_err()
    );
    assert_two_hop_path(&store, &case.id, &filter);
}

fn assert_two_hop_path(store: &LocalStore, id: &CaseId, filter: &GraphQueryFilter) {
    let two_hop = store
        .graph_path_filtered(
            id,
            &GraphQueryFilter::default(),
            ("ip", "203.0.113.2"),
            ("ip", "203.0.113.3"),
        )
        .unwrap();
    assert!(two_hop.contains("account 222222222222"));
    assert_eq!(two_hop.lines().count(), 2);
    let filtered_path = store
        .graph_path_filtered(id, filter, ("ip", "203.0.113.2"), ("ip", "203.0.113.3"))
        .unwrap();
    assert!(filtered_path.starts_with("no co-observation path"));
}

fn write_source(root: &Path) -> PathBuf {
    let inputs = root.join("inputs");
    fs::create_dir(&inputs).unwrap();
    fs::write(
        inputs.join("events.json"),
        br#"{"Records":[
          {"eventTime":"2026-10-27T12:00:00Z","eventName":"AlphaEvent","recipientAccountId":"111111111111","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.1"},
          {"eventTime":"2026-10-28T12:00:00Z","eventName":"BetaEvent","recipientAccountId":"222222222222","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.2"},
          {"eventTime":"2026-10-28T14:00:00Z","eventName":"GammaEvent","recipientAccountId":"222222222222","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.3"}
        ]}"#,
    )
    .unwrap();
    inputs
}
