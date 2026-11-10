use super::*;

#[test]
#[ignore = "weekly evaluation requires the pinned external HuntEval source and private answers"]
fn hunteval_reference_corpus() -> Result<(), String> {
    for precise in [false, true] {
        reference_corpus(precise)?;
    }
    Ok(())
}

fn reference_corpus(precise: bool) -> Result<(), String> {
    let source = root_from_environment().ok_or("IRMIND_HUNTEVAL_ROOT is required")?;
    let episodes = load_episodes(&source);
    let mut metrics = BTreeMap::new();
    for episode in &episodes {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("source");
        fs::create_dir(&input).unwrap();
        let names = stage_sources(&input, std::slice::from_ref(episode));
        let mut local = open_source_store(&root.path().join("case")).unwrap();
        if precise {
            local.parquet = crate::ParquetStore::open_precise(&root.path().join("case")).unwrap();
        }
        let store = Arc::new(local);
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
            parser: &json_source_parser(),
        };
        assert_eq!(ingest_selected(&ingest, &case.id, &input, &names), 1);
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
    report_metrics(
        if precise {
            "reference-v2"
        } else {
            "reference-v1"
        },
        &metrics,
    );
    Ok(())
}
