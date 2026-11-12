use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn large_sources_sign_complete_reports_and_current_parser_identity() {
    let root = tempfile::tempdir().unwrap();
    let inputs = root.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    let store = Arc::new(open_source_store(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[71u8; 32]),
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
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();

    let uses = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json_source_parser(),
    };
    let first =
        r#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"First","recipientAccountId":"123"}"#;
    let hidden =
        r#"{"eventTime":"2026-11-01T00:00:01Z","eventName":"Hidden","recipientAccountId":"123"}"#;
    let last =
        r#"{"eventTime":"2026-11-01T00:00:02Z","eventName":"Last","recipientAccountId":"123"}"#;
    let large_row = format!(
        "{{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"Synthetic\",\"payload\":\"{}\"}}",
        "x".repeat(2048)
    );
    let ordinary = format!(
        "{{\"Records\":[{}]}}",
        std::iter::repeat_n(large_row.as_str(), 2600)
            .collect::<Vec<_>>()
            .join(",")
    )
    .into_bytes();
    let mut partial = format!("{{\"Records\":[{first},").into_bytes();
    partial.resize(4 * 1024 * 1024 + 1, b' ');
    partial.extend_from_slice(format!("{hidden},\n{last}]}}").as_bytes());
    for (name, bytes, expected) in [
        ("ordinary.json", ordinary, 2600),
        ("partial.json", partial, 3),
    ] {
        let case = engine
            .create_case("Synthetic complete source", "local sources")
            .unwrap();
        fs::write(inputs.join(name), &bytes).unwrap();
        let baseline = store.entries(&case.id).unwrap().len();
        let result = uses.ingest_local_batch(
            &case.id,
            &inputs,
            &[name.into()],
            false,
            &CancellationToken::new(),
        );
        let entries = store.entries(&case.id).unwrap();
        result.unwrap();
        let source_entry = entries
            .iter()
            .find(|e| e.kind == AuditEventKind::SourceManifestV2)
            .unwrap();
        let manifest = irmind_domain::SourceManifestV2::decode(&source_entry.payload).unwrap();
        assert_eq!(manifest.rejected_records, 0);
        assert!(manifest.rejected_sample.is_empty());
        assert_eq!(manifest.source.size, bytes.len() as u64);
        assert_eq!(
            manifest.source.sha256.as_str(),
            irmind_app::hex(&irmind_app::sha256(&bytes))
        );
        let timeline = store.timeline(&case.id, 10000).unwrap();
        assert_eq!(timeline.len(), expected.min(100));
        assert!(
            store
                .graph_summary(&case.id)
                .unwrap()
                .contains(&format!("Parquet records={expected};"))
        );
        assert_eq!(manifest.parser_version, "json-source-v1");
        assert_eq!(manifest.parser_id, "parser-json");
        assert_eq!(manifest.confidence, 0);
        assert_eq!(
            manifest.selection,
            irmind_domain::ParserSelectionMode::Analyst
        );
        assert!(entries.len() > baseline);
        assert!(engine.verify(&case.id).is_ok());
    }
}
