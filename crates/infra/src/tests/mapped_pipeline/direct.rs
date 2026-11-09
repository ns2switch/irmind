use super::*;
use irmind_app::RejectedSource;

#[test]
fn direct_physical_recipe_is_a_portable_golden_with_current_build_bindings() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Direct physical golden", "local only")
        .unwrap();
    let path = root.path().join("source.json");
    fs::write(&path, br#"{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Login","sourceIPAddress":"203.0.113.77"}"#).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_hours(482_136))
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    large
        .ingest_local_batch(
            &case.id,
            root.path(),
            &["source.json".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let outputs = irmind_app::artifact_catalog(&store.entries(&case.id).unwrap())
        .unwrap()
        .active;
    let actual = outputs
        .iter()
        .map(|output| {
            let ParquetArtifact::V3(mapped) = output else {
                panic!("direct output must carry V3 bindings");
            };
            assert_eq!(
                mapped.core().builder_version,
                irmind_domain::COMMON_EVENT_DIRECT_BUILDER
            );
            assert_eq!(
                irmind_domain::ParquetArtifactV3::decode(&mapped.encode().unwrap()).unwrap(),
                *mapped
            );
            serde_json::json!({
                "schema": output.schema_version(),
                "physical_sha256": output.sha256().as_str(),
            })
        })
        .collect::<Vec<_>>();
    let expected: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("direct-golden.json")).unwrap();
    assert_eq!(
        actual,
        expected,
        "DIRECT_PHYSICAL_GOLDEN {}",
        serde_json::to_string(&actual).unwrap()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn corrupt_sources_refill_groups_without_changing_clean_derived_bytes() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let inputs = root.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    let all = (0..300).map(|index| {
        let name = format!("source-{index:03}.json");
        let json = format!(r#"{{"Records":[{{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Event{index}","sourceIPAddress":"203.0.113.77"}}]}}"#);
        let bytes = if [1,150,299].contains(&index) { json.trim_end_matches('}').to_owned() } else { json };
        fs::write(inputs.join(&name), bytes).unwrap(); name
    }).collect::<Vec<_>>();
    let clean = all
        .iter()
        .enumerate()
        .filter(|(index, _)| ![1, 150, 299].contains(index))
        .map(|(_, name)| name.clone())
        .collect::<Vec<_>>();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let mixed = engine
        .create_case("Mixed collection", "local only")
        .unwrap();
    let healthy = engine
        .create_case("Clean collection", "local only")
        .unwrap();
    let accepted = use_cases
        .ingest_local_batch(&mixed.id, &inputs, &all, false, &CancellationToken::new())
        .unwrap();
    assert_eq!(accepted.len(), 297);
    use_cases
        .ingest_local_batch(
            &healthy.id,
            &inputs,
            &clean,
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    let left = store.entries(&mixed.id).unwrap();
    let right = store.entries(&healthy.id).unwrap();
    let rejected = left
        .iter()
        .filter_map(|entry| RejectedSource::from_audit(entry).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rejected.len(), 3);
    assert_eq!(
        rejected
            .iter()
            .map(RejectedSource::source)
            .collect::<Vec<_>>(),
        ["source-001.json", "source-150.json", "source-299.json"]
    );
    let catalog_left = irmind_app::artifact_catalog(&left).unwrap();
    let catalog_right = irmind_app::artifact_catalog(&right).unwrap();
    assert_eq!(catalog_left.all, catalog_left.active);
    assert_eq!(catalog_left.all, catalog_right.all);
    assert!(
        catalog_left
            .all
            .iter()
            .all(|a| a.precise_metadata().unwrap().builder_version
                == irmind_domain::COMMON_EVENT_DIRECT_BUILDER)
    );
    for kind in [
        AuditEventKind::SourceRecordSetV1,
        AuditEventKind::MappingProfileV1,
        AuditEventKind::MappingRunV1,
    ] {
        assert_eq!(
            left.iter()
                .filter(|e| e.kind == kind)
                .map(|e| &e.payload)
                .collect::<Vec<_>>(),
            right
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| &e.payload)
                .collect::<Vec<_>>()
        );
    }
    engine.verify(&mixed.id).unwrap();
    engine.verify(&healthy.id).unwrap();
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&mixed.id, &inputs, &CancellationToken::new())
            .unwrap(),
        297
    );
    engine.seal(&mixed.id).unwrap();
    let export = root.path().join("direct.irmind");
    let key = irmind_app::export_case(
        &engine,
        store.as_ref(),
        &mixed.id,
        &export,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        LocalExportVerifier
            .verify_export_details(&export, Some(&key))
            .unwrap()
            .format_version,
        6
    );
    assert_eq!(
        fs::read_dir(store.parquet.case_dir(&mixed.id).unwrap().join("spool"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn copied_direct_sources_reconstruct_without_the_external_originals() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Copied direct reconstruction", "local only")
        .unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let paths = ["first.json", "second.json"].map(String::from);
    for (index, path) in paths.iter().enumerate() {
        fs::write(
            sources.join(path),
            format!(r#"{{"eventTime":"2026-11-01T00:00:0{index}.123456789Z","eventName":"Event{index}","sourceIPAddress":"203.0.113.77"}}"#),
        )
        .unwrap();
    }
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    large
        .ingest_local_batch(&case.id, &sources, &paths, true, &CancellationToken::new())
        .unwrap();
    for path in &paths {
        fs::remove_file(sources.join(path)).unwrap();
    }
    let before = store.last_entry(&case.id).unwrap().unwrap();
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, &sources, &CancellationToken::new())
            .unwrap(),
        2
    );
    let after = store.last_entry(&case.id).unwrap().unwrap();
    assert_eq!((after.seq, after.hash), (before.seq, before.hash));
    engine.verify(&case.id).unwrap();
    assert_eq!(
        fs::read_dir(store.parquet.case_dir(&case.id).unwrap().join("spool"))
            .unwrap()
            .count(),
        0
    );
}
