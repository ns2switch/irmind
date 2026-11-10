use super::*;
use irmind_app::{LogParser, source_mapping::SourceDecoderSelection};
fn mapped_registry(
    approved: &irmind_app::ApprovedDefinitions,
    definitions: &FileDefinitionStore,
) -> ModuleRegistry {
    let (active, _) = approved.load_active(definitions, &DeclarativeCompiler);
    let mut registry = ModuleRegistry::new();
    registry
        .register(
            Box::new(DeclarativeModule::new(active).unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry.with_definition_history(approved.clone(), Arc::new(DeclarativeCompiler))
}
#[test]
fn mapped_definition_rebuilds_after_replacement_and_deactivation_from_approved_history() {
    let root = tempfile::tempdir().unwrap();
    let base = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&base);
    let definitions = FileDefinitionStore::new(root.path());
    let id = engine
        .install_parser_definition(&definitions, &DeclarativeCompiler, DEFINITION)
        .unwrap();
    let approved = engine.approved_definitions().unwrap();
    let (active, _) = approved.load_active(&definitions, &DeclarativeCompiler);
    let selected: Arc<dyn LogParser> = Arc::new(
        SourceDecoderSelection::new(active[0].compiled().decoder().clone())
            .with_selector(active[0].compiled().selector().clone())
            .unwrap(),
    );
    let registry = mapped_registry(&approved, &definitions);
    let store = LocalStore::open_mapped(root.path(), Arc::new(registry.mapping_catalog().unwrap()))
        .unwrap();
    let source = root.path().join("input");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("access.csv"), SAMPLE).unwrap();
    let case = engine
        .create_case("Synthetic definition history", "local evidence only")
        .unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: selected.as_ref(),
    }
    .ingest_local_batch(
        &case.id,
        &source,
        &["access.csv".into()],
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    engine
        .install_parser_definition(
            &definitions,
            &DeclarativeCompiler,
            &DEFINITION.replace(
                "Synthetic comma-separated access events",
                "Updated synthetic access events",
            ),
        )
        .unwrap();
    assert_rebuild(&engine, &base, &definitions, root.path(), &case.id, &source);
    engine
        .deactivate_parser_definition(&definitions, &id)
        .unwrap();
    assert_rebuild(&engine, &base, &definitions, root.path(), &case.id, &source);
}
fn assert_rebuild(
    engine: &Engine<'_>,
    base: &LocalStore,
    definitions: &FileDefinitionStore,
    root: &std::path::Path,
    case: &irmind_domain::CaseId,
    source: &std::path::Path,
) {
    let approved = engine.approved_definitions().unwrap();
    let registry = mapped_registry(&approved, definitions);
    let store =
        LocalStore::open_mapped(root, Arc::new(registry.mapping_catalog().unwrap())).unwrap();
    let entries = base.entries(case).unwrap();
    let router = registry
        .parser_catalog()
        .with_resolver(approved.resolver(Arc::new(DeclarativeCompiler)))
        .rebuild_router(&entries)
        .unwrap();
    engine.verify(case).unwrap();
    LargeCaseUseCases {
        engine,
        store: &store,
        parser: &router,
    }
    .verify_parquet_rebuild(case, source, &CancellationToken::new())
    .unwrap();
}

#[test]
fn reconstruction_requires_approved_history_and_the_exact_mapping_snapshot() {
    use irmind_domain::{EvidenceHash, MappingInputRefV1, MappingProfileV1, MappingSnapshotRefV1};
    let root = tempfile::tempdir().unwrap();
    let base = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&base);
    let definitions = FileDefinitionStore::new(root.path());
    let id = engine
        .install_parser_definition(&definitions, &DeclarativeCompiler, DEFINITION)
        .unwrap();
    let approved = engine.approved_definitions().unwrap();
    let catalog = mapped_registry(&approved, &definitions)
        .mapping_catalog()
        .unwrap();
    let reference = catalog.snapshots().unwrap()[0].reference().unwrap();
    let inputs = vec![
        MappingInputRefV1::try_new(
            EvidenceHash::from_bytes([1; 32]),
            EvidenceHash::from_bytes([2; 32]),
            1,
        )
        .unwrap(),
    ];
    let profile = MappingProfileV1::try_new(inputs.clone(), vec![reference.clone()]).unwrap();
    engine
        .deactivate_parser_definition(&definitions, &id)
        .unwrap();
    let approved = engine.approved_definitions().unwrap();
    let inactive = mapped_registry(&approved, &definitions)
        .mapping_catalog()
        .unwrap();
    assert_eq!(inactive.manifests().len(), 0);
    assert!(
        !inactive.supports_decoder(
            &id,
            catalog.manifests().next().unwrap().selectors()[0]
                .versions()
                .first()
                .unwrap()
        )
    );
    let frozen = inactive.frozen_for_profile(&profile).unwrap();
    assert_eq!(
        frozen.snapshots().unwrap()[0].reference().unwrap(),
        reference
    );
    // Resolving a signed profile must not reactivate its mapping for new ingestions.
    assert_eq!(inactive.manifests().len(), 0);
    let wrong = MappingSnapshotRefV1::try_new(
        reference.mapping().clone(),
        EvidenceHash::from_bytes([3; 32]),
    );
    let changed = MappingProfileV1::try_new(inputs, vec![wrong]).unwrap();
    assert!(inactive.frozen_for_profile(&changed).is_err());
    let unapproved = ModuleRegistry::new()
        .with_definition_history(
            irmind_app::ApprovedDefinitions::default(),
            Arc::new(DeclarativeCompiler),
        )
        .mapping_catalog()
        .unwrap();
    assert!(unapproved.frozen_for_profile(&profile).is_err());
}
