use super::*;

fn source_catalog() -> Arc<irmind_app::source_mapping::MappingCatalog> {
    Arc::new(
        irmind_app::source_mapping::MappingCatalog::freeze(
            vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    )
}
pub(in crate::tests) fn open_source_store(root: &Path) -> Result<LocalStore, AppError> {
    LocalStore::open_mapped(root, source_catalog())
}
pub(in crate::tests) fn json_source_parser() -> irmind_app::source_mapping::SourceDecoderSelection {
    source_catalog()
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap()
}

pub(in crate::tests) fn source_fixture(
    root: &Path,
    seed: u8,
) -> (Arc<LocalStore>, Engine<'static>) {
    let store = Arc::new(open_source_store(root).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[seed; 32]),
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
    (store, engine)
}
