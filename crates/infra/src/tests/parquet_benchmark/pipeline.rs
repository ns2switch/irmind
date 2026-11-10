//! Release-only measurements run the complete ingestion and custody path.
mod report;
mod sources;
use super::*;
use irmind_app::source_mapping::MappingCatalog;
use irmind_app::{SourceDecoder, SourceMapper, StreamingEventParser};

#[test]
#[ignore = "manual release-only production pipeline timing and allocation profile"]
fn source_pipeline_production_1gib() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("release build required");
    }
    let label = std::env::var("IRMIND_PIPELINE_SOURCE").unwrap();
    let input = sources::Input::generate(&label);
    let single = std::env::var("IRMIND_PIPELINE_VARIANT").ok();
    let repetitions = if single.is_some() { 1 } else { 3 };
    for repetition in 1..=repetitions {
        for mapped in [false, true] {
            if single.as_deref().is_some_and(|v| (v == "v3") != mapped) {
                continue;
            }
            measure(&label, &input, mapped, repetition);
        }
    }
    Ok(())
}
fn measure(label: &str, input: &sources::Input, mapped: bool, repetition: u32) {
    let root = tempfile::tempdir().unwrap();
    let mut store = LocalStore::open(root.path()).unwrap();
    let (catalog, mapping) = sources::catalog(label, root.path());
    store.parquet = if mapped {
        crate::ParquetStore::open_mapped(root.path(), catalog.clone()).unwrap()
    } else {
        crate::ParquetStore::open_precise(root.path()).unwrap()
    };
    let profile = Arc::new(ParquetProfile::default());
    store.parquet.attach_profile(profile.clone());
    let store = Arc::new(store);
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[74; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
    let mut ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(
            signer.clone(),
            Arc::new(LocalVerifier::from_signer(signer.as_ref())),
        ),
        Arc::new(MandatoryGuard::new().unwrap()),
        parser,
    );
    let custody = custody::attach(&mut ports);
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock)).unwrap();
    let case = engine
        .create_case("Synthetic production pipeline", "local only")
        .unwrap();
    let parser = sources::parser(label, mapped, &catalog, root.path());
    custody.reset();
    let start = Instant::now();
    ingest_production(&engine, store.as_ref(), parser.as_ref(), &case.id, input);
    let elapsed = start.elapsed();
    report::check(&store, &case.id, root.path(), input.records);
    engine.verify(&case.id).unwrap();
    report::print(
        label, mapped, repetition, input, elapsed, &profile, &mapping,
    );
    custody.report();
}
// A stable symbol also bounds allocation attribution to the real ingestion.
#[inline(never)]
fn ingest_production(
    engine: &Engine<'_>,
    store: &LocalStore,
    parser: &dyn StreamingEventParser,
    case: &CaseId,
    input: &sources::Input,
) {
    ingest_selected(
        &LargeCaseUseCases {
            engine,
            store,
            parser,
        },
        case,
        input.root.path(),
        std::slice::from_ref(&input.name),
    );
}
