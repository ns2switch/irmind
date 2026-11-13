//! Installation proofs remain usable in a standalone public-key-only V6 export.
use super::*;
use irmind_app::source_mapping::{MappingCatalog, verify_mapping_installation};
use irmind_app::{LargeCaseUseCases, ParserSelection, SourceDecoder, SourceMapper};
use irmind_domain::ParserSelectionMode;
use irmind_mapping_tables::TableMapping;
use irmind_mod_parser_json::JsonSourceDecoder;
const DEFINITION: &str = r#"
interpreter = "irmind-mapping-tables-v2"
id = "mapping-synthetic-status"
version = "1"
target_schema = "irmind-common-event-v1"
source_contract = "irmind-source-record-v1"
parser = "parser-json"
parser_versions = ["json-source-v1"]
[[rules]]
categories = ["authentication"]
outcome = "failure"
[[rules.when]]
path = ["status"]
predicate = { op = "text", value = "failed" }
"#;
struct Harness {
    root: tempfile::TempDir,
    store: Arc<LocalStore>,
    signer: Arc<LocalSigner>,
}
impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        Self {
            store: Arc::new(open_source_store(root.path()).unwrap()),
            root,
            signer: Arc::new(LocalSigner {
                key: SigningKey::from_bytes(&[89; 32]),
                actor: Actor::Analyst,
            }),
        }
    }
    fn engine(&self, store: Arc<LocalStore>) -> Engine<'static> {
        Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store,
                CryptoPorts::new(
                    self.signer.clone(),
                    Arc::new(LocalVerifier::from_signer(self.signer.as_ref())),
                ),
                Arc::new(MandatoryGuard::new().unwrap()),
            ),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )
        .unwrap()
    }
    fn base() -> MappingCatalog {
        MappingCatalog::freeze(vec![Arc::new(JsonSourceDecoder)], vec![]).unwrap()
    }
}
#[test]
fn mapping_changes_preflight_overlap_versions_and_do_not_partially_append() {
    let h = Harness::new();
    let engine = h.engine(h.store.clone());
    let base = Harness::base();
    let manifest = TableMapping::review(DEFINITION).unwrap();
    let approved = engine
        .change_mapping_definition(&base, &manifest, true)
        .unwrap();
    assert!(approved.active());
    for invalid in [
        DEFINITION.replace("mapping-synthetic-status", "mapping-overlap"),
        DEFINITION.replace("failure", "success"),
    ] {
        let candidate = TableMapping::review(&invalid).unwrap();
        assert!(
            engine
                .change_mapping_definition(&base, &candidate, true)
                .is_err()
        );
        assert_eq!(h.store.global_operations().unwrap().len(), 1);
    }
    let disabled = engine
        .change_mapping_definition(&base, &manifest, false)
        .unwrap();
    assert!(!disabled.active());
    assert!(TableMapping::installed(&disabled).is_err());
    let enabled = engine
        .change_mapping_definition(&base, &manifest, true)
        .unwrap();
    assert!(enabled.active());
    engine.verify_global_operations().unwrap();
    assert_eq!(h.store.global_operations().unwrap().len(), 3);
}
#[test]
fn installation_proofs_bind_analyst_content_scope_and_active_authorization() {
    let h = Harness::new();
    let engine = h.engine(h.store.clone());
    let base = Harness::base();
    let reviewed = TableMapping::review(DEFINITION).unwrap();
    let approved = engine
        .change_mapping_definition(&base, &reviewed, true)
        .unwrap();
    let manifest = approved.installed_manifest().unwrap();
    let verifier = LocalVerifier::from_signer(h.signer.as_ref());
    verify_mapping_installation(
        &manifest,
        approved.operation(),
        &verifier,
        &h.signer.public_key(),
    )
    .unwrap();
    for mutate in [0, 1, 2, 3] {
        let mut proof = approved.operation().clone();
        match mutate {
            0 => proof.case_id = "case-other".into(),
            1 => {
                proof.actor =
                    Actor::Agent(irmind_domain::AgentId::parse("synthetic-agent").unwrap());
            }
            2 => proof.operation.push('0'),
            _ => proof.sig[0] ^= 1,
        }
        assert!(
            verify_mapping_installation(&manifest, &proof, &verifier, &h.signer.public_key())
                .is_err()
        );
    }
    let mapper: Arc<dyn SourceMapper> = Arc::new(TableMapping::installed(&approved).unwrap());
    assert!(
        MappingCatalog::freeze(vec![Arc::new(JsonSourceDecoder)], vec![mapper.clone()]).is_err()
    );
    assert!(
        MappingCatalog::freeze_authenticated(
            vec![Arc::new(JsonSourceDecoder)],
            vec![mapper.clone()],
            &[],
            &verifier,
            &h.signer.public_key()
        )
        .is_err()
    );
    MappingCatalog::freeze_authenticated(
        vec![Arc::new(JsonSourceDecoder)],
        vec![mapper],
        &[approved.operation().clone()],
        &verifier,
        &h.signer.public_key(),
    )
    .unwrap();
    assert!(!format!("{approved:?}{manifest:?}").contains("failed"));
}
#[test]
fn installed_mapping_round_trips_v7_without_keyring_and_rebuilds_exact_version() {
    let h = Harness::new();
    let engine = h.engine(h.store.clone());
    let definition = TableMapping::review(DEFINITION).unwrap();
    let approved = engine
        .change_mapping_definition(&Harness::base(), &definition, true)
        .unwrap();
    let mapper = Arc::new(TableMapping::installed(&approved).unwrap());
    let catalog = Arc::new(
        MappingCatalog::freeze_authenticated(
            vec![Arc::new(JsonSourceDecoder)],
            vec![mapper],
            &[approved.operation().clone()],
            engine.verifier.as_ref(),
            &h.signer.public_key(),
        )
        .unwrap(),
    );
    let store = Arc::new(LocalStore::open_mapped(h.root.path(), catalog.clone()).unwrap());
    let engine = h.engine(store.clone());
    let case = engine
        .create_case("Synthetic mapping", "local only")
        .unwrap();
    let raw = br#"{"eventTime":"2026-11-01T00:00:00Z","status":"failed"}"#;
    fs::write(h.root.path().join("record.json"), raw).unwrap();
    let parser = catalog
        .decoder_selection("parser-json", JsonSourceDecoder.identity().version)
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let selected = ParserSelection {
        parser_id: "parser-json".into(),
        parser_version: JsonSourceDecoder.identity().version.into(),
        confidence: 90,
        mode: ParserSelectionMode::Automatic,
        timestamp_context: None,
        cluster_context: None,
        format_sample_sha256: sha256(raw),
    };
    let cancel = CancellationToken::new();
    large
        .ingest_local_batch_selected(
            &case.id,
            h.root.path(),
            &["record.json".into()],
            true,
            &BTreeMap::from([("record.json".into(), selected)]),
            &cancel,
        )
        .unwrap();
    engine.verify(&case.id).unwrap();
    assert_eq!(count_parquet(&store.parquet.case_dir(&case.id).unwrap()), 1);
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, h.root.path(), &cancel)
            .unwrap(),
        1
    );
    engine.seal(&case.id).unwrap();
    let path = h.root.path().join("installed-v6.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &path, &cancel).unwrap();
    assert_eq!(
        LocalExportVerifier
            .verify_export_details(&path, Some(&key))
            .unwrap()
            .format_version,
        7
    );
    assert_tampered_proof_rejected(&path, approved.operation(), &key);
}
fn assert_tampered_proof_rejected(path: &Path, operation: &SignedOperation, key: &str) {
    let mut bytes = fs::read(path).unwrap();
    let needle = operation.operation.as_bytes();
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    bytes[offset + needle.len() - 1] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(
        LocalExportVerifier
            .verify_export_details(path, Some(key))
            .is_err()
    );
}

fn count_parquet(root: &Path) -> usize {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                count_parquet(&path)
            } else {
                usize::from(path.extension().is_some_and(|e| e == "parquet"))
            }
        })
        .sum()
}
