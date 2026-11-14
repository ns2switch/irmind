#![allow(clippy::unwrap_used)]
mod blocked;
use super::*;
use crate::{LocalVerifier, SystemClock, signing::LocalSigner};
use ed25519_dalek::SigningKey;
use irmind_app::{
    CryptoPorts, Engine, EnginePorts, LargeCaseUseCases, ParserSelection, SourceDecoder,
    source_mapping::MappingCatalog,
};
use irmind_domain::{Actor, ExecutionMode, ParserSelectionMode};

const RAW: &[u8] = b"{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"synthetic\",\"requestObject\":{\"roleRef\":\"synthetic-role\"}}\n{\"eventTime\":\"2026-11-01T00:00:01Z\",\"eventName\":\"second\"}\n";
struct Fixture {
    root: std::path::PathBuf,
    store: Arc<LocalStore>,
    reader: Arc<OriginalReader>,
    engine: Engine<'static>,
    case: CaseId,
    hash: EvidenceHash,
    // Close the reader/database before removing synthetic files on Windows.
    temp: tempfile::TempDir,
}
impl Fixture {
    fn new(copy: bool) -> Self {
        Self::with_decoder(
            copy,
            RAW,
            Arc::new(irmind_mod_parser_json::JsonSourceDecoder),
        )
    }
    fn with_decoder(copy: bool, bytes: &[u8], decoder: Arc<dyn SourceDecoder>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("input");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("events.ndjson"), bytes).unwrap();
        let catalog = mapping_catalog(decoder);
        let store = Arc::new(
            LocalStore::open_mapped(&temp.path().join("data"), Arc::clone(&catalog)).unwrap(),
        );
        let reader = Arc::new(OriginalReader {
            store: Arc::clone(&store),
            authority: Mutex::new(Authority::default()),
            busy: Arc::new(AtomicBool::new(false)),
        });
        let signer = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[88; 32]),
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
                Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
            )
            .with_source_evidence_reader(reader.clone()),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )
        .unwrap();
        let case = engine
            .create_case("Synthetic original read", "local only")
            .unwrap()
            .id;
        let parser = catalog
            .decoder_selection("parser-json", "json-source-v1")
            .unwrap();
        let selection = ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-source-v1".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            cluster_context: None,
            format_sample_sha256: irmind_app::sha256(bytes),
        };
        let rows = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &parser,
        }
        .ingest_local_batch_selected(
            &case,
            &root,
            &["events.ndjson".into()],
            copy,
            &std::collections::BTreeMap::from([("events.ndjson".into(), selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
        Self {
            temp,
            root,
            store,
            reader,
            engine,
            case,
            hash: rows[0].1.clone(),
        }
    }
    fn read(&self, index: u64) -> Result<Tainted<SourceRecordV1>, AppError> {
        self.reader
            .read_verified_record(&self.case, &self.hash, index, &CancellationToken::new())
    }
}
fn fields(record: &Tainted<SourceRecordV1>) -> String {
    let mut output = String::new();
    record.inspect(|r| {
        output = irmind_app::source_mapping::json::render_source_fields(r.fields()).unwrap();
    });
    output
}
#[test]
fn original_read_reproduces_fields_provenance_and_leaves_no_spool() {
    let f = Fixture::new(false);
    let entries = walk(f.temp.path());
    let raw = f.read(0).unwrap();
    assert!(fields(&raw).contains("roleRef"));
    assert_eq!(raw.provenance().record_index(), Some(0));
    assert_eq!(raw.provenance().evidence_hash(), &irmind_app::sha256(RAW));
    assert!(fields(&f.read(1).unwrap()).contains("second"));
    assert_eq!(walk(f.temp.path()), entries);
}
fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut entries = Vec::new();
    for item in std::fs::read_dir(root).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            entries.extend(walk(&path));
        } else {
            entries.push(path);
        }
    }
    entries.sort();
    entries
}
#[test]
fn a_new_session_has_no_root_authority_and_a_case_switch_revokes_it() {
    let f = Fixture::new(false);
    let fresh = f.store.source_evidence_reader();
    assert!(
        fresh
            .read_verified_record(&f.case, &f.hash, 0, &CancellationToken::new())
            .is_err()
    );
    fresh
        .authorize_local_root(&f.case, &f.root, std::slice::from_ref(&f.hash))
        .unwrap();
    assert!(
        fresh
            .read_verified_record(&f.case, &f.hash, 0, &CancellationToken::new())
            .is_ok()
    );
    let other = f
        .engine
        .create_case("Other synthetic case", "local only")
        .unwrap();
    f.reader
        .authorize_local_root(&other.id, Path::new(""), &[])
        .unwrap();
    assert!(f.read(0).is_err());
    assert!(
        f.reader
            .authorize_local_root(&other.id, &f.root, std::slice::from_ref(&f.hash))
            .is_err()
    );
    f.reader
        .authorize_local_root(&f.case, &f.root, std::slice::from_ref(&f.hash))
        .unwrap();
    assert!(f.read(0).is_ok());
}
#[test]
fn a_private_case_copy_needs_no_external_root() {
    let f = Fixture::new(true);
    std::fs::remove_dir_all(&f.root).unwrap();
    let reader = f.store.source_evidence_reader();
    assert!(
        fields(
            &reader
                .read_verified_record(&f.case, &f.hash, 0, &CancellationToken::new())
                .unwrap()
        )
        .contains("roleRef")
    );
}
#[test]
fn changed_sources_unknown_pointers_and_cancelled_reads_never_return_a_record() {
    let f = Fixture::new(false);
    assert!(f.read(2).is_err());
    assert!(f.read(100_000).is_err());
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        f.reader
            .read_verified_record(&f.case, &f.hash, 0, &cancelled),
        Err(AppError::Cancelled)
    ));
    let mut changed = RAW.to_vec();
    let n = changed.iter().position(|b| *b == b'r').unwrap();
    changed[n] = b'R';
    std::fs::write(f.root.join("events.ndjson"), changed).unwrap();
    assert!(matches!(f.read(0), Err(AppError::EvidenceMismatch(_))));
    let unknown = EvidenceHash::from_bytes([9; 32]);
    assert!(
        f.reader
            .read_verified_record(&f.case, &unknown, 0, &CancellationToken::new())
            .is_err()
    );
}
#[cfg(unix)]
#[test]
fn replacing_an_authorized_source_with_a_symlink_is_rejected() {
    let f = Fixture::new(false);
    let outside = f.temp.path().join("outside.ndjson");
    std::fs::write(&outside, RAW).unwrap();
    std::fs::remove_file(f.root.join("events.ndjson")).unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join("events.ndjson")).unwrap();
    assert!(f.read(0).is_err());
    let alias = f.temp.path().join("root-alias");
    std::os::unix::fs::symlink(&f.root, &alias).unwrap();
    assert!(
        f.reader
            .authorize_local_root(&f.case, &alias, std::slice::from_ref(&f.hash))
            .is_err()
    );
}

#[test]
fn an_object_uri_is_not_a_local_root_capability_or_a_network_request() {
    use irmind_app::AuditLog as _;
    let f = Fixture::new(false);
    let entry = f
        .store
        .entries(&f.case)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .unwrap();
    let mut manifest = irmind_domain::SourceManifestV2::decode(&entry.payload).unwrap();
    let job = replay::ReadJob {
        store: f.store.clone(),
        case: f.case.clone(),
        hash: f.hash.clone(),
        index: 0,
        root: Some(f.root.clone()),
        cancel: CancellationToken::new(),
    };
    for source in [
        "s3://synthetic-bucket/events.ndjson",
        "gs://synthetic-bucket/events.ndjson",
        "azure://synthetic-container/events.ndjson",
        "../outside.ndjson",
        "/outside.ndjson",
    ] {
        manifest.source.source = source.into();
        assert!(job.open(&manifest).is_err());
    }
}

fn mapping_catalog(decoder: Arc<dyn SourceDecoder>) -> Arc<MappingCatalog> {
    Arc::new(
        MappingCatalog::freeze(
            vec![decoder],
            vec![Arc::new(
                irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    )
}

#[test]
fn completed_reads_release_the_worker_slot_before_returning_the_record() {
    let f = Fixture::new(false);
    for _ in 0..32 {
        assert!(fields(&f.read(0).unwrap()).contains("roleRef"));
    }
}
