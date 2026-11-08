//! A fully synthetic V6 package is a byte golden and an export fuzz seed.
use super::*;
use irmind_app::source_mapping::MappingCatalog;
use irmind_domain::SourceManifestV2;
use serde::Serialize;
use std::io::Write;
const ID: &str = "11111111-1111-1111-1111-111111111111";
const TITLE: &str = "Synthetic mapped V6 fixture";

fn append(
    entries: &mut Vec<SignedEntry>,
    signer: &LocalSigner,
    kind: AuditEventKind,
    payload: String,
) {
    let mut entry = SignedEntry {
        seq: entries.len() as u64 + 1,
        case_id: ID.into(),
        at: 0,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind,
        payload,
        evidence: None,
        prev: entries.last().map_or([0; 32], |e| e.hash),
        hash: [0; 32],
        sig: vec![],
        public_key: signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = signer.sign(&entry.hash).unwrap();
    entries.push(entry);
}
#[derive(Serialize)]
struct Header {
    version: u32,
    case_id: String,
    title: String,
    severity: String,
    scope: String,
    seal: irmind_app::CaseSeal,
}
#[derive(Serialize)]
struct Frame<'a> {
    path: &'a str,
    sha256: &'a str,
    size: u64,
}
fn frame(out: &mut Vec<u8>, value: &impl Serialize) {
    let bytes = serde_json::to_vec(value).unwrap();
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(&bytes);
}
fn source(
    root: &std::path::Path,
) -> (
    crate::ParquetStore,
    SourceManifestV2,
    irmind_app::source_mapping::BoundMappingSource,
) {
    fs::write(
        root.join("synthetic.json"),
        br#"{"source_ip":"203.0.113.77"}"#,
    )
    .unwrap();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
            vec![],
        )
        .unwrap(),
    );
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let store = crate::ParquetStore::open_mapped(root, catalog).unwrap();
    let id = CaseId::parse(ID).unwrap();
    let prepared = store
        .prepare_local_batch(
            irmind_app::LocalBatchRequest {
                case_id: &id,
                source_root: root,
                relative_paths: &["synthetic.json".into()],
                copy_original: false,
                parser: &parser,
                committed_artifacts: &[],
                limits: irmind_app::PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )
        .unwrap()
        .pop()
        .unwrap();
    let mut source = prepared.manifest;
    source.modified_unix_seconds = None;
    let manifest = SourceManifestV2 {
        source,
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let bound = prepared.mapping.unwrap().bind(&manifest).unwrap();
    (store, manifest, bound)
}

fn entries(
    signer: &LocalSigner,
    manifest: &SourceManifestV2,
    bound: &irmind_app::source_mapping::BoundMappingSource,
) -> Vec<SignedEntry> {
    let mut entries = vec![];
    append(
        &mut entries,
        signer,
        AuditEventKind::CaseCreated,
        format!(r#"{{"version":3,"title":"{TITLE}","severity":"medium","scope":"local only"}}"#),
    );
    append(
        &mut entries,
        signer,
        AuditEventKind::SourceManifestV2,
        manifest.encode().unwrap(),
    );
    append(
        &mut entries,
        signer,
        AuditEventKind::SourceRecordSetV1,
        bound.input().encode().unwrap(),
    );
    append(
        &mut entries,
        signer,
        AuditEventKind::MappingProfileV1,
        bound.profile().encode().unwrap(),
    );
    for artifact in bound.artifacts() {
        append(
            &mut entries,
            signer,
            AuditEventKind::ParquetArtifactV3,
            artifact.encode().unwrap(),
        );
    }
    append(
        &mut entries,
        signer,
        AuditEventKind::MappingRunV1,
        bound.receipt().encode().unwrap(),
    );
    let inventory = irmind_app::seal_inventory(&entries, &[]).unwrap().join(",");
    append(&mut entries, signer, AuditEventKind::CaseSealed, inventory);
    entries
}

fn header(signer: &LocalSigner, entries: &[SignedEntry]) -> Header {
    let last = entries.last().unwrap();
    let seal = irmind_app::CaseSeal {
        seq: last.seq,
        hash: last.hash,
        public_key: signer.public_key(),
        sig: signer
            .sign(&seal_challenge(
                &CaseId::parse(ID).unwrap(),
                last.seq,
                &last.hash,
                &last.payload,
            ))
            .unwrap(),
        analyst_key_fingerprint: hex(&sha256(&signer.public_key())),
    };
    Header {
        version: 6,
        case_id: ID.into(),
        title: TITLE.into(),
        severity: "medium".into(),
        scope: "local only".into(),
        seal,
    }
}

fn fixture() -> Vec<u8> {
    let root = tempfile::tempdir().unwrap();
    let (store, manifest, bound) = source(root.path());
    let signer = LocalSigner {
        key: SigningKey::from_bytes(&[43; 32]),
        actor: Actor::Analyst,
    };
    let entries = entries(&signer, &manifest, &bound);
    let header = header(&signer, &entries);
    let id = CaseId::parse(ID).unwrap();
    let mut out = b"IRMIND-EXPORT-V6\0".to_vec();
    frame(&mut out, &header);
    out.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in &entries {
        frame(&mut out, entry);
    }
    out.extend_from_slice(&[0; 24]); // No copied blobs, originals or operational entries.
    out.extend_from_slice(&(bound.artifacts().len() as u64).to_be_bytes());
    for artifact in bound.artifacts() {
        let a = artifact.core();
        frame(
            &mut out,
            &Frame {
                path: &a.path,
                sha256: a.sha256.as_str(),
                size: a.size,
            },
        );
        out.write_all(&fs::read(store.case_dir(&id).unwrap().join(&a.path)).unwrap())
            .unwrap();
    }
    out
}
#[test]
fn synthetic_v6_package_golden_authenticates_without_any_keystore() {
    let actual = fixture();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds/export/valid-v6-mapped.irmind");
    if std::env::var_os("IRMIND_REGENERATE_MAPPED_EXPORT_FIXTURE").is_some() {
        fs::write(&path, &actual).unwrap();
    }
    assert_eq!(fs::read(&path).unwrap(), actual);
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("synthetic.irmind");
    fs::write(&package, &actual).unwrap();
    let expected = hex(&sha256(
        &SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
    ));
    let verified = LocalExportVerifier
        .verify_export_details(&package, Some(&expected))
        .unwrap();
    assert_eq!(
        (
            verified.format_version,
            verified.entries,
            verified.source_manifests
        ),
        (6, 7, 1)
    );
    let mut changed = actual;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    fs::write(&package, changed).unwrap();
    assert!(verify_export(&package).is_err());
}
