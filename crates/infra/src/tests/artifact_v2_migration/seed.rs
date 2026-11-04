use super::archive::frame;
use super::*;
use irmind_domain::{
    EvidenceHash, ParquetArtifactV2, ParserSelectionMode, SourceManifestV1, SourceManifestV2,
};
const DATA: &[u8] = b"synthetic-derived-fixture";
const ID: &str = "11111111-1111-1111-1111-111111111111";
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
        sig: Vec::new(),
        public_key: signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = signer.sign(&entry.hash).unwrap();
    entries.push(entry);
}
fn metadata(signer: &LocalSigner) -> (Vec<SignedEntry>, ParquetArtifactV2) {
    let mut entries = Vec::new();
    append(&mut entries,signer,AuditEventKind::CaseCreated,r#"{"version":3,"title":"V5 synthetic inventory","severity":"medium","scope":"local only"}"#.into());
    let source = SourceManifestV2 {
        source: SourceManifestV1 {
            source: "synthetic.json".into(),
            sha256: EvidenceHash::from_bytes(sha256(b"{}")),
            size: 2,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            copied: false,
        },
        parser_id: "parser-json".into(),
        parser_version: "json-stream-v2".into(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: Vec::new(),
    };
    let mut artifact = ParquetArtifactV2::decode(
        include_str!("../../../../domain/tests/fixtures/parquet-artifact-v2.hex").trim(),
    )
    .unwrap();
    artifact.builder_version = "parquet-builder-v3".into();
    artifact.source_hashes = vec![source.source.sha256.clone()];
    artifact.sha256 = EvidenceHash::from_bytes(sha256(DATA));
    artifact.size = DATA.len() as u64;
    append(
        &mut entries,
        signer,
        AuditEventKind::SourceManifestV2,
        source.encode().unwrap(),
    );
    append(
        &mut entries,
        signer,
        AuditEventKind::ParquetArtifactV2,
        artifact.encode().unwrap(),
    );
    let payload = irmind_app::seal_inventory(&entries, &[]).unwrap().join(",");
    append(&mut entries, signer, AuditEventKind::CaseSealed, payload);
    (entries, artifact)
}
fn synthetic_seed() -> Vec<u8> {
    let signer = LocalSigner {
        key: SigningKey::from_bytes(&[43; 32]),
        actor: Actor::Analyst,
    };
    let (entries, artifact) = metadata(&signer);
    let last = entries.last().unwrap();
    let id = CaseId::parse(ID).unwrap();
    let seal = irmind_app::CaseSeal {
        seq: last.seq,
        hash: last.hash,
        public_key: signer.public_key(),
        sig: signer
            .sign(&seal_challenge(&id, last.seq, &last.hash, &last.payload))
            .unwrap(),
        analyst_key_fingerprint: hex(&sha256(&signer.public_key())),
    };
    let mut header = serde_json::json!({"version":5,"case_id":ID,"title":"V5 synthetic inventory","severity":"medium","scope":"local only","seal":seal});
    header.sort_all_objects();
    let mut bytes = b"IRMIND-EXPORT-V5\0".to_vec();
    frame(&mut bytes, &header);
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in &entries {
        frame(&mut bytes, entry);
    }
    bytes.extend_from_slice(&[0; 24]);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    let mut file = serde_json::json!({"path":artifact.path,"sha256":artifact.sha256.as_str(),"size":artifact.size});
    file.sort_all_objects();
    frame(&mut bytes, &file);
    bytes.extend_from_slice(DATA);
    bytes
}
#[test]
fn synthetic_v5_inventory_fuzz_seed_verifies_all_bytes_without_private_environment_data() {
    let bytes = synthetic_seed();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds/export/valid-v5-inventory.irmind");
    if std::env::var_os("IRMIND_REGENERATE_SYNTHETIC_FUZZ_SEED").is_some() {
        fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("synthetic.irmind");
    fs::write(&package, bytes).unwrap();
    assert_eq!(verify_export(&package).unwrap().1, 4);
}
