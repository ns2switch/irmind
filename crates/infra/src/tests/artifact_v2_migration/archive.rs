use super::*;
use serde::Serialize;
use std::io::{Cursor, Read};
fn u64_read(input: &mut Cursor<&[u8]>) -> u64 {
    let mut b = [0; 8];
    input.read_exact(&mut b).unwrap();
    u64::from_be_bytes(b)
}
fn json_read(input: &mut Cursor<&[u8]>) -> serde_json::Value {
    let size = u64_read(input);
    let mut bytes = vec![0; usize::try_from(size).unwrap()];
    input.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
pub(super) fn frame(out: &mut Vec<u8>, value: &impl Serialize) {
    let bytes = serde_json::to_vec(value).unwrap();
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend(bytes);
}
fn resign_inventory(
    bytes: &[u8],
    change: impl FnOnce(&mut irmind_domain::SealInventoryV2),
) -> Vec<u8> {
    let mut input = Cursor::new(bytes);
    input.set_position(b"IRMIND-EXPORT-V5\0".len() as u64);
    let mut header = json_read(&mut input);
    let count = u64_read(&mut input);
    let mut entries = (0..count)
        .map(|_| serde_json::from_value::<SignedEntry>(json_read(&mut input)).unwrap())
        .collect::<Vec<_>>();
    let signer = LocalSigner {
        key: SigningKey::from_bytes(&[43; 32]),
        actor: Actor::Analyst,
    };
    let sealed = entries.last_mut().unwrap();
    let mut root = irmind_domain::SealInventoryV2::decode(&sealed.payload).unwrap();
    change(&mut root);
    sealed.payload = root.encode().unwrap();
    sealed.hash = sha256(&sealed.canonical());
    sealed.sig = signer.sign(&sealed.hash).unwrap();
    let id = CaseId::parse(&sealed.case_id).unwrap();
    let mut seal: irmind_app::CaseSeal = serde_json::from_value(header["seal"].clone()).unwrap();
    seal.hash = sealed.hash;
    seal.sig = signer
        .sign(&seal_challenge(
            &id,
            sealed.seq,
            &sealed.hash,
            &sealed.payload,
        ))
        .unwrap();
    header["seal"] = serde_json::to_value(seal).unwrap();
    let mut out = b"IRMIND-EXPORT-V5\0".to_vec();
    frame(&mut out, &header);
    out.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        frame(&mut out, &entry);
    }
    out.extend_from_slice(&bytes[usize::try_from(input.position()).unwrap()..]);
    out
}
fn artifact_ranges(bytes: &[u8]) -> (usize, Vec<std::ops::Range<usize>>) {
    let mut input = Cursor::new(bytes);
    input.set_position(b"IRMIND-EXPORT-V5\0".len() as u64);
    json_read(&mut input);
    let count = u64_read(&mut input);
    for _ in 0..count {
        json_read(&mut input);
    }
    assert_eq!(u64_read(&mut input), 0); // legacy blobs
    assert_eq!(u64_read(&mut input), 0); // originals omitted
    let operations = u64_read(&mut input);
    for _ in 0..operations {
        json_read(&mut input);
    }
    let section = usize::try_from(input.position()).unwrap();
    let count = u64_read(&mut input);
    let mut ranges = Vec::new();
    for _ in 0..count {
        let start = usize::try_from(input.position()).unwrap();
        let metadata = json_read(&mut input);
        let size = metadata["size"].as_u64().unwrap();
        input.set_position(input.position() + size);
        ranges.push(start..usize::try_from(input.position()).unwrap());
    }
    assert_eq!(usize::try_from(input.position()).unwrap(), bytes.len());
    (section, ranges)
}
#[test]
fn v5_recomputes_even_a_resigned_commitment_and_checks_all_derived_file_frames() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let id = engine.create_case("V5 integrity", "local only").unwrap().id;
    ingest(&store, &engine, &id, root.path(), true);
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    }
    .migrate_artifacts_v2(&id, None, &CancellationToken::new())
    .unwrap();
    engine.seal(&id).unwrap();
    let path = root.path().join("case.irmind");
    irmind_app::export_case_v6(
        &engine,
        store.as_ref(),
        &id,
        &path,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let bytes = fs::read(&path).unwrap();
    let invalid = [
        resign_inventory(&bytes, |r| r.count += 1),
        resign_inventory(&bytes, |r| {
            r.sha256 = irmind_domain::EvidenceHash::from_bytes([0; 32]);
        }),
    ];
    for changed in invalid {
        fs::write(&path, changed).unwrap();
        assert!(verify_export(&path).is_err());
    }
    let (section, ranges) = artifact_ranges(&bytes);
    assert_eq!(ranges.len(), 6);
    let mut changed = bytes.clone();
    changed[ranges[0].end - 1] ^= 1;
    fs::write(&path, changed).unwrap();
    assert!(matches!(
        verify_export(&path),
        Err(AppError::EvidenceMismatch(_))
    ));
    let mut reordered = bytes[..section + 8].to_vec();
    reordered.extend_from_slice(&bytes[ranges[1].clone()]);
    reordered.extend_from_slice(&bytes[ranges[0].clone()]);
    for range in &ranges[2..] {
        reordered.extend_from_slice(&bytes[range.clone()]);
    }
    fs::write(&path, reordered).unwrap();
    assert!(verify_export(&path).is_err());
    fs::write(&path, &bytes[..section]).unwrap();
    assert!(verify_export(&path).is_err());
    let mut removed = bytes.clone();
    removed.drain(ranges[0].clone());
    fs::write(&path, removed).unwrap();
    assert!(verify_export(&path).is_err());
    let mut added = bytes.clone();
    added.extend_from_slice(&bytes[ranges[0].clone()]);
    fs::write(&path, added).unwrap();
    assert!(verify_export(&path).is_err());
}
