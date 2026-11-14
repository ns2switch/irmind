use super::*;
use irmind_app::{
    SignedEntry, SignedOperation, SkillReceiptVerifier,
    catalog::{
        CatalogProofReader, CatalogProofRequirement, catalog_proof_chunk, catalog_proof_descriptor,
    },
};

fn requirement() -> CatalogProofRequirement {
    let snapshot: SignedEntry = serde_json::from_slice(include_bytes!(
        "../../../../../docs/development/catalog-format-vectors/signed-snapshot.json"
    ))
    .unwrap();
    let admission: SignedOperation = serde_json::from_slice(include_bytes!(
        "../../../../../docs/development/catalog-format-vectors/signed-installation.json"
    ))
    .unwrap();
    let mut checked = SkillReceiptVerifier::default();
    checked
        .accept(&snapshot, &crate::TomlSkillCompiler)
        .unwrap();
    checked
        .catalog_requirements(
            std::slice::from_ref(&admission),
            &crate::LocalVerifier {
                trusted: std::collections::BTreeMap::new(),
            },
            &admission.public_key,
        )
        .unwrap()
        .remove(0)
}
#[test]
fn catalog_v8_descriptor_chunk_and_complete_extension_match_approved_vectors() {
    let index = verified();
    let descriptor = catalog_proof_descriptor(&index).unwrap();
    let chunk = catalog_proof_chunk(&index, 0).unwrap();
    assert_eq!(
        descriptor,
        include_bytes!(
            "../../../../../docs/development/catalog-format-vectors/proof-descriptor.json"
        )
    );
    assert_eq!(
        chunk,
        include_bytes!("../../../../../docs/development/catalog-format-vectors/proof-chunk.json")
    );
    let mut tail = 1u64.to_be_bytes().to_vec();
    for frame in [&descriptor, &chunk] {
        tail.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        tail.extend_from_slice(frame);
    }
    tail.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        tail,
        hex::decode(
            include_str!(
                "../../../../../docs/development/catalog-format-vectors/v8-catalog-tail.hex"
            )
            .trim()
        )
        .unwrap()
    );
    let requirement = requirement();
    let mut reader = CatalogProofReader::new(&descriptor, requirement.proof()).unwrap();
    reader.accept(&chunk).unwrap();
    assert_eq!(
        reader
            .finish(
                &requirement,
                &Ed25519CatalogIndexVerifier::from_release_keys(keys()).unwrap()
            )
            .unwrap()
            .proof_id(),
        index.proof_id()
    );
}
#[test]
fn catalog_v8_rejects_missing_extra_changed_and_reordered_chunks_without_recovery() {
    let index = verified();
    let descriptor = catalog_proof_descriptor(&index).unwrap();
    let chunk = catalog_proof_chunk(&index, 0).unwrap();
    let requirement = requirement();
    let verifier = Ed25519CatalogIndexVerifier::from_release_keys(keys()).unwrap();
    assert!(
        CatalogProofReader::new(&descriptor, requirement.proof())
            .unwrap()
            .finish(&requirement, &verifier)
            .is_err()
    );
    let changed = std::str::from_utf8(&chunk)
        .unwrap()
        .replace("\"ordinal\":0", "\"ordinal\":1");
    let mut reader = CatalogProofReader::new(&descriptor, requirement.proof()).unwrap();
    assert!(reader.accept(changed.as_bytes()).is_err());
    assert!(reader.accept(&chunk).is_err());
    assert!(reader.finish(&requirement, &verifier).is_err());
    let mut reader = CatalogProofReader::new(&descriptor, requirement.proof()).unwrap();
    reader.accept(&chunk).unwrap();
    assert!(reader.accept(&chunk).is_err());
    assert!(reader.finish(&requirement, &verifier).is_err());
    let mut reader = CatalogProofReader::new(&descriptor, requirement.proof()).unwrap();
    let changed = std::str::from_utf8(&chunk).unwrap().replacen(
        "\"bytes_hex\":\"7b",
        "\"bytes_hex\":\"7a",
        1,
    );
    assert_ne!(changed.as_bytes(), chunk);
    reader.accept(changed.as_bytes()).unwrap();
    assert!(reader.finish(&requirement, &verifier).is_err());
}
