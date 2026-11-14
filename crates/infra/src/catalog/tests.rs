use super::*;
use ed25519_dalek::SigningKey;
use irmind_app::catalog::{CatalogIndex, CatalogProofId};
use std::sync::OnceLock;

const INDEX: &[u8] =
    include_bytes!("../../../../docs/development/catalog-format-vectors/index.json");

fn keys() -> &'static [[u8; 32]] {
    static KEYS: OnceLock<[[u8; 32]; 1]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let keys: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../docs/development/catalog-format-vectors/public-keys.json"
        ))
        .unwrap();
        [hex::decode(keys["catalog"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()]
    })
}
fn bytes(index: &[u8]) -> CatalogIndexBytes {
    let signature = hex::decode(
        include_str!("../../../../docs/development/catalog-format-vectors/index-signature.hex")
            .trim(),
    )
    .unwrap();
    CatalogIndexBytes::new(index.into(), &signature).unwrap()
}
fn verified() -> VerifiedCatalogIndex {
    Ed25519CatalogIndexVerifier::from_release_keys(keys())
        .unwrap()
        .verify(&bytes(INDEX), &FrozenCatalogRelease::new("v0.1.0").unwrap())
        .unwrap()
}

#[test]
fn catalog_index_signature_preimage_proof_and_asset_match_approved_vectors() {
    let raw = bytes(INDEX);
    let expected = hex::decode(
        include_str!("../../../../docs/development/catalog-format-vectors/index-preimage.hex")
            .trim(),
    )
    .unwrap();
    assert_eq!(raw.signature_preimage(), expected);
    let identities: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/catalog-format-vectors/identities.json"
    ))
    .unwrap();
    let index = verified();
    let receipt: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/catalog-format-vectors/catalog-receipt.json"
    ))
    .unwrap();
    assert_eq!(
        irmind_app::hex(index.keyset_hash().as_bytes()),
        receipt["keyset_sha256"]
    );
    assert_eq!(
        irmind_app::hex(index.index_hash().as_bytes()),
        identities["index_sha256"]
    );
    assert_eq!(
        index.proof_id(),
        CatalogProofId::parse(identities["proof_sha256"].as_str().unwrap()).unwrap()
    );
    let asset = index.asset("synthetic-triage").unwrap();
    assert_eq!(
        irmind_app::hex(asset.entry().identity().unwrap().as_bytes()),
        receipt["entry_sha256"]
    );
    assert_eq!(
        irmind_app::hex(asset.entry().package_hash().as_bytes()),
        identities["package_sha256"]
    );
    asset
        .check_bytes(include_bytes!(
            "../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
        ))
        .unwrap();
    assert!(
        asset
            .check_bytes(include_bytes!(
                "../../../../docs/development/catalog-format-vectors/changed-asset.json"
            ))
            .is_err()
    );
    assert_eq!(index.release().tag(), "v0.1.0");
    assert_eq!(index.release().index_hash(), asset.index_hash());
}

#[test]
fn catalog_has_no_production_test_key_or_unverified_alternate_trust_path() {
    let production = Ed25519CatalogIndexVerifier::production().unwrap();
    assert!(!production.available());
    let release = FrozenCatalogRelease::new("v0.1.0").unwrap();
    assert!(
        production
            .verify(&bytes(INDEX), &release)
            .err()
            .unwrap()
            .to_string()
            .contains("no compiled")
    );
    let verifier = Ed25519CatalogIndexVerifier::from_release_keys(keys()).unwrap();
    assert!(
        verifier
            .verify(
                &bytes(include_bytes!(
                    "../../../../docs/development/catalog-format-vectors/changed-index.json"
                )),
                &release
            )
            .is_err()
    );
    assert!(
        verifier
            .verify(&bytes(INDEX), &FrozenCatalogRelease::new("v0.1.1").unwrap())
            .is_err()
    );
    let mut changed = bytes(INDEX);
    let mut signature = *changed.signature();
    signature[0] ^= 1;
    changed = CatalogIndexBytes::new(changed.index().into(), &signature).unwrap();
    assert!(verifier.verify(&changed, &release).is_err());
    assert!(
        CatalogIndex::decode_untrusted(include_bytes!(
            "../../../../docs/development/catalog-format-vectors/duplicate-field.json"
        ))
        .is_err()
    );
}

#[test]
fn catalog_key_and_signature_bounds_fail_before_admission() {
    static WEAK: [[u8; 32]; 1] = [[0; 32]];
    static DUPLICATE: OnceLock<[[u8; 32]; 2]> = OnceLock::new();
    assert!(Ed25519CatalogIndexVerifier::from_release_keys(&WEAK).is_err());
    let duplicates = DUPLICATE.get_or_init(|| [keys()[0], keys()[0]]);
    assert!(Ed25519CatalogIndexVerifier::from_release_keys(duplicates).is_err());
    assert!(CatalogIndexBytes::new(INDEX.into(), &[0; 63]).is_err());
    assert!(CatalogIndexBytes::new(vec![0; 1024 * 1024 + 1], &[0; 64]).is_err());
}

#[test]
fn catalog_key_rotation_preserves_accepted_signers_and_rejects_removed_signers() {
    static EXTENDED: OnceLock<[[u8; 32]; 2]> = OnceLock::new();
    static REPLACED: OnceLock<[[u8; 32]; 1]> = OnceLock::new();
    let replacement = SigningKey::from_bytes(&[112; 32])
        .verifying_key()
        .to_bytes();
    let extended = EXTENDED.get_or_init(|| [replacement, keys()[0]]);
    let replaced = REPLACED.get_or_init(|| [replacement]);
    let release = FrozenCatalogRelease::new("v0.1.0").unwrap();
    let admitted = Ed25519CatalogIndexVerifier::from_release_keys(extended)
        .unwrap()
        .verify(&bytes(INDEX), &release)
        .unwrap();
    assert_eq!(admitted.proof_id(), verified().proof_id());
    assert_ne!(admitted.keyset_hash(), verified().keyset_hash());
    assert!(
        Ed25519CatalogIndexVerifier::from_release_keys(replaced)
            .unwrap()
            .verify(&bytes(INDEX), &release)
            .is_err()
    );
}

#[test]
fn catalog_asset_uses_existing_compiler_and_checks_version_and_both_commitments() {
    use irmind_app::catalog::BoundedPackageBytes;
    let verified = verified();
    let asset = verified.asset("synthetic-triage").unwrap();
    let raw = BoundedPackageBytes::new(
        include_bytes!(
            "../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
        )
        .to_vec(),
    )
    .unwrap();
    let compiled = asset
        .compile(&raw, "0.5.0", &crate::TomlSkillCompiler)
        .unwrap();
    assert_eq!(compiled.metadata().name().as_str(), "synthetic-triage");
    assert_eq!(
        compiled.package().hash().as_bytes(),
        asset.entry().package_hash().as_bytes()
    );
    assert!(
        asset
            .compile(&raw, "0.4.2", &crate::TomlSkillCompiler)
            .is_err()
    );
    let bad = BoundedPackageBytes::new(vec![b'{', b'}']).unwrap();
    assert!(
        asset
            .compile(&bad, "0.5.0", &crate::TomlSkillCompiler)
            .is_err()
    );
}
