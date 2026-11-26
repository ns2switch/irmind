use super::*;
use ed25519_dalek::SigningKey;
use irmind_app::catalog::{CatalogIndex, CatalogProofId};
use std::sync::OnceLock;
mod case;
mod frames;

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
    assert!(production.available());
    assert_eq!(RELEASE_CATALOG_KEYS.len(), 1);
    assert_eq!(
        hex::encode(RELEASE_CATALOG_KEYS[0]),
        "fb2015c83d13fe018e270a7fe73bf7bccfdb622565e30f7ade436637c3b2c25b"
    );
    assert_eq!(
        irmind_app::hex(&irmind_app::sha256(&RELEASE_CATALOG_KEYS[0])),
        "f04daae3f8243ed76452d5f787ea527c8fbec895ca0c91a35f453f6677575e4f"
    );
    let public = VerifyingKey::from_bytes(&RELEASE_CATALOG_KEYS[0]).unwrap();
    assert!(!public.is_weak());
    assert!(!RELEASE_CATALOG_KEYS.contains(&keys()[0]));
    for seed in [42, 43, 44, 73, 74, 88, 90] {
        let synthetic = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        assert!(!RELEASE_CATALOG_KEYS.contains(&synthetic));
    }
    // Even a valid index signed by the documented fixture key is not trusted.
    let release = FrozenCatalogRelease::new("v0.1.0").unwrap();
    assert!(
        production
            .verify(&bytes(INDEX), &release)
            .err()
            .unwrap()
            .to_string()
            .contains("catalog")
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
    let receipt =
        irmind_app::catalog::CatalogReceipt::new(&verified(), "synthetic-triage", false, false)
            .unwrap();
    let package = irmind_app::catalog::BoundedPackageBytes::new(
        include_bytes!(
            "../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
        )
        .to_vec(),
    )
    .unwrap();
    let skill = admitted
        .asset("synthetic-triage")
        .unwrap()
        .compile(&package, "0.5.0", &crate::TomlSkillCompiler)
        .unwrap();
    receipt.check(&admitted, &skill).unwrap();
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

#[test]
fn catalog_receipt_binds_the_whole_index_entry_asset_and_logical_package() {
    use irmind_app::catalog::{BoundedPackageBytes, CatalogReceipt};
    let index = verified();
    let receipt = CatalogReceipt::new(&index, "synthetic-triage", true, false).unwrap();
    assert_eq!(
        receipt.canonical().unwrap(),
        include_bytes!("../../../../docs/development/catalog-format-vectors/catalog-receipt.json")
    );
    let raw = BoundedPackageBytes::new(
        include_bytes!(
            "../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
        )
        .to_vec(),
    )
    .unwrap();
    let skill = index
        .asset("synthetic-triage")
        .unwrap()
        .compile(&raw, "0.5.0", &crate::TomlSkillCompiler)
        .unwrap();
    receipt.check(&index, &skill).unwrap();
    let source = std::str::from_utf8(&receipt.canonical().unwrap())
        .unwrap()
        .to_owned();
    for changed in [
        source.replace("v0.1.0", "v0.1.1"),
        source.replace("\"release_sequence\":1", "\"release_sequence\":2"),
        source.replace("\"asset_bytes\":403", "\"asset_bytes\":404"),
        source.replace("synthetic-triage-1.skill.json", "different.skill.json"),
        source.replace(
            "df8cd53705dceb000ff823863f45549a8e9b3650f901567aad806d92f4ba0970",
            &"a".repeat(64),
        ),
    ] {
        assert!(
            CatalogReceipt::decode(changed.as_bytes())
                .unwrap()
                .check(&index, &skill)
                .is_err()
        );
    }
}

#[test]
fn catalog_admission_requires_publisher_proof_beyond_a_valid_analyst_signature() {
    use irmind_app::{SignedEntry, SignedOperation, SkillReceiptVerifier, Verifier};
    let snapshot: SignedEntry = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/catalog-format-vectors/signed-snapshot.json"
    ))
    .unwrap();
    let admission: SignedOperation = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/catalog-format-vectors/signed-installation.json"
    ))
    .unwrap();
    let verifier = crate::LocalVerifier {
        trusted: std::collections::BTreeMap::new(),
    }
    .with_trusted_key(&irmind_domain::Actor::Analyst, &admission.public_key)
    .unwrap();
    assert_eq!(snapshot.hash, irmind_app::sha256(&snapshot.canonical()));
    verifier
        .verify(&snapshot.public_key, &snapshot.hash, &snapshot.sig)
        .unwrap();
    let mut checked = SkillReceiptVerifier::default();
    checked
        .accept(&snapshot, &crate::TomlSkillCompiler)
        .unwrap();
    let proofs = [admission];
    let analyst = proofs[0].public_key.clone();
    assert!(
        checked
            .verify_admissions(&proofs, &verifier, &analyst)
            .is_err()
    );
    let requirements = checked
        .catalog_requirements(&proofs, &verifier, &analyst)
        .unwrap();
    assert_eq!(requirements.len(), 1);
    assert_eq!(requirements[0].proof(), verified().proof_id());
    assert_eq!(requirements[0].release().tag(), "v0.1.0");
    checked
        .verify_catalog_admissions(
            &proofs,
            &[verified()],
            &verifier,
            &analyst,
            &crate::TomlSkillCompiler,
        )
        .unwrap();
    checked
        .verify_admissions(&proofs, &verifier, &analyst)
        .unwrap();
    assert!(
        checked
            .verify_catalog_admissions(&proofs, &[], &verifier, &analyst, &crate::TomlSkillCompiler)
            .is_err()
    );
    assert!(
        checked
            .verify_admissions(&proofs, &verifier, &analyst)
            .is_err()
    );
    assert!(
        SkillReceiptVerifier::default()
            .verify_catalog_admissions(
                &[],
                &[verified()],
                &verifier,
                &analyst,
                &crate::TomlSkillCompiler
            )
            .is_err()
    );
}

#[cfg(feature = "sigma")]
#[test]
fn approved_sigma_catalog_vector_authenticates_in_its_own_domain() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/development/sigma-package-vectors/wire.json"
    ))
    .unwrap();
    let read = |name: &str| hex::decode(vectors[name].as_str().unwrap()).unwrap();
    let body = |name: &str| hex::decode(vectors[name]["bytes_hex"].as_str().unwrap()).unwrap();
    let key: [u8; 32] = read("publisher_public_key").try_into().unwrap();
    let verifier =
        Ed25519CatalogIndexVerifier::from_release_keys(Box::leak(Box::new([key]))).unwrap();
    let index = body("index");
    let signature = read("sigma_index_signature");
    let authenticated = verifier.verify_sigma(&index, &signature, "v1.0.0").unwrap();
    assert_eq!(authenticated.proof(), body("v10_object_7"));
    let proof = authenticated.proof();
    let digest = irmind_app::sha256(proof);
    let reopened = verifier
        .verify_sigma_proof(proof, digest, "v1.0.0")
        .unwrap();
    assert!(
        reopened
            .check_release_history([authenticated.release_stamp()])
            .is_ok()
    );
    assert!(
        verifier
            .verify_sigma_proof(proof, [0; 32], "v1.0.0")
            .is_err()
    );
    let mut changed_proof = proof.to_vec();
    changed_proof.push(0);
    assert!(
        verifier
            .verify_sigma_proof(&changed_proof, irmind_app::sha256(&changed_proof), "v1.0.0")
            .is_err()
    );

    assert_eq!(authenticated.sequence(), 1);
    let package = body("package");
    let cancel = irmind_app::CancellationToken::new();
    let bundle = crate::sigma_pack::inspect_sigma_catalog_asset(
        &authenticated,
        "synthetic",
        &package,
        &cancel,
    )
    .unwrap();
    assert_eq!(bundle.pack.rules.len(), 1);
    let mut wrong = package;
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        crate::sigma_pack::inspect_sigma_catalog_asset(
            &authenticated,
            "synthetic",
            &wrong,
            &cancel
        )
        .is_err()
    );

    assert!(verifier.verify_sigma(&index, &signature, "v1.0.1").is_err());
    assert!(matches!(
        verifier.verify_sigma(
            &body("skills_index"),
            &read("skills_index_signature"),
            "v1.0.0"
        ),
        Err(CatalogError::InvalidSignature)
    ));
    let raw = CatalogIndexBytes::new(index, &signature).unwrap();
    assert!(
        verifier
            .verify(&raw, &FrozenCatalogRelease::new("v1.0.0").unwrap())
            .is_err()
    );
}

#[cfg(feature = "sigma")]
#[test]
fn approved_sigma_installation_proof_checks_the_analyst_and_operation_digest() {
    use irmind_app::v10_proofs::verify_sigma_installation_proof;
    use irmind_domain::Actor;

    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/development/sigma-package-vectors/wire.json"
    ))
    .unwrap();
    let raw = hex::decode(vectors["v10_object_6"]["bytes_hex"].as_str().unwrap()).unwrap();
    let entry: irmind_app::SignedOperation = serde_json::from_slice(&raw).unwrap();
    let verifier = crate::LocalVerifier {
        trusted: std::collections::BTreeMap::new(),
    }
    .with_trusted_key(&Actor::Analyst, &entry.public_key)
    .unwrap();
    let receipt = verify_sigma_installation_proof(&raw, entry.hash, &verifier).unwrap();
    assert_eq!(receipt.name, "synthetic");
    assert!(verify_sigma_installation_proof(&raw, [0; 32], &verifier).is_err());
    let mut altered = entry.clone();
    altered.sig[0] ^= 1;
    assert!(
        verify_sigma_installation_proof(
            &serde_json::to_vec(&altered).unwrap(),
            entry.hash,
            &verifier
        )
        .is_err()
    );
}

#[cfg(feature = "sigma")]
#[expect(
    clippy::too_many_lines,
    reason = "covers an authenticated pair and invalid pair variants"
)]
#[test]
fn approved_sigma_case_admission_binds_the_following_run() {
    use irmind_app::{
        Verifier,
        v10_proofs::{CaseCheckpointV1, SigmaCaseRunAdmissionV1, SigmaRunStatusV1, SigmaRunV1},
    };
    use irmind_domain::Actor;

    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/development/sigma-package-vectors/wire.json"
    ))
    .unwrap();
    let raw = hex::decode(
        vectors["signed_case_admission"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let entry: irmind_app::SignedEntry = serde_json::from_slice(&raw).unwrap();
    let key = crate::LocalVerifier {
        trusted: std::collections::BTreeMap::new(),
    }
    .with_trusted_key(&Actor::Analyst, &entry.public_key)
    .unwrap();
    assert_eq!(
        irmind_app::hex(&entry.canonical()),
        vectors["case_admission_signing_preimage"]["bytes_hex"]
    );
    assert_eq!(irmind_app::sha256(&entry.canonical()), entry.hash);
    key.verify(&entry.public_key, &entry.hash, &entry.sig)
        .unwrap();
    let admission = SigmaCaseRunAdmissionV1::from_case_entry(&entry).unwrap();
    let mut run = SigmaRunV1 {
        checkpoint: CaseCheckpointV1 {
            case_id: admission.checkpoint.case_id.clone(),
            sequence: entry.seq,
            entry_hash: entry.hash,
        },
        pack_admission: admission.pack_admission,
        artifact_inventory: admission.artifact_inventory,
        selected_sources: admission.selected_sources,
        start_utc_micros: admission.start_us,
        end_utc_micros: admission.end_us,
        compiled_rules: admission.compiled_rules,
        field_table: admission.field_table,
        evaluator: admission.evaluator.clone(),
        reserved_units: admission.reserved_work,
        used_units: 1,
        status: SigmaRunStatusV1::Complete,
        matched_rows: 0,
        result_manifest: [97; 32],
        proof_set: [98; 32],
    };
    assert!(
        SigmaCaseRunAdmissionV1::verify_following_run(&entry, &run, admission.manifest).is_ok()
    );
    let mut following = entry.clone();
    following.seq += 1;
    following.kind = irmind_domain::AuditEventKind::SigmaRunV1;
    following.prev = entry.hash;
    following.payload = run.encode().unwrap();
    assert!(
        irmind_app::v10_proofs::verify_sigma_case_admission_pairs(&[
            entry.clone(),
            following.clone()
        ])
        .is_ok()
    );
    assert!(
        irmind_app::v10_proofs::verify_sigma_case_admission_pairs(std::slice::from_ref(&following))
            .is_err()
    );
    assert!(
        irmind_app::v10_proofs::verify_sigma_case_admission_pairs(std::slice::from_ref(&entry))
            .is_err()
    );
    let mut downgraded = following;
    let mut ungated = run.clone();
    ungated.evaluator = irmind_app::v10_proofs::SIGMA_EVALUATOR_V3.into();
    downgraded.payload = ungated.encode().unwrap();
    assert!(
        irmind_app::v10_proofs::verify_sigma_case_admission_pairs(&[entry.clone(), downgraded])
            .is_err()
    );
    assert!(SigmaCaseRunAdmissionV1::verify_following_run(&entry, &run, [0; 32]).is_err());
    run.selected_sources[0] ^= 1;
    assert!(
        SigmaCaseRunAdmissionV1::verify_following_run(&entry, &run, admission.manifest).is_err()
    );
}

#[cfg(feature = "sigma")]
#[test]
fn approved_v4_gate_vectors_round_trip_and_reject_ungated_run() {
    use irmind_app::{
        Verifier,
        v10_proofs::{SIGMA_EVALUATOR_V4_CASE_ADMISSION, SigmaCaseRunAdmissionV1, SigmaRunV1},
    };
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/development/sigma-package-vectors/v4-gate.json"
    ))
    .unwrap();
    let raw = |key: &str| hex::decode(vectors[key]["bytes_hex"].as_str().unwrap()).unwrap();
    let entry: irmind_app::SignedEntry = serde_json::from_slice(&raw("signed_admission")).unwrap();
    let verifier = crate::LocalVerifier {
        trusted: std::collections::BTreeMap::new(),
    }
    .with_trusted_key(&irmind_domain::Actor::Analyst, &entry.public_key)
    .unwrap();
    assert_eq!(entry.canonical(), raw("admission_challenge"));
    verifier
        .verify(&entry.public_key, &entry.hash, &entry.sig)
        .unwrap();
    let admit = SigmaCaseRunAdmissionV1::from_case_entry(&entry).unwrap();
    assert_eq!(admit.encode().unwrap(), raw("admission"));
    let run = SigmaRunV1::decode(&irmind_app::hex(&raw("following_run"))).unwrap();
    assert_eq!(run.evaluator, SIGMA_EVALUATOR_V4_CASE_ADMISSION);
    assert_eq!(
        run.encode().unwrap(),
        irmind_app::hex(&raw("following_run"))
    );
    assert!(SigmaCaseRunAdmissionV1::verify_following_run(&entry, &run, admit.manifest).is_ok());
    let ungated = SigmaRunV1::decode(&irmind_app::hex(&raw(
        "invalid_following_run_without_gate_identity",
    )))
    .unwrap();
    assert!(
        SigmaCaseRunAdmissionV1::verify_following_run(&entry, &ungated, admit.manifest).is_err()
    );
}
