#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{CaseSeal, SignedEntry, hex, seal_challenge, sha256, verify_case_metadata};
use irmind_domain::{Actor, CaseId, Severity};
use serde_json::json;
use std::process::Command;

fn synthetic_export(path: &std::path::Path) -> String {
    let case_id = "11111111-1111-1111-1111-111111111111";
    let scope = "synthetic-only";
    let key = SigningKey::from_bytes(&[17; 32]);
    let public_key = key.verifying_key().to_bytes().to_vec();
    let fingerprint = hex(&sha256(&public_key));
    let mut created = SignedEntry {
        seq: 1,
        case_id: case_id.into(),
        at: 1,
        actor: Actor::Analyst,
        origin: "analyst".into(),
        kind: "CaseCreated".into(),
        payload: json!({"version": 3, "title": "Synthetic", "severity": "medium", "scope": scope})
            .to_string(),
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: public_key.clone(),
    };
    created.hash = sha256(&created.canonical());
    created.sig = key.sign(&created.hash).to_bytes().to_vec();
    let mut sealed = SignedEntry {
        seq: 2,
        case_id: case_id.into(),
        at: 2,
        actor: Actor::Analyst,
        origin: "analyst".into(),
        kind: "CaseSealed".into(),
        payload: String::new(),
        evidence: None,
        prev: created.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: public_key.clone(),
    };
    sealed.hash = sha256(&sealed.canonical());
    sealed.sig = key.sign(&sealed.hash).to_bytes().to_vec();
    assert!(
        verify_case_metadata(
            "Synthetic",
            Severity::Medium,
            scope,
            &[created.clone(), sealed.clone()]
        )
        .is_ok()
    );
    let seal = CaseSeal {
        seq: sealed.seq,
        hash: sealed.hash,
        sig: key
            .sign(&seal_challenge(
                &CaseId::parse(case_id).unwrap(),
                sealed.seq,
                &sealed.hash,
                &sealed.payload,
            ))
            .to_bytes()
            .to_vec(),
        public_key,
        analyst_key_fingerprint: fingerprint.clone(),
    };
    let bundle = json!({
        "version": 3,
        "case_id": case_id,
        "title": "Synthetic",
        "severity": "medium",
        "scope": scope,
        "audit": [created, sealed],
        "seal": seal,
        "evidence": {},
    });
    std::fs::write(path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    fingerprint
}

#[test]
fn export_verifies_without_a_keyring() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("synthetic.irmind.json");
    let fingerprint = synthetic_export(&path);

    let output = Command::new(env!("CARGO_BIN_EXE_irmind"))
        .env_clear()
        .args([
            "verify-export",
            path.to_str().unwrap(),
            "--expected-key",
            &fingerprint,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&fingerprint));
}

#[test]
fn portable_export_fixture() {
    let scratch = tempfile::tempdir().unwrap();
    let root = std::env::var_os("IRMIND_PORTABLE_EXPORT_DIR")
        .map_or_else(|| scratch.path().to_path_buf(), std::path::PathBuf::from);
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("synthetic.irmind.json");
    let fingerprint = synthetic_export(&path);
    std::fs::write(root.join("expected-key.txt"), format!("{fingerprint}\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_irmind"))
        .env_clear()
        .args([
            "verify-export",
            path.to_str().unwrap(),
            "--expected-key",
            &fingerprint,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
