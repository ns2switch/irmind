#![cfg(all(
    feature = "keystore-file",
    feature = "parser-json",
    feature = "mapping-cloudtrail"
))]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use irmind_app::ingest_outcome::{FileReason, IngestFileOutcome};
use irmind_app::{AuditLog, SignerBackend, hex, sha256};
use irmind_domain::{Actor, CaseId};
use irmind_infra::LocalStore;
use irmind_mod_keystore_file::FileKeystore;
use secrecy::SecretString;
use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

#[cfg(unix)]
#[path = "support/demo_session.rs"]
mod demo_session;
#[cfg(unix)]
#[path = "support/terminal_screen.rs"]
mod terminal_screen;

#[cfg(unix)]
use std::time::Instant;

const PHRASE: &str = "synthetic folder ingestion test only";
const EVENT: &str = include_str!("../../testkit/fixtures/common/cloudtrail-console-login.jsonl");

fn cli(home: &Path, args: &[&str]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irmind"))
        .args(["--home", home.to_str().unwrap(), "--passphrase-fd", "0"])
        .args(args)
        .env_remove("IRMIND_POLICY")
        .env_remove("IRMIND_SSE_DIAGNOSTICS_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{PHRASE}").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn setup(home: &Path) -> String {
    fs::create_dir(home).unwrap();
    let key = FileKeystore::open(home, &SecretString::from(PHRASE.to_owned()), true)
        .unwrap()
        .create(Actor::Analyst)
        .unwrap()
        .public_key();
    let key = hex(&sha256(&key));
    fs::write(home.join("keystore.toml"),
        format!("[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{key}\"\n")).unwrap();
    key
}

fn write_mixed_evidence(evidence: &Path) {
    let name = "collection/registro-ñ.json";
    fs::write(evidence.join(name), EVENT).unwrap();
    fs::write(evidence.join("same-bytes.json"), EVENT).unwrap();
    fs::write(
        evidence.join("matching.sha256"),
        format!("{} *{name}\n", hex(&sha256(EVENT.as_bytes()))),
    )
    .unwrap();
    fs::write(
        evidence.join("independent.json"),
        EVENT.replace("ConsoleLogin", "OtherEvent"),
    )
    .unwrap();
    fs::write(evidence.join("independent.json.sha256"), "0".repeat(64)).unwrap();
    fs::write(
        evidence.join("collector_ConsoleLog.txt"),
        "2026-11-26 00:00:00.0000 | I | KAPE version 1.3 Author: Eric Zimmerman\n2026-11-26 00:00:00.0001 | I | Command line: synthetic",
    )
    .unwrap();
    fs::write(evidence.join("collection/Collection-endpoint.log"), "[INFO] 2026-11-26T00:00:00Z Starting collection of Collector\n[INFO] 2026-11-26T00:00:00Z Will create container at Collection-endpoint.zip").unwrap();
    fs::write(evidence.join("generic.log"), "unknown synthetic format").unwrap();
    fs::write(evidence.join("opaque.bin"), b"\x01\x02opaque input").unwrap();
    fs::write(evidence.join("event.sig"), "synthetic signature sidecar").unwrap();
    fs::write(
        evidence.join("traversal.sha256"),
        format!(
            "{}  ../outside\n{} *C:/other\n{}  collection\\other\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        ),
    )
    .unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(EVENT.as_bytes()).unwrap();
    gzip.write_all(&vec![b' '; 70_000]).unwrap();
    let mut corrupt = gzip.finish().unwrap();
    let crc = corrupt.len() - 8;
    corrupt[crc] ^= 1;
    fs::write(evidence.join("malformed.json.gz"), corrupt).unwrap();
}

#[test]
fn mixed_folder_custody_with_unicode_and_malicious_checksum_paths() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("vault");
    let key = setup(&home);
    let evidence = scratch.path().join("delivery");
    fs::create_dir_all(evidence.join("collection")).unwrap();
    write_mixed_evidence(&evidence);

    let case = cli(
        &home,
        &["case", "new", "Synthetic folder case", "--scope", "local"],
    );
    let case = case.trim();
    let root = evidence.to_str().unwrap();
    let result = cli(&home, &["ingest", case, root]);
    assert!(result.contains("Ingested 2 files"), "{result}");
    assert!(
        result.contains("1 SHA-256 matches · 1 SHA-256 mismatches"),
        "{result}"
    );
    assert!(result.contains("WARNING: SHA-256 MISMATCH"), "{result}");
    let id = CaseId::parse(case).unwrap();
    let store = LocalStore::open(&home).unwrap();
    let outcomes = store
        .entries(&id)
        .unwrap()
        .iter()
        .filter_map(|entry| IngestFileOutcome::from_audit(entry).unwrap())
        .collect::<Vec<_>>();

    assert!(outcomes.iter().any(|outcome| matches!(outcome, IngestFileOutcome::Disposition { path, reason: FileReason::InvalidFormat, .. } if path == "malformed.json.gz")));
    assert!(outcomes.iter().any(|outcome| matches!(outcome, IngestFileOutcome::Disposition { path, reason: FileReason::NoParserSelected, .. } if path == "generic.log")));
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                IngestFileOutcome::Disposition {
                    reason: FileReason::CollectorLog,
                    ..
                }
            ))
            .count(),
        2
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, IngestFileOutcome::Integrity { .. }))
            .count(),
        2
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, IngestFileOutcome::Disposition {
        path, reason: FileReason::PipelineUnavailable, ..
    } if path == "same-bytes.json"))
    );
    assert!(result.contains("already have a mapped generation"));
    assert!(evidence.join("opaque.bin").is_file());
    assert!(
        cli(&home, &["verify", case, "--source-root", root]).contains("WARNING: SHA-256 MISMATCH")
    );
    cli(&home, &["seal", case]);
    let package = scratch.path().join("mixed.v10");
    cli(&home, &["export", case, package.to_str().unwrap()]);
    irmind_app::verify_export(&irmind_infra::LocalExportVerifier, &package, Some(&key)).unwrap();
}

#[cfg(unix)]
#[test]
#[ignore = "release benchmark with 10,000 filesystem entries"]
fn folder_ingest_ten_thousand_files() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("vault");
    setup(&home);
    let evidence = scratch.path().join("delivery");
    fs::create_dir(&evidence).unwrap();
    for i in 0..10_000 {
        let (extension, contents) = match i {
            0..100 => ("json", EVENT),
            100..8_100 => ("sig", "synthetic signature sidecar"),
            _ => ("bin", "unrecognized synthetic record"),
        };
        let name = evidence.join(format!("{i:05}.{extension}"));
        if extension == "json" {
            fs::write(
                name,
                EVENT.replace("ConsoleLogin", &format!("ConsoleLogin{i}")),
            )
            .unwrap();
        } else {
            fs::write(name, contents).unwrap();
        }
    }
    let case = cli(
        &home,
        &[
            "case",
            "new",
            "Synthetic folder benchmark",
            "--scope",
            "local",
        ],
    );
    let case = case.trim();
    let root = evidence.to_str().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_irmind"));
    command
        .args(["--home", home.to_str().unwrap(), "tui", case])
        .env_remove("IRMIND_POLICY")
        .env_remove("IRMIND_SSE_DIAGNOSTICS_FILE");
    let mut ui = demo_session::DemoSession::spawn_sized(&command, 100, 40).unwrap();
    ui.timeout = std::time::Duration::from_secs(90);
    ui.expect("Unlock the configured file keystore").unwrap();
    ui.send(format!("{PHRASE}\r")).unwrap();
    ui.expect("Analyst public-key fingerprint").unwrap();
    ui.send("\r").unwrap();
    ui.expect("Synthetic folder benchmark").unwrap();
    let start = Instant::now();
    ui.send(format!("/ingest {root}\r")).unwrap();
    ui.expect("Folder queue · 1900 unresolved").unwrap();
    let queued = start.elapsed();
    ui.send("\u{e}").unwrap();
    ui.expect("08102.bin").unwrap();
    let start = Instant::now();
    ui.send("\u{f}").unwrap();
    ui.expect("Ingested 100 files · 9900 skipped · 0 failed")
        .unwrap();
    let resolved = start.elapsed();
    drop(ui);
    let start = Instant::now();
    let checked = cli(&home, &["verify", case, "--source-root", root]);
    let verify = start.elapsed();
    assert!(checked.contains("9900 skipped · 0 failed"), "{checked}");
    println!(
        "FOLDER_BENCH files=10000 recognized=100 unresolved=1900 companions=8000 queue_ms={} skip_and_sign_ms={} verify_ms={}",
        queued.as_millis(),
        resolved.as_millis(),
        verify.as_millis()
    );
}
