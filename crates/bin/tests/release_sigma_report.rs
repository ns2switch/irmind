#![cfg(all(unix, feature = "keystore-file"))]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use irmind_app::v10_proofs::{
    ReportCitationsV1, ReportCoverageV2, ReportMediaV1, ReportPublishedV1, SigmaPackManifestV1,
    SigmaPackRuleV1, SigmaRuleKeyV1, SigmaRunResultsV1, SigmaRunV1, V10Citation,
};
use irmind_app::{SignerBackend, hex, sha256};
use irmind_domain::{Actor, CaseId};
use irmind_mod_keystore_file::FileKeystore;
use secrecy::SecretString;
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[path = "support/demo_session.rs"]
mod demo_session;
#[path = "support/terminal_screen.rs"]
mod terminal_screen;

use demo_session::DemoSession;

const PASSPHRASE: &str = "synthetic release test file keystore";
const TITLE: &str = "Synthetic failed CloudTrail sign-in";
const RULE_ID: &str = "427b4a53-2c9b-4c89-8b76-25ef2a96e2aa";
const RULE: &str = "title: Synthetic failed CloudTrail sign-in
id: 427b4a53-2c9b-4c89-8b76-25ef2a96e2aa
logsource: {product: aws, service: cloudtrail}
detection: {selection: {Outcome: failure}, condition: selection}
";

#[test]
#[ignore = "requires the staged distribution binary and an artifact output directory"]
fn release_binary_sigma_report_v10() {
    let binary = required_path("IRMIND_RELEASE_BINARY");
    let output = required_path("IRMIND_RELEASE_SIGMA_OUTPUT");
    assert!(binary.is_file());
    fs::create_dir(&output).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("vault");
    fs::create_dir(&home).unwrap();
    let key = prepare_keystore(&home);
    let pack = scratch.path().join("rules");
    fs::create_dir(&pack).unwrap();
    fs::write(pack.join("failed-login.yml"), RULE).unwrap();

    let source = write_evidence(scratch.path());
    let cli = |args: &[&str]| run_cli(&binary, &home, args);
    let case = cli(&[
        "case",
        "new",
        "Synthetic Sigma release case",
        "--scope",
        "local",
    ]);
    let case = case.trim();
    CaseId::parse(case).unwrap();
    cli(&[
        "ingest",
        case,
        source.to_str().unwrap(),
        "--parser",
        "parser-json",
    ]);

    let finding = evaluate(&binary, &home, case, &pack, &cli);
    cli(&["confirm-finding", case, &finding]);
    publish(&binary, &home, case);
    cli(&["verify", case]);
    cli(&["seal", case]);

    let export = output.join("sigma-report-v10.irmind");
    cli(&["export", case, export.to_str().unwrap()]);
    let bytes = fs::read(&export).unwrap();
    assert!(bytes.len() < 16 * 1024 * 1024);
    assert_package(&bytes, &finding);
    fs::write(output.join("expected-key.txt"), format!("{key}\n")).unwrap();
    fs::write(
        output.join("archive-sha256.txt"),
        format!("{}\n", hex(&sha256(&bytes))),
    )
    .unwrap();
}

fn required_path(name: &str) -> PathBuf {
    let path = std::env::var_os(name)
        .ok_or_else(|| format!("{name} is required"))
        .unwrap();
    let path = PathBuf::from(path);
    assert!(path.is_absolute(), "{name} must be an absolute path");
    path
}

fn prepare_keystore(home: &Path) -> String {
    let phrase = SecretString::from(PASSPHRASE.to_owned());
    let backend = FileKeystore::open(home, &phrase, true).unwrap();
    let analyst = backend.create(Actor::Analyst).unwrap();
    let fingerprint = hex(&sha256(&analyst.public_key()));
    fs::write(
        home.join("keystore.toml"),
        format!(
            "[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{fingerprint}\"\n"
        ),
    )
    .unwrap();
    fingerprint
}

fn write_evidence(root: &Path) -> PathBuf {
    let failure = include_str!("../../testkit/fixtures/common/cloudtrail-console-login.jsonl");
    let mut success: serde_json::Value = serde_json::from_str(failure).unwrap();
    success["responseElements"]["ConsoleLogin"] = "Success".into();
    success["eventTime"] = "2026-11-01T00:01:00Z".into();
    success["eventID"] = "synthetic-console-success".into();
    let path = root.join("cloudtrail.jsonl");
    fs::write(&path, format!("{}\n{success}\n", failure.trim_end())).unwrap();
    path
}

fn command(binary: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .arg("--home")
        .arg(home)
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .env_remove("IRMIND_POLICY")
        .env_remove("IRMIND_LLM_MODULE");
    command
}

fn run_cli(binary: &Path, home: &Path, args: &[&str]) -> String {
    let mut child = command(binary, home)
        .args(["--passphrase-fd", "0"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{PASSPHRASE}").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "IRMind {} failed: {}",
        args[0],
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn open_tui(binary: &Path, home: &Path, case: &str) -> DemoSession {
    let mut command = command(binary, home);
    command.args(["tui", case]);
    let mut ui = DemoSession::spawn_sized(&command, 140, 50).unwrap();
    ui.expect("Unlock the configured file keystore").unwrap();
    ui.send(format!("{PASSPHRASE}\r")).unwrap();
    ui.expect("Analyst public-key fingerprint").unwrap();
    ui.send("\r").unwrap();
    ui.expect("Synthetic Sigma release case").unwrap();
    ui
}

fn evaluate(
    binary: &Path,
    home: &Path,
    case: &str,
    pack: &Path,
    cli: &impl Fn(&[&str]) -> String,
) -> String {
    let mut ui = open_tui(binary, home, case);
    ui.send(format!("/sigma inspect {}\r", pack.display()))
        .unwrap();
    expect_result(&mut ui, "1 validated rules");
    let digest = pack_digest();
    ui.expect(&digest).unwrap();
    ui.send(format!("/sigma import {}\r", pack.display()))
        .unwrap();
    ui.expect("Sign Sigma pack admission").unwrap();
    ui.send("\r").unwrap();
    ui.expect("Sigma pack admitted").unwrap();
    ui.send(format!(
        "/sigma run {digest} 2026-11-01T00:00:00Z 2026-11-01T00:02:00Z\r",
    ))
    .unwrap();
    ui.expect("Sigma run complete").unwrap();
    ui.send("/quit\r").unwrap();
    ui.expect_exit().unwrap();

    let findings = cli(&["findings", case]);
    let proposals = findings
        .lines()
        .filter(|line| line.contains(" proposed "))
        .collect::<Vec<_>>();
    assert_eq!(proposals.len(), 1, "only the failing login should match");
    assert!(proposals[0].contains(TITLE));
    proposals[0].split_whitespace().next().unwrap().to_owned()
}

fn pack_digest() -> String {
    let manifest = SigmaPackManifestV1(vec![SigmaPackRuleV1 {
        path: "failed-login.yml".into(),
        rule: SigmaRuleKeyV1 {
            id: RULE_ID.into(),
            sha256: sha256(RULE.as_bytes()),
        },
        version: None,
        author: None,
        size: RULE.len() as u64,
    }]);
    hex(&sha256(&manifest.encode().unwrap()))
}

fn publish(binary: &Path, home: &Path, case: &str) {
    let mut ui = open_tui(binary, home, case);
    ui.send("/report save md en\r").unwrap();
    expect_result(&mut ui, "Signed report");
    ui.send("/quit\r").unwrap();
    ui.expect_exit().unwrap();

    let mut ui = open_tui(binary, home, case);
    ui.send("/report save pdf en\r").unwrap();
    expect_result(&mut ui, "Signed report");
    ui.send("/quit\r").unwrap();
    ui.expect_exit().unwrap();
}

fn expect_result(ui: &mut DemoSession, expected: &str) {
    ui.expect("approved · result available").unwrap();
    ui.send("/expand\r").unwrap();
    ui.expect(expected).unwrap();
}

fn read_count(reader: &mut impl Read) -> u64 {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes).unwrap();
    u64::from_be_bytes(bytes)
}

fn read_frame(reader: &mut impl Read) -> serde_json::Value {
    let size = usize::try_from(read_count(reader)).unwrap();
    assert!((1..=1024 * 1024).contains(&size));
    let mut frame = vec![0; size];
    reader.read_exact(&mut frame).unwrap();
    serde_json::from_slice(&frame).unwrap()
}

fn assert_package(bytes: &[u8], finding: &str) {
    let magic = b"IRMIND-EXPORT-V10\0";
    let mut reader = Cursor::new(bytes.strip_prefix(magic).unwrap());
    assert_eq!(read_frame(&mut reader)["version"], 10);
    let count = read_count(&mut reader);
    assert!((1..1024).contains(&count));
    let entries = (0..count)
        .map(|_| read_frame(&mut reader))
        .collect::<Vec<_>>();
    let payloads = |kind| {
        entries
            .iter()
            .filter(move |entry| entry["kind"] == kind)
            .map(|entry| entry["payload"].as_str().unwrap())
    };
    let runs = payloads("sigma-run-v1").collect::<Vec<_>>();
    assert_eq!(runs.len(), 1);
    let run = SigmaRunV1::decode(runs[0]).unwrap();
    assert_eq!(run.matched_rows, 1);
    assert!(run.status == irmind_app::v10_proofs::SigmaRunStatusV1::Complete);
    assert_ne!(run.pack_admission, [0; 32]);
    let results = SigmaRunResultsV1::decode(&object(bytes, 5, &run.result_manifest)).unwrap();
    assert_eq!(results.matches.len(), 1);
    let matched = &results.matches[0];
    assert_eq!(matched.rule.id, RULE_ID);
    assert_eq!(object(bytes, 1, &matched.rule.sha256), RULE.as_bytes());
    assert_eq!(matched.row.record, 0);

    let reports = payloads("report-published-v1").collect::<Vec<_>>();
    assert_eq!(reports.len(), 2);
    for (payload, format) in reports
        .into_iter()
        .zip([ReportMediaV1::Markdown, ReportMediaV1::Pdf])
    {
        let report = ReportPublishedV1::decode(payload).unwrap();
        assert!(report.media == format);
        assert_report_objects(bytes, &report, finding, matched.row);
    }
}

fn object(bytes: &[u8], kind: u8, hash: &[u8; 32]) -> Vec<u8> {
    let mut marker = [0; 33];
    marker[0] = kind;
    marker[1..].copy_from_slice(hash);
    let offset = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    let mut frame = &bytes[offset + marker.len()..];
    let size = usize::try_from(read_count(&mut frame)).unwrap();
    let body = frame[..size].to_vec();
    assert_eq!(&sha256(&body), hash);
    body
}

fn assert_report_objects(
    bytes: &[u8],
    report: &ReportPublishedV1,
    finding: &str,
    matched_row: irmind_app::v10_proofs::V10RowReference,
) {
    let citations = ReportCitationsV1::decode(&object(bytes, 0, &report.citations)).unwrap();
    assert_eq!(citations.0.len(), 1);
    assert_eq!(citations.0[0].finding_id, finding);
    assert!(matches!(
        citations.0[0].citations.as_slice(),
        [V10Citation::Row(row)] if *row == matched_row
    ));
    ReportCoverageV2::decode(&object(bytes, 2, &report.coverage)).unwrap();
    let document = object(bytes, 3, &report.rendered_sha256);
    assert_eq!(document.len() as u64, report.rendered_length);
    if report.media == ReportMediaV1::Pdf {
        assert!(document.starts_with(b"%PDF-"));
    } else {
        assert!(String::from_utf8(document).unwrap().contains(TITLE));
    }
}
