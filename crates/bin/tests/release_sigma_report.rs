#![cfg(all(unix, feature = "keystore-file"))]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use irmind_app::ingest_outcome::{FileReason, IngestFileOutcome};
use irmind_app::v10_proofs::{
    ReportCitationsV1, ReportCoverageV2, ReportMediaV1, ReportPublishedV1, SIGMA_EVALUATOR_V4,
    SIGMA_EVALUATOR_V4_CASE_ADMISSION, SigmaCaseRunAdmissionV1, SigmaPackManifestV1,
    SigmaPackRuleV1, SigmaRuleKeyV1, SigmaRunResultsV3, SigmaRunV1, V10Citation,
};
use irmind_app::{SignerBackend, hex, sha256};
use irmind_domain::{Actor, AuditEventKind, CaseId, SourceManifestV2};
use irmind_mod_keystore_file::FileKeystore;
use secrecy::SecretString;
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

#[path = "support/demo_session.rs"]
mod demo_session;
#[path = "support/terminal_screen.rs"]
mod terminal_screen;

use demo_session::DemoSession;

const PASSPHRASE: &str = "synthetic release test file keystore";
struct Scenario {
    name: &'static str,
    title: &'static str,
    parser: Option<&'static str>,
    rule_id: &'static str,
    rule: &'static str,
    time_range: &'static str,
    evidence: fn(&Path) -> PathBuf,
}

const SCENARIOS: [Scenario; 2] = [
    Scenario {
        name: "cloudtrail",
        title: "Synthetic failed CloudTrail sign-in",
        parser: None,
        rule_id: "427b4a53-2c9b-4c89-8b76-25ef2a96e2aa",
        rule: "title: Synthetic failed CloudTrail sign-in
id: 427b4a53-2c9b-4c89-8b76-25ef2a96e2aa
logsource: {product: aws, service: cloudtrail}
detection: {selection: {Outcome: failure}, condition: selection}
",
        time_range: "2026-11-01T00:00:00Z 2026-11-01T00:02:00Z",
        evidence: write_cloudtrail,
    },
    Scenario {
        name: "windows",
        title: "Synthetic Sysmon process start",
        parser: Some("parser-evtx"),
        rule_id: "427b4a53-2c9b-4c89-8b76-25ef2a96e2ab",
        rule: "title: Synthetic Sysmon process start
id: 427b4a53-2c9b-4c89-8b76-25ef2a96e2ab
logsource: {product: windows, service: sysmon, category: process_creation}
detection: {selection: {EventID: 1, 'CommandLine|contains': 'echo synthetic'}, condition: selection}
",
        time_range: "2026-11-01T12:00:00Z 2026-11-01T12:02:00Z",
        evidence: write_sysmon,
    },
];
const RULE_FILE: &str = "synthetic.yml";
const LOG_DIRECTORY: &str = "AWSLogs/111122223333/CloudTrail/us-east-2/2026/11/01";
const FAILED_LOG: &str =
    "111122223333_CloudTrail_us-east-2_20261101T0000Z_synthetic-fail00.json.gz";
const SUCCESS_LOG: &str =
    "111122223333_CloudTrail_us-east-2_20261101T0001Z_synthetic-pass00.json.gz";
const DIGEST: &str = "AWSLogs/111122223333/CloudTrail-Digest/us-east-2/2026/11/01/111122223333_CloudTrail-Digest_us-east-2_synthetic_us-east-2_20261101T010000Z.json.gz";

#[test]
#[ignore = "requires the staged distribution binary and an artifact output directory"]
fn release_binary_sigma_report_v10() {
    let binary = required_path("IRMIND_RELEASE_BINARY");
    let output = required_path("IRMIND_RELEASE_SIGMA_OUTPUT");
    assert!(binary.is_file());
    fs::create_dir(&output).unwrap();
    for scenario in &SCENARIOS {
        let output = output.join(scenario.name);
        fs::create_dir(&output).unwrap();
        run_scenario(&binary, &output, scenario);
    }
}

fn run_scenario(binary: &Path, output: &Path, scenario: &Scenario) {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("vault");
    fs::create_dir(&home).unwrap();
    let key = prepare_keystore(&home);
    let pack = scratch.path().join("rules");
    fs::create_dir(&pack).unwrap();
    fs::write(pack.join(RULE_FILE), scenario.rule).unwrap();

    let source = (scenario.evidence)(scratch.path());
    let cli = |args: &[&str]| run_cli(binary, &home, args);
    let case = cli(&[
        "case",
        "new",
        "Synthetic Sigma release case",
        "--scope",
        "local",
    ]);
    let case = case.trim();
    CaseId::parse(case).unwrap();
    let mut ingest = vec!["ingest", case, source.to_str().unwrap()];
    if let Some(parser) = scenario.parser {
        ingest.extend(["--parser", parser]);
    }
    if source.is_dir() {
        let mut ui = open_tui(binary, &home, case);
        ui.send(format!("/ingest {}\r", source.display())).unwrap();
        ui.expect("Folder queue").unwrap();
        ui.expect("skip file").unwrap();
        ui.send("\u{13}").unwrap();
        ui.expect("Ingested 2 files").unwrap();
        quit(&mut ui);
        let verified = cli(&["verify", case, "--source-root", source.to_str().unwrap()]);
        assert!(verified.contains("1 SHA-256 matches"), "{verified}");
    } else {
        cli(&ingest);
    }

    let finding = evaluate(binary, &home, case, &pack, scenario, &cli);
    cli(&["confirm-finding", case, &finding]);
    publish(binary, &home, case);
    cli(&[
        "verify",
        case,
        "--source-root",
        if source.is_dir() {
            &source
        } else {
            scratch.path()
        }
        .to_str()
        .unwrap(),
    ]);
    cli(&["seal", case]);

    let export = output.join("sigma-report-v10.irmind");
    cli(&["export", case, export.to_str().unwrap()]);
    let bytes = fs::read(&export).unwrap();
    assert!(bytes.len() < 16 * 1024 * 1024);
    assert_package(&bytes, &finding, scenario);
    if source.is_dir() {
        assert_cloudtrail_originals(&bytes, &source);
    }
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

fn write_cloudtrail(root: &Path) -> PathBuf {
    let failure = include_str!("../../testkit/fixtures/common/cloudtrail-console-login.jsonl");
    let mut success: serde_json::Value = serde_json::from_str(failure).unwrap();
    success["responseElements"]["ConsoleLogin"] = "Success".into();
    success["eventTime"] = "2026-11-01T00:01:00Z".into();
    success["eventID"] = "synthetic-console-success".into();
    let delivery = root.join("cloudtrail-delivery");
    let logs = delivery.join(LOG_DIRECTORY);
    fs::create_dir_all(&logs).unwrap();
    let failure = format!("{{\"Records\":[{}]}}", failure.trim_end());
    let success = format!("{{\"Records\":[{success}]}}");
    for (name, content) in [(FAILED_LOG, &failure), (SUCCESS_LOG, &success)] {
        let midpoint = content.len() / 2;
        write_gzip_members(
            &logs.join(name),
            [
                &content.as_bytes()[..midpoint],
                &content.as_bytes()[midpoint..],
            ],
        );
    }
    let log_files = [(FAILED_LOG, failure), (SUCCESS_LOG, success)].map(|(name, log)| {
        serde_json::json!({
            "s3Bucket": "synthetic-delivery",
            "s3Object": format!("{LOG_DIRECTORY}/{name}"),
            "hashValue": hex(&sha256(log.as_bytes())),
            "hashAlgorithm": "SHA-256"
        })
    });
    let digest = serde_json::json!({
        "awsAccountId": "111122223333",
        "digestStartTime": "2026-11-01T00:00:00Z",
        "digestEndTime": "2026-11-01T01:00:00Z",
        "digestS3Bucket": "synthetic-delivery",
        "digestS3Object": DIGEST,
        "digestPublicKeyFingerprint": "00000000000000000000000000000000",
        "digestSignatureAlgorithm": "SHA256withRSA",
        "logFiles": log_files
    });
    let path = delivery.join(DIGEST);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    write_gzip_members(&path, [digest.to_string().as_bytes()]);
    let original = logs.join(FAILED_LOG);
    fs::write(
        logs.join(format!("{FAILED_LOG}.sha256")),
        hex(&sha256(&fs::read(original).unwrap())),
    )
    .unwrap();
    fs::write(delivery.join("unknown-ñ.bin"), [1, 2, 3]).unwrap();
    delivery
}

fn write_gzip_members(path: &Path, members: impl IntoIterator<Item = impl AsRef<[u8]>>) {
    let mut file = fs::File::create(path).unwrap();
    for member in members {
        let mut encoder = flate2::write::GzEncoder::new(&mut file, flate2::Compression::fast());
        encoder.write_all(member.as_ref()).unwrap();
        encoder.finish().unwrap();
    }
}

fn write_sysmon(root: &Path) -> PathBuf {
    let path = root.join("synthetic-sysmon.evtx");
    fs::write(
        &path,
        include_bytes!("../../testkit/fixtures/mapping-evtx/source/sysmon.evtx"),
    )
    .unwrap();
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
    String::from_utf8(cli_output(binary, home, args).stdout).unwrap()
}

fn cli_output(binary: &Path, home: &Path, args: &[&str]) -> Output {
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
    result
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
    scenario: &Scenario,
    cli: &impl Fn(&[&str]) -> String,
) -> String {
    let mut ui = open_tui(binary, home, case);
    if scenario.name == "cloudtrail" {
        let bundle = pack.join("synthetic.sigma");
        write_installed_bundle(&bundle, scenario);
        ui.send(format!("/sigma install {}\r", bundle.display()))
            .unwrap();
        ui.expect("Install Sigma package synthetic-release 1.0.0")
            .unwrap();
        ui.send("2\r").unwrap();
        ui.expect("Sigma package synthetic-release is active")
            .unwrap();
        ui.send(format!(
            "/sigma run synthetic-release {}\r",
            scenario.time_range
        ))
        .unwrap();
        ui.expect("Sign case admission for Sigma package synthetic-release")
            .unwrap();
        ui.send("2\r").unwrap();
    } else {
        ui.send(format!("/sigma inspect {}\r", pack.display()))
            .unwrap();
        expect_result(&mut ui, "1 validated rules");
        let digest = hex(&sha256(&pack_manifest(scenario)));
        ui.expect(&digest).unwrap();
        ui.send(format!("/sigma import --license MIT {}\r", pack.display()))
            .unwrap();
        ui.expect("Sign Sigma pack admission").unwrap();
        ui.send("2\r").unwrap();
        ui.expect("Sigma pack admitted").unwrap();
        ui.send(format!("/sigma run {digest} {}\r", scenario.time_range))
            .unwrap();
    }
    ui.expect("Sigma run complete").unwrap();
    quit(&mut ui);

    let findings = cli(&["findings", case]);
    let proposals = findings
        .lines()
        .filter(|line| line.contains(" proposed "))
        .collect::<Vec<_>>();
    assert_eq!(
        proposals.len(),
        1,
        "only the selected synthetic row should match"
    );
    assert!(proposals[0].contains(scenario.title));
    proposals[0].split_whitespace().next().unwrap().to_owned()
}

fn pack_manifest(scenario: &Scenario) -> Vec<u8> {
    SigmaPackManifestV1(vec![SigmaPackRuleV1 {
        path: RULE_FILE.into(),
        rule: SigmaRuleKeyV1 {
            id: scenario.rule_id.into(),
            sha256: sha256(scenario.rule.as_bytes()),
        },
        version: None,
        author: None,
        size: scenario.rule.len() as u64,
    }])
    .encode()
    .unwrap()
}

fn write_installed_bundle(path: &Path, scenario: &Scenario) {
    let metadata = br#"{"format_version":1,"name":"synthetic-release","version":"1.0.0","license":"MIT","attribution":"Release test"}"#;
    let manifest = pack_manifest(scenario);
    let mut bundle = b"irmind-sigma-package-v1\0".to_vec();
    for frame in [metadata.as_slice(), manifest.as_slice()] {
        bundle.extend((frame.len() as u64).to_be_bytes());
        bundle.extend(frame);
    }
    bundle.extend(scenario.rule.as_bytes());
    fs::write(path, bundle).unwrap();
}

fn publish(binary: &Path, home: &Path, case: &str) {
    let mut ui = open_tui(binary, home, case);
    ui.send("/report save md en\r").unwrap();
    expect_result(&mut ui, "Signed report");
    quit(&mut ui);

    let mut ui = open_tui(binary, home, case);
    ui.send("/report save pdf en\r").unwrap();
    expect_result(&mut ui, "Signed report");
    quit(&mut ui);
}

fn quit(ui: &mut DemoSession) {
    ui.send("/quit\r").unwrap();
    ui.expect("Exit IRMind? Enter confirms").unwrap();
    ui.send("\r").unwrap();
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

fn assert_cloudtrail_originals(bytes: &[u8], delivery: &Path) {
    let mut reader = Cursor::new(bytes.strip_prefix(b"IRMIND-EXPORT-V10\0").unwrap());
    read_frame(&mut reader);
    let count = read_count(&mut reader);
    let entries = (0..count)
        .map(|_| read_frame(&mut reader))
        .collect::<Vec<_>>();
    let sources = entries
        .iter()
        .filter(|entry| entry["kind"] == AuditEventKind::SourceManifestV2.as_str())
        .map(|entry| SourceManifestV2::decode(entry["payload"].as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    let outcomes = entries
        .iter()
        .filter(|entry| entry["kind"] == "ingest-file-outcome-v1")
        .map(|entry| IngestFileOutcome::decode(entry["payload"].as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, IngestFileOutcome::Disposition {
        path, reason: FileReason::AnalystSkipped, ..
    } if path == "unknown-ñ.bin"))
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, IngestFileOutcome::Integrity {
        observed, declared, ..
    } if observed.sha256 == *declared))
    );
    assert_eq!(sources.len(), 2);
    for name in [FAILED_LOG, SUCCESS_LOG] {
        let relative = format!("{LOG_DIRECTORY}/{name}");
        let source = sources
            .iter()
            .find(|source| source.source.source == relative)
            .unwrap();
        assert_eq!(source.parser_id, "parser-json");
        assert_eq!(
            source.selection,
            irmind_domain::ParserSelectionMode::Automatic
        );
        assert_eq!(
            source.source.sha256.as_str(),
            hex(&sha256(&fs::read(delivery.join(relative)).unwrap()))
        );
    }
}

fn assert_package(bytes: &[u8], finding: &str, scenario: &Scenario) {
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
    assert_evaluator(
        &run,
        scenario,
        &payloads("sigma-case-run-admission-v1").collect::<Vec<_>>(),
    );
    assert_eq!(run.matched_rows, 1);
    assert_eq!(
        run.status,
        irmind_app::v10_proofs::SigmaRunStatusV1::Complete
    );
    assert_ne!(run.pack_admission, [0; 32]);
    let results = SigmaRunResultsV3::decode(&object(bytes, 5, &run.result_manifest)).unwrap();
    assert_eq!(results.plan.coverage().eligible_pairs, 1);
    let results = results.scan;
    assert!(results.unavailable_by_source.is_empty());
    assert!(results.indeterminate_by_rule.is_empty());
    assert_eq!(results.results.matches.len(), 1);
    let matched = &results.results.matches[0];
    assert_eq!(matched.rule.id, scenario.rule_id);
    assert_eq!(
        object(bytes, 1, &matched.rule.sha256),
        scenario.rule.as_bytes()
    );
    assert_eq!(matched.row.record, 0);

    let reports = payloads("report-published-v1").collect::<Vec<_>>();
    assert_eq!(reports.len(), 2);
    for (payload, format) in reports
        .into_iter()
        .zip([ReportMediaV1::Markdown, ReportMediaV1::Pdf])
    {
        let report = ReportPublishedV1::decode(payload).unwrap();
        assert!(report.media == format);
        assert_report_objects(bytes, &report, finding, matched.row, scenario.title);
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
    title: &str,
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
        assert!(
            document
                .windows(title.len())
                .any(|part| part == title.as_bytes())
        );
    } else {
        let escaped_title = title.replace('-', r"\-");
        let markdown = String::from_utf8(document).unwrap();
        assert!(markdown.contains(&escaped_title));
        if title == SCENARIOS[0].title {
            assert!(markdown.contains("Folder ingestion"));
            assert!(markdown.contains(r"unknown\-ñ\[\.\]bin"));
        }
    }
}

fn assert_evaluator(run: &SigmaRunV1, scenario: &Scenario, case_admissions: &[&str]) {
    // The harness builds with minimal features. The staged release executable
    // supplies Entra's field table and therefore uses the V4 evaluator.
    if scenario.name == "cloudtrail" {
        assert_eq!(run.evaluator, SIGMA_EVALUATOR_V4_CASE_ADMISSION);
        assert_eq!(case_admissions.len(), 1);
        let admission = SigmaCaseRunAdmissionV1::decode(&decode_hex(case_admissions[0])).unwrap();
        assert_eq!(admission.evaluator, run.evaluator);
        assert!(admission.installation.is_some());
        assert_eq!(admission.manifest, sha256(&pack_manifest(scenario)));
    } else {
        assert_eq!(run.evaluator, SIGMA_EVALUATOR_V4);
        assert!(case_admissions.is_empty());
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}
