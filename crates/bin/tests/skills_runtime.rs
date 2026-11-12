#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![cfg(all(
    feature = "parser-json",
    feature = "parser-linux",
    feature = "parser-hayabusa"
))]
#[path = "support/current_sources.rs"]
mod current_sources;
#[path = "skills_runtime/mod.rs"]
mod support;
use irmind_app::{
    AuditLog, CancellationToken, ExportVerifier, FindingKind, LargeCaseUseCases, MessageRole,
};
use irmind_domain::{Actor, AuditEventKind};
use support::*;

#[test]
fn three_bundled_methods_complete_scripted_synthetic_investigations_and_v7_exports() {
    for (name, parser, fixture, term) in [
        (
            "windows-triage",
            "parser-hayabusa",
            include_str!("../../testkit/fixtures/parser-hayabusa/source/events.jsonl"),
            "powershell",
        ),
        (
            "linux-triage",
            "parser-linux",
            include_str!("../../testkit/fixtures/common/linux/sshd.log"),
            "alice",
        ),
        (
            "aws-credential-compromise",
            "parser-json",
            include_str!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"),
            "AssumeRole",
        ),
    ] {
        episode(name, parser, fixture, term);
    }
}
#[allow(clippy::too_many_lines)]
fn episode(name: &str, parser_id: &str, fixture: &str, term: &str) {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let case = engine
        .create_case("Synthetic skill episode", "local evidence only")
        .unwrap();
    std::fs::write(root.path().join("source.log"), fixture).unwrap();
    let parser = current_sources::parser(parser_id);
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    let ingested = large
        .ingest_local_batch(
            &case.id,
            root.path(),
            &["source.log".into()],
            false,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(ingested.len(), 1);
    let hash = ingested[0].1.as_str().to_owned();
    let model = Episode::new(name, term, &hash);
    let answer = engine
        .investigate(
            &case.id,
            "Review the synthetic incident using the relevant method.",
            &model,
        )
        .unwrap();
    assert!(answer.contains(&hash));
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(
        requests[0]
            .messages
            .iter()
            .any(|m| m.content.contains(name))
    );
    assert!(
        !requests[0]
            .messages
            .iter()
            .any(|m| m.content.contains("## Establish coverage"))
    );
    for request in requests.iter() {
        request.validate().unwrap();
        for message in &request.messages {
            if message.role == MessageRole::System {
                assert!(!message.content.contains("## Establish coverage"));
                assert!(!message.content.contains("Synthetic skill episode"));
            }
            if message.content.contains("## Establish coverage") {
                assert_eq!(message.role, MessageRole::Tool);
                assert!(message.content.contains("<UNTRUSTED_"));
                assert_eq!(message.tool_call_id.as_deref(), Some("episode_0"));
            }
        }
    }
    drop(requests);
    let entries = store.entries(&case.id).unwrap();
    let snapshot = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::SkillSnapshotV1)
        .unwrap();
    let load = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::SkillLoadV1)
        .unwrap();
    assert_eq!(snapshot.actor, Actor::Analyst);
    assert!(matches!(load.actor, Actor::Agent(_)));
    assert!(load.evidence.is_none());
    let package = irmind_app::SkillSnapshotV1::decode(&snapshot.payload).unwrap();
    assert!(
        engine
            .add_finding(
                &case.id,
                FindingKind::Hypothesis,
                "Methodology is not evidence",
                &irmind_app::hex(package.package().unwrap().hash().as_bytes())
            )
            .is_err()
    );
    let findings = engine.findings(&case.id).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(!findings[0].confirmed);
    engine.confirm_finding(&case.id, &findings[0].id).unwrap();
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let export = root.path().join("episode.irmind");
    let key = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &case.id,
        &export,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let details = irmind_infra::LocalExportVerifier
        .verify_export_details(&export, Some(&key))
        .unwrap();
    assert_eq!(details.format_version, 7);
    assert!(
        std::fs::read(&export)
            .unwrap()
            .starts_with(b"IRMIND-EXPORT-V7\0")
    );
    if std::env::var_os("IRMIND_REFRESH_SKILL_EXPORT_SEEDS").is_some() {
        let seed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/seeds/export")
            .join(format!("valid-v7-skill-{name}.irmind"));
        std::fs::copy(&export, seed).unwrap();
    }
}
