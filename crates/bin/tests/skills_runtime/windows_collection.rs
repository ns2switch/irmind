//! Synthetic exported Windows collection; private answers are evaluator-only.
mod model;
use irmind_app::{
    CancellationToken, EvidenceGraph, ExportVerifier, LargeCaseUseCases, MessageRole,
    modules::ParserSelectionRequest,
};
use irmind_domain::{Actor, AuditEventKind, SourceRecordSetV1};
use std::{collections::BTreeMap, path::Path};

const FILES: &[(&str, &str)] = &[
    ("amcache.csv", "parser-eztools"),
    ("appcompat.csv", "parser-eztools"),
    ("evtxecmd.csv", "parser-eztools"),
    ("hayabusa.jsonl", "parser-hayabusa"),
    ("lnk.csv", "parser-eztools"),
    ("mft.csv", "parser-eztools"),
    ("pecmd.csv", "parser-eztools"),
    ("registry.csv", "parser-eztools"),
    ("srum.csv", "parser-eztools"),
];

fn source_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testkit/fixtures/windows-triage-collection")
}

#[test]
fn windows_triage_correlates_nine_exports_without_treating_cache_presence_as_execution() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("input");
    std::fs::create_dir(&input).unwrap();
    let (store, engine) = super::setup(temporary.path());
    let case = engine
        .create_case(
            "Synthetic multi-artifact Windows collection",
            "local evidence only",
        )
        .unwrap();
    let hashes = ingest(&engine, &store, &case.id, &input);
    assert_eq!(store.timeline(&case.id, 20).unwrap().len(), 10);
    let scripted = model::Collection::new(hashes.clone());
    let answer = engine
        .investigate(
            &case.id,
            "Use Windows triage on these exported artifacts; separate observations from hypotheses and missing coverage.",
            &scripted,
        )
        .unwrap();
    assert!(answer.contains("Cache presence alone does not prove execution"));
    check_requests(&scripted);
    evaluate(&engine, &case.id, &hashes, &scripted, &answer);
    verify_collection(&engine, &store, &case.id, &input);
    export(&engine, &store, &case.id, temporary.path());
}

fn ingest(
    engine: &irmind_app::Engine<'_>,
    store: &irmind_infra::LocalStore,
    case: &irmind_domain::CaseId,
    input: &Path,
) -> BTreeMap<String, String> {
    let catalog = crate::current_sources::catalog();
    FILES
        .iter()
        .map(|(name, parser)| {
            let bytes = std::fs::read(source_root().join("source").join(name)).unwrap();
            std::fs::write(input.join(name), &bytes).unwrap();
            let selected = catalog
                .select_source(ParserSelectionRequest {
                    source: name,
                    sample: &bytes,
                    parser_override: None,
                    forced: false,
                    time_context: None,
                    cluster_context: None,
                })
                .unwrap();
            assert_eq!(selected.parser.identity().name, *parser);
            assert_eq!(selected.selection.parser_id, *parser);
            let result = LargeCaseUseCases {
                engine,
                store,
                parser: selected.parser.as_ref(),
            }
            .ingest_local_batch_selected(
                case,
                input,
                &[(*name).into()],
                false,
                &BTreeMap::from([((*name).into(), selected.selection)]),
                &CancellationToken::new(),
            )
            .unwrap();
            assert_eq!(result.len(), 1);
            ((*name).into(), result[0].1.as_str().into())
        })
        .collect()
}

fn check_requests(scripted: &model::Collection) {
    let requests = scripted.requests.lock().unwrap();
    assert_eq!(requests.len(), 7);
    for request in requests.iter() {
        for message in &request.messages {
            assert!(
                !message
                    .content
                    .contains("WINDOWS_COLLECTION_EVALUATOR_ONLY_157")
            );
            if message.role == MessageRole::System {
                for source in [
                    "synthetic-win-01",
                    "demo-agent.exe",
                    "## Establish coverage",
                ] {
                    assert!(!message.content.contains(source));
                }
            }
            if message.content.contains("view=original") {
                assert_eq!(message.role, MessageRole::Tool);
                assert!(message.content.contains("<UNTRUSTED_"));
            }
        }
    }
    assert!(
        requests[1].messages.iter().any(|m| {
            m.role == MessageRole::Tool && m.content.contains("## Establish coverage")
        })
    );
}

fn evaluate(
    engine: &irmind_app::Engine<'_>,
    id: &irmind_domain::CaseId,
    hashes: &BTreeMap<String, String>,
    scripted: &model::Collection,
    answer: &str,
) {
    // Read expectations only after the scripted agent's final response.
    let expected: serde_json::Value = serde_json::from_slice(
        &std::fs::read(source_root().join("private/ground-truth.json")).unwrap(),
    )
    .unwrap();
    let requests = scripted.requests.lock().unwrap();
    let originals = requests
        .iter()
        .flat_map(|r| &r.messages)
        .filter(|m| m.role == MessageRole::Tool && m.content.contains("view=original"))
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for field in ["expected_host", "observed_process"] {
        let guarded = engine
            .guard
            .screen(expected[field].as_str().unwrap())
            .unwrap()
            .text;
        assert!(originals.contains(&guarded));
    }
    for event in expected["event_ids"].as_array().unwrap() {
        assert!(originals.contains(&event.as_u64().unwrap().to_string()));
    }
    for unsupported in expected["must_not_claim"].as_array().unwrap() {
        assert!(!answer.contains(unsupported.as_str().unwrap()));
    }
    drop(requests);
    let entries = engine.audit_log.entries(id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SourceRecordSetV1)
            .count(),
        usize::try_from(expected["source_files"].as_u64().unwrap()).unwrap()
    );
    let records: u64 = entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::SourceRecordSetV1)
        .map(|e| SourceRecordSetV1::decode(&e.payload).unwrap().records())
        .sum();
    assert_eq!(records, expected["source_records"].as_u64().unwrap());
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SkillLoadV1 && matches!(e.actor, Actor::Agent(_)))
            .count(),
        1
    );
    assert!(
        !entries
            .iter()
            .any(|e| e.payload.contains(expected["marker"].as_str().unwrap()))
    );
    let findings = engine.findings(id).unwrap();
    assert_eq!(findings.len(), 2);
    for finding in findings {
        assert!(!finding.confirmed);
        engine.confirm_finding(id, &finding.id).unwrap();
    }
    let report = engine.report(id).unwrap();
    assert!(report.contains(expected["proposal_technique"].as_str().unwrap()));
    for hash in hashes.values() {
        assert!(report.contains(hash));
    }
}

fn verify_collection(
    engine: &irmind_app::Engine<'_>,
    store: &irmind_infra::LocalStore,
    id: &irmind_domain::CaseId,
    input: &Path,
) {
    let parser = crate::current_sources::parser("parser-eztools");
    let large = LargeCaseUseCases {
        engine,
        store,
        parser: parser.as_ref(),
    };
    let checked = large
        .verify_sources(
            id,
            input,
            irmind_app::SourceCheckMode::Full,
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(checked.checked, 9);
    assert!(checked.missing_or_changed.is_empty());
    assert!(
        large
            .verify_parquet_rebuild(id, input, &CancellationToken::new())
            .unwrap()
            > 0
    );
    engine.verify(id).unwrap();
}

fn export(
    engine: &irmind_app::Engine<'_>,
    store: &irmind_infra::LocalStore,
    id: &irmind_domain::CaseId,
    root: &Path,
) {
    engine.seal(id).unwrap();
    let file = root.join("windows-collection.irmind");
    let key = irmind_app::export_case_with_originals(
        engine,
        store,
        id,
        &file,
        Some(&root.join("input")),
        true,
        &CancellationToken::new(),
    )
    .unwrap();
    let verified = irmind_infra::LocalExportVerifier
        .verify_export_details(&file, Some(&key))
        .unwrap();
    assert_eq!(verified.format_version, 7);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_irmind"))
        .args([
            "--home",
            root.join("offline-verifier").to_str().unwrap(),
            "verify-export",
        ])
        .arg(&file)
        .args(["--expected-key", &key])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("original bytes verified: 9")
    );
}
