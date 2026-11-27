use super::*;
use irmind_app::ExportVerifier;
use irmind_domain::{CommonEventFilter, EntityRole, EventCategory, EventOutcome, GraphQueryFilter};
#[test]
fn native_entra_exports_keep_outcomes_roles_and_signed_reconstruction() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic Entra exports", "local only")
        .unwrap();
    for (name, bytes) in [
        (
            "signin-resource.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/signin-resource.ndjson")
                .as_slice(),
        ),
        (
            "signin-table.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/signin-table.ndjson")
                .as_slice(),
        ),
        (
            "audit-resource.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/audit-resource.ndjson")
                .as_slice(),
        ),
        (
            "audit-table.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-entra/source/audit-table.ndjson")
                .as_slice(),
        ),
    ] {
        fs::write(originals.join(name), bytes).unwrap();
        assert_eq!(
            ingest_with_context(&engine, store.as_ref(), &case.id, &originals, name, None),
            1
        );
    }
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 4);
    for (category, outcome, role) in [
        (
            EventCategory::Authentication,
            EventOutcome::Failure,
            EntityRole::Source,
        ),
        (EventCategory::Iam, EventOutcome::Success, EntityRole::Actor),
        (
            EventCategory::Iam,
            EventOutcome::Success,
            EntityRole::Target,
        ),
    ] {
        let filter = GraphQueryFilter::default().with_common(CommonEventFilter {
            category: Some(category),
            outcome: Some(outcome),
            role: Some(role),
            ..Default::default()
        });
        assert_eq!(
            store
                .timeline_filtered(&case.id, &filter, 10)
                .unwrap()
                .len(),
            2
        );
    }
    verify_custody(
        &engine,
        store.as_ref(),
        &case.id,
        &originals,
        &root.path().join("synthetic.irmind"),
    );
}
fn verify_custody(
    engine: &Engine<'_>,
    store: &LocalStore,
    id: &irmind_domain::CaseId,
    originals: &std::path::Path,
    path: &std::path::Path,
) {
    let parser = current_sources::parser("parser-entra");
    LargeCaseUseCases {
        engine,
        store,
        parser: parser.as_ref(),
    }
    .verify_parquet_rebuild(id, originals, &CancellationToken::new())
    .unwrap();
    engine.verify(id).unwrap();
    engine.seal(id).unwrap();
    let key = irmind_app::export_case(engine, store, id, path, &CancellationToken::new()).unwrap();
    assert_eq!(
        irmind_infra::LocalExportVerifier
            .verify_export_details(path, Some(&key))
            .unwrap()
            .format_version,
        11
    );
}

#[cfg(feature = "sigma")]
#[expect(
    clippy::too_many_lines,
    reason = "exercise one signed case through its complete evidence path"
)]
#[test]
fn azure_decimal_projection_is_exact_in_signed_case_and_v10() {
    use irmind_app::{
        ReportDocumentFormat, ReportDocumentLanguage, v10_proofs::SIGMA_EVALUATOR_V5,
    };
    use serde_json::{Value, json};

    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    let rules = root.path().join("rules");
    fs::create_dir(&originals).unwrap();
    fs::create_dir(&rules).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store)
        .with_large_case_pipeline(store.clone(), current_sources::parser("parser-entra"));
    let case = engine
        .create_case("Synthetic decimal coverage", "local only")
        .unwrap();
    let cancel = CancellationToken::new();
    let mut row: Value = serde_json::from_slice(include_bytes!(
        "../../../testkit/fixtures/parser-entra/source/signin-table.ndjson"
    ))
    .unwrap();
    row["ResultType"] = json!("50053");
    let valid = row.to_string();
    row["ResultType"] = json!("Failure");
    row["Id"] = json!("synthetic-malformed-interactive");
    row["UserPrincipalName"] = json!("other-rule@example.invalid");
    let malformed = row.to_string();
    row["Type"] = json!("AADNonInteractiveUserSignInLogs");
    let noninteractive = row.to_string();
    assert_eq!(
        malformed.replace("\"SigninLogs\"", "\"AADNonInteractiveUserSignInLogs\""),
        noninteractive,
    );
    let raw = format!("{valid}\n{malformed}\n{noninteractive}\n");
    fs::write(originals.join("signin.ndjson"), &raw).unwrap();
    assert_eq!(
        ingest_with_context(&engine, &store, &case.id, &originals, "signin.ndjson", None),
        3
    );

    for (id, selection, condition) in [
        ("numeric", "ResultType: 50053", "selection"),
        ("negated", "ResultType: 50053", "not selection"),
        (
            "unaffected",
            "UserPrincipalName: other-rule@example.invalid",
            "selection",
        ),
        ("noninteractive-text", "ResultType: 'Failure'", "selection"),
    ] {
        fs::write(
            rules.join(format!("{id}.yml")),
            format!(
                "title: Synthetic {id}\nid: {id}\nlogsource: {{product: azure, service: signinlogs}}\ndetection:\n  selection: {{{selection}}}\n  condition: {condition}\n"
            ),
        )
        .unwrap();
    }
    let pack = irmind_infra::sigma_pack::inspect_local_sigma_pack(&rules, &cancel).unwrap();
    let manifest = pack.manifest.encode().unwrap();
    let metadata = br#"{"format_version":1,"name":"synthetic-azure","version":"1.0.0","license":"MIT","attribution":"Synthetic example"}"#;
    let mut bundle = b"irmind-sigma-package-v1\0".to_vec();
    bundle.extend((metadata.len() as u64).to_be_bytes());
    bundle.extend(metadata);
    bundle.extend((manifest.len() as u64).to_be_bytes());
    bundle.extend(&manifest);
    for raw in &pack.rules {
        bundle.extend(raw);
    }
    let activation = store
        .install_local_sigma_package(&engine, &bundle, irmind_app::sha256(&bundle), None, &cancel)
        .unwrap();
    let case_head = store.entries(&case.id).unwrap().last().unwrap().hash;
    let selection = irmind_app::v10_proofs::InstalledSigmaRunSelection {
        name: "synthetic-azure".into(),
        installation: activation.hash,
        case_head,
    };
    let instant = |text| {
        irmind_app::IndexedTime::from_rfc3339(text, false)
            .unwrap()
            .instant()
            .unix_micros()
    };
    let run = store
        .run_installed_sigma(
            &engine,
            &case.id,
            &selection,
            instant("2026-11-01T00:00:00Z")..instant("2026-11-01T00:01:00Z"),
            &cancel,
        )
        .unwrap();
    assert_eq!(run.receipt.evaluator, SIGMA_EVALUATOR_V5);
    assert_eq!(run.receipt.matched_rows, 4);
    assert_eq!(run.unavailable_by_source, [("signin.ndjson".into(), 1)]);
    assert_eq!(
        run.indeterminate_by_rule
            .iter()
            .map(|(rule, count)| (rule.id.as_str(), *count))
            .collect::<Vec<_>>(),
        [("negated", 1), ("numeric", 1)]
    );
    let findings = engine.findings(&case.id).unwrap();
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.value == "Synthetic unaffected")
            .count(),
        2
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.value == "Synthetic noninteractive-text")
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.value == "Synthetic negated")
    );

    let entries = store.entries(&case.id).unwrap();
    let admitted = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SigmaCaseRunAdmissionV1)
        .unwrap();
    irmind_app::v10_proofs::SigmaCaseRunAdmissionV1::verify_following_run(
        admitted,
        &run.receipt,
        irmind_app::sha256(&manifest),
    )
    .unwrap();
    engine
        .deactivate_sigma_package("synthetic-azure", activation.hash)
        .unwrap();
    fs::remove_dir_all(root.path().join("data").join("sigma-packs")).unwrap();
    let preview = store
        .preview_cited_report(&engine, &case.id, ReportDocumentLanguage::Spanish, &cancel)
        .unwrap();
    assert!(preview.markdown.contains("filas indeterminadas"));
    let plan = store
        .plan_cited_report(
            &engine,
            &case.id,
            ReportDocumentLanguage::Spanish,
            ReportDocumentFormat::Markdown,
            &cancel,
        )
        .unwrap();
    engine
        .publish_cited_report(&case.id, plan, &cancel)
        .unwrap();
    verify_custody(
        &engine,
        &store,
        &case.id,
        &originals,
        &root.path().join("azure.irmind"),
    );
}
