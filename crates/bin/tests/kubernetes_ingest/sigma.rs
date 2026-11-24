use super::*;
use irmind_app::{
    ExportVerifier, ReportDocumentFormat, ReportDocumentLanguage, sha256,
    v10_proofs::{SIGMA_EVALUATOR_V2, SigmaRunStatusV1},
};
use serde_json::{Value, json};

#[test]
fn forwarded_list_overflow_stays_in_custody_and_warns_in_the_signed_report() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    let rules = root.path().join("rules");
    fs::create_dir(&originals).unwrap();
    fs::create_dir(&rules).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let parser = current_sources::parser("parser-kubernetes");
    let engine = engine(&store).with_large_case_pipeline(store.clone(), parser);
    let case = engine
        .create_case("Synthetic audit coverage", "local only")
        .unwrap();
    let cancel = CancellationToken::new();

    let mut event: Value = serde_json::from_slice(include_bytes!(
        "../../../testkit/fixtures/parser-kubernetes/source/event.ndjson"
    ))
    .unwrap();
    event["sourceIPs"] = json!(["203.0.113.12"]);
    let first = event.to_string();
    event["auditID"] = Value::from("synthetic-audit-2");
    event["sourceIPs"] = json!((1..=33).map(|i| format!("192.0.2.{i}")).collect::<Vec<_>>());
    let raw = format!("{first}\n{event}\n");
    fs::write(originals.join("audit.ndjson"), &raw).unwrap();
    assert_eq!(
        ingest(&engine, &store, &case.id, &originals, "audit.ndjson"),
        2
    );
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 2);
    assert_eq!(
        fs::read_to_string(originals.join("audit.ndjson")).unwrap(),
        raw
    );

    fs::write(
        rules.join("source-ip.yml"),
        "title: Synthetic forwarded source\nlogsource: {product: kubernetes, service: audit}\ndetection: {selection: {'sourceIPs|cidr': '203.0.113.0/24'}, condition: selection}\n",
    ).unwrap();
    let pack = irmind_infra::sigma_pack::inspect_local_sigma_pack(&rules, &cancel).unwrap();
    let digest = sha256(&pack.manifest.encode().unwrap());
    store
        .admit_local_sigma_pack(&engine, &rules, digest, "MIT", &cancel)
        .unwrap();
    let instant = |text| {
        irmind_app::IndexedTime::from_rfc3339(text, false)
            .unwrap()
            .instant()
            .unix_micros()
    };
    let time = instant("2026-11-01T00:00:00Z")..instant("2026-11-01T00:01:00Z");
    let result = store
        .run_sigma(&engine, &case.id, digest, time, &cancel)
        .unwrap();
    assert_eq!(result.receipt.evaluator, SIGMA_EVALUATOR_V2);
    assert_eq!(
        result.receipt.status,
        SigmaRunStatusV1::ExactFieldsUnavailable
    );
    assert_eq!(result.receipt.matched_rows, 1);
    assert_eq!(result.unavailable_by_source, [("audit.ndjson".into(), 1)]);
    assert_eq!(result.indeterminate_by_rule.len(), 1);
    assert_eq!(result.indeterminate_by_rule[0].1, 1);

    let preview = store
        .preview_cited_report(&engine, &case.id, ReportDocumentLanguage::Spanish, &cancel)
        .unwrap();
    assert!(preview.markdown.contains("filas indeterminadas"));
    assert!(preview.markdown.contains("manipulación de la fuente"));
    assert!(!preview.markdown.contains("Synthetic forwarded source"));
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
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let target = root.path().join("retained-audit.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &target, &cancel).unwrap();
    let verified = irmind_infra::LocalExportVerifier
        .verify_export_details(&target, Some(&key))
        .unwrap();
    assert_eq!(verified.format_version, 10);
}
