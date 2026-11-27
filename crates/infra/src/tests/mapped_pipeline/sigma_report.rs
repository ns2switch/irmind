use super::*;
use crate::sigma_pack::{evaluation::SigmaVariantPrograms, field_table::ReviewedSigmaFieldTable};
use irmind_app::{
    EntityDetails, FindingKind, ReportDocumentFormat, ReportDocumentLanguage,
    v10_proofs::{
        CaseCheckpointV1, ReportCitationsV1, SigmaFieldTableV1, SigmaRuleKeyV1, SigmaRunV2,
        V10ArtifactReference, V10AuditReference, V10CheckpointView, V10Citation,
        V10FindingCitations, V10RowReference, V10SigmaRunObjects, V10SourceReference,
    },
};
use irmind_domain::{ArtifactSchemaV2, SourceManifestV2};
use std::time::{Duration, Instant};

const SIGMA_RULE: &[u8] = b"title: Synthetic failed AWS sign in\nlogsource: {product: aws, service: cloudtrail}\ndetection: {selection: {Outcome: failure}, condition: selection}\n";
const FINDING: &str = "Synthetic failed AWS sign in found by Sigma";

#[test]
fn sigma_match_stays_out_of_cited_reports_until_analyst_confirms_the_exact_row() {
    let root = tempfile::tempdir().unwrap();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    );
    let (store, engine, catalog) = fixture_catalog(root.path(), catalog);
    let case = engine.create_case("Sigma review", "local only").unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    ingest_login_pair(&large, &case.id, root.path(), "aws.jsonl", &cancel);
    engine.verify(&case.id).unwrap();
    let row = scan(&store, &case.id, &cancel);
    let evidence = irmind_domain::EvidenceHash::from_bytes(row.source.evidence_sha256);
    let id = engine
        .add_entity(
            &case.id,
            FindingKind::Timeline,
            FINDING,
            evidence.as_str(),
            EntityDetails::Timeline {
                at: "2026-11-01T00:00:00Z".into(),
                source: "aws.jsonl".into(),
                record_index: Some(row.record.try_into().unwrap()),
            },
        )
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let proposed = entries.last().unwrap();
    let mut citations = ReportCitationsV1(vec![V10FindingCitations {
        finding_id: id.clone(),
        confirmation: reference(proposed),
        citations: vec![V10Citation::Row(row)],
    }]);
    assert!(render(&store, &engine, &case.id, &citations).is_err());
    assert!(!engine.report(&case.id).unwrap().contains(FINDING));
    let preview = store
        .preview_cited_report(&engine, &case.id, ReportDocumentLanguage::English, &cancel)
        .unwrap();
    assert_eq!(preview.omitted_findings, 0);
    assert!(!preview.markdown.contains(FINDING));

    let empty = render(&store, &engine, &case.id, &ReportCitationsV1(vec![])).unwrap();
    assert!(!String::from_utf8(empty).unwrap().contains(FINDING));

    engine.confirm_finding(&case.id, &id).unwrap();
    assert!(engine.report(&case.id).unwrap().contains(FINDING));
    let preview = store
        .preview_cited_report(&engine, &case.id, ReportDocumentLanguage::Spanish, &cancel)
        .unwrap();
    assert_eq!(preview.omitted_findings, 0);
    assert!(preview.markdown.contains(FINDING));
    assert!(preview.markdown.contains("Hallazgos confirmados"));
    assert!(
        preview
            .markdown
            .contains(&format!("{} · registro {}", evidence.as_str(), row.record))
    );

    let entries = store.entries(&case.id).unwrap();
    citations.0[0].confirmation = reference(entries.last().unwrap());
    let markdown = render(&store, &engine, &case.id, &citations).unwrap();
    let markdown = String::from_utf8(markdown).unwrap();
    assert!(markdown.contains(FINDING));
    assert!(markdown.contains("Source availability unknown"));
    assert!(markdown.contains(&format!("{} · record {}", evidence.as_str(), row.record)));
    citations.0[0].citations[0] = V10Citation::Row(V10RowReference {
        physical_row: row.physical_row + 1,
        ..row
    });
    assert!(render(&store, &engine, &case.id, &citations).is_err());
    verify_signed_reports(engine, &store, &case.id, root.path(), &cancel);
}

fn verify_signed_reports(
    engine: Engine<'_>,
    store: &Arc<LocalStore>,
    case: &CaseId,
    root: &Path,
    cancel: &CancellationToken,
) {
    use irmind_app::v10_proofs::{ReportAnalystSectionsV1, ReportCoverageV2};
    let engine = engine.with_large_case_pipeline(store.clone(), Arc::new(json_source_parser()));
    for (language, format) in [
        (
            ReportDocumentLanguage::English,
            ReportDocumentFormat::Markdown,
        ),
        (ReportDocumentLanguage::Spanish, ReportDocumentFormat::Pdf),
    ] {
        let mut plan = store
            .plan_cited_report(&engine, case, language, format, cancel)
            .unwrap();
        plan.analyst = Some(ReportAnalystSectionsV1([
            "Synthetic scope".into(),
            "Independently checked".into(),
            String::new(),
            String::new(),
        ]));
        let receipt = engine.publish_cited_report(case, plan, cancel).unwrap();
        let coverage = store
            .read_addressed_report_proof(case, 2, receipt.coverage, cancel)
            .unwrap();
        assert!(ReportCoverageV2::decode(&coverage).is_ok());
        let rendered = store
            .read_addressed_report_proof(case, 3, receipt.rendered_sha256, cancel)
            .unwrap();
        assert_eq!(sha256(&rendered), receipt.rendered_sha256);
        if format == ReportDocumentFormat::Pdf {
            assert!(rendered.starts_with(b"%PDF"));
        } else {
            assert!(String::from_utf8(rendered).unwrap().contains(FINDING));
        }
    }
    engine.verify(case).unwrap();
    engine.seal(case).unwrap();
    let path = root.join("signed-report.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), case, &path, cancel).unwrap();
    assert_eq!(
        LocalExportVerifier
            .verify_export_details(&path, Some(&key))
            .unwrap()
            .format_version,
        11
    );
    let mut tampered = fs::read(&path).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&path, tampered).unwrap();
    assert!(
        LocalExportVerifier
            .verify_export_details(&path, Some(&key))
            .is_err()
    );
}

fn ingest_login_pair(
    large: &LargeCaseUseCases<'_, '_>,
    case: &CaseId,
    root: &Path,
    source_file: &str,
    cancel: &CancellationToken,
) {
    let raw = include_bytes!("../../../../testkit/fixtures/common/cloudtrail-console-login.jsonl");
    let mut success: serde_json::Value = serde_json::from_slice(raw).unwrap();
    success["responseElements"]["ConsoleLogin"] = "Success".into();
    success["eventTime"] = "2026-11-01T00:00:01.123456Z".into();
    success["eventID"] = "synthetic-console-success".into();
    let mut source = raw.to_vec();
    serde_json::to_writer(&mut source, &success).unwrap();
    source.push(b'\n');
    fs::write(root.join(source_file), source).unwrap();
    large
        .ingest_local(case, root, source_file, false, cancel)
        .unwrap();
}

fn reference(entry: &irmind_app::SignedEntry) -> V10AuditReference {
    V10AuditReference {
        sequence: entry.seq,
        entry_sha256: entry.hash,
    }
}

fn checkpoint(id: &CaseId, entry: &irmind_app::SignedEntry) -> CaseCheckpointV1 {
    CaseCheckpointV1 {
        case_id: id.clone(),
        sequence: entry.seq,
        entry_hash: entry.hash,
    }
}

fn render(
    store: &LocalStore,
    engine: &Engine<'_>,
    case: &CaseId,
    citations: &ReportCitationsV1,
) -> Result<Vec<u8>, AppError> {
    let entries = store.entries(case).unwrap();
    let base = checkpoint(case, entries.last().unwrap());
    let root = store.parquet.owned_case_path(case);
    engine.render_cited_findings(
        case,
        &base,
        citations,
        ReportDocumentLanguage::English,
        ReportDocumentFormat::Markdown,
        |artifact, row| {
            let mut file =
                irmind_fs::open_regular_no_follow(&root, Path::new(artifact.path())).unwrap();
            crate::verify_v10_artifact_rows(
                &mut file,
                0,
                artifact,
                &[row],
                &CancellationToken::new(),
            )
        },
    )
}

fn scan(store: &LocalStore, case: &CaseId, cancel: &CancellationToken) -> V10RowReference {
    let entries = store.entries(case).unwrap();
    let base = checkpoint(case, entries.last().unwrap());
    let view = V10CheckpointView::resolve(&entries, &base).unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .unwrap();
    let manifest = SourceManifestV2::decode(&entry.payload).unwrap();
    let source_digest = digest(manifest.source.sha256.as_str());
    let source = V10SourceReference {
        manifest: reference(entry),
        evidence_sha256: source_digest,
    };
    let (artifact, entry) = entries
        .iter()
        .find_map(|entry| {
            let artifact = ParquetArtifact::decode(entry.kind, &entry.payload).ok()?;
            let ParquetArtifact::V3(value) = &artifact;
            (value.core().schema == ArtifactSchemaV2::CommonEvents).then_some((artifact, entry))
        })
        .unwrap();
    let artifact_ref = V10ArtifactReference {
        entry: reference(entry),
        artifact_sha256: digest(artifact.sha256().as_str()),
    };
    let artifact = view.artifact(source, artifact_ref).unwrap();
    let ParquetArtifact::V3(envelope) = &artifact;
    assert_eq!(envelope.pipeline().rows(), 2);
    let root = store.parquet.owned_case_path(case);
    let mut file = irmind_fs::open_regular_no_follow(&root, Path::new(artifact.path())).unwrap();
    crate::verify_v10_artifact_rows(&mut file, 0, &artifact, &[], cancel).unwrap();
    let table = cloudtrail_table();
    let rule = SIGMA_RULE;
    let key = SigmaRuleKeyV1 {
        id: "synthetic-login".into(),
        sha256: sha256(rule),
    };
    let programs =
        SigmaVariantPrograms::compile(&table.variants[0], [(key.clone(), rule)]).unwrap();
    let mut evaluation = programs.start(10_000);
    let mut matches = Vec::new();
    evaluation
        .scan_authenticated(
            file,
            0..i64::MAX,
            Instant::now() + Duration::from_secs(10),
            cancel,
            |physical_row, common, _| {
                assert_eq!(common.origin().source(), &manifest.source.sha256);
                matches.push((
                    V10RowReference {
                        source,
                        artifact: artifact_ref,
                        physical_row,
                        record: common.origin().record(),
                    },
                    common.clone(),
                ));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(matches.len(), 1);
    let (row, event) = &matches[0];
    verify_sigma_case_references(&entries, &base, *row, key.clone(), &root, cancel);
    verify_sigma_v3_binding(&entries, &base, &artifact, *row, event, key, cancel);
    *row
}

fn verify_sigma_v3_binding(
    entries: &[SignedEntry],
    checkpoint: &CaseCheckpointV1,
    artifact: &ParquetArtifact,
    row: V10RowReference,
    event: &irmind_domain::CommonEventV1,
    rule: SigmaRuleKeyV1,
    cancel: &CancellationToken,
) {
    use crate::sigma_pack::{SigmaMatchCheck, verify_class_plan};

    let (receipt, mut materials) = sigma_case_row_proofs(checkpoint, row, rule.clone(), cancel);
    let table = ReviewedSigmaFieldTable::parse(&materials.field_table).unwrap();
    let rules = [(rule, SIGMA_RULE)];
    let deadline = Instant::now() + Duration::from_secs(5);
    verify_class_plan(
        &receipt, &materials, &table, entries, &rules, deadline, cancel,
    )
    .unwrap();
    SigmaMatchCheck::new(&table, &materials, &rules, deadline, 10_000, cancel)
        .check(artifact, row, event, "{}")
        .unwrap();

    materials.compiled_rules.0[0].variants.clear();
    assert!(
        verify_class_plan(
            &receipt, &materials, &table, entries, &rules, deadline, cancel
        )
        .is_err()
    );
    assert!(
        SigmaMatchCheck::new(&table, &materials, &rules, deadline, 10_000, cancel)
            .check(artifact, row, event, "{}")
            .is_err()
    );
}

fn verify_sigma_case_references(
    entries: &[SignedEntry],
    checkpoint: &CaseCheckpointV1,
    row: V10RowReference,
    rule: SigmaRuleKeyV1,
    root: &Path,
    cancel: &CancellationToken,
) {
    let (mut receipt, mut objects) = sigma_case_row_proofs(checkpoint, row, rule, cancel);
    let verify = |objects: &V10SigmaRunObjects, receipt: &SigmaRunV2| {
        objects.verify_case_rows(
            entries,
            receipt,
            |artifact, rows| {
                let mut file =
                    irmind_fs::open_regular_no_follow(root, Path::new(artifact.path())).unwrap();
                crate::verify_v10_artifact_rows(&mut file, 0, artifact, rows, cancel)
            },
            cancel,
        )
    };
    verify(&objects, &receipt).unwrap();
    receipt.checkpoint.entry_hash[0] ^= 1;
    assert!(verify(&objects, &receipt).is_err());
    receipt.checkpoint.entry_hash[0] ^= 1;
    objects.results.matches[0].row.physical_row += 1;
    assert!(verify(&objects, &receipt).is_err());
}

fn sigma_case_row_proofs(
    checkpoint: &CaseCheckpointV1,
    row: V10RowReference,
    rule: SigmaRuleKeyV1,
    cancel: &CancellationToken,
) -> (SigmaRunV2, V10SigmaRunObjects) {
    use irmind_app::v10_proofs::{
        SIGMA_EVALUATOR_V5, SigmaAdmissionMode, SigmaClassOutcome, SigmaClassPlan,
        SigmaCompiledRuleV1, SigmaCompiledRulesV1, SigmaCoverageV1, SigmaMatchV1,
        SigmaRuleCoverageV1, SigmaRunResultsV1, SigmaRunResultsV2, SigmaRunResultsV3,
        SigmaRunStatusV1, SigmaSourceScopeV1, V10ProofDescriptor, V10ProofFamily,
        v10_proof_commitment,
    };
    let mut plan = SigmaClassPlan::new(vec![0], 1).unwrap();
    plan.set(0, 0, SigmaClassOutcome::Eligible).unwrap();
    let objects = V10SigmaRunObjects {
        class_plan: plan,
        field_table: cloudtrail_definition(),
        selected_sources: SigmaSourceScopeV1(vec![row.source]),
        compiled_rules: SigmaCompiledRulesV1(vec![SigmaCompiledRuleV1 {
            rule: rule.clone(),
            variants: vec![0],
        }]),
        unavailable_by_source: vec![],
        indeterminate_by_rule: vec![],
        results: SigmaRunResultsV1 {
            coverage: vec![SigmaRuleCoverageV1 {
                rule: rule.clone(),
                status: SigmaCoverageV1::Eligible,
                detail: None,
            }],
            matches: vec![SigmaMatchV1 {
                rule: rule.clone(),
                row,
                query_limit: None,
            }],
        },
    };
    let family = V10ProofFamily::Sigma;
    let bodies = [
        (2, objects.field_table.encode().unwrap()),
        (3, objects.selected_sources.encode().unwrap()),
        (4, objects.compiled_rules.encode().unwrap()),
        (
            5,
            SigmaRunResultsV3 {
                plan: objects.class_plan,
                scan: SigmaRunResultsV2 {
                    results: objects.results,
                    unavailable_by_source: objects.unavailable_by_source,
                    indeterminate_by_rule: objects.indeterminate_by_rule,
                },
            }
            .encode()
            .unwrap(),
        ),
    ];
    let descriptors = std::array::from_fn::<_, 4, _>(|index| {
        let (kind, bytes) = &bodies[index];
        V10ProofDescriptor::from_body(family, *kind, bytes).unwrap()
    });
    let receipt = SigmaRunV2 {
        checkpoint: checkpoint.clone(),
        pack_admission: [0; 32],
        artifact_inventory: [0; 32],
        selected_sources: descriptors[1].hash(),
        start_utc_micros: 0,
        end_utc_micros: i64::MAX,
        compiled_rules: descriptors[2].hash(),
        field_table: descriptors[0].hash(),
        evaluator: SIGMA_EVALUATOR_V5.into(),
        admission_mode: SigmaAdmissionMode::DirectLocal,
        reserved_units: 1024,
        used_units: 8,
        status: SigmaRunStatusV1::Complete,
        matched_rows: 1,
        result_manifest: descriptors[3].hash(),
        proof_set: v10_proof_commitment(family, &descriptors).unwrap(),
    };
    let checked = load_sigma_case_row_proofs(&receipt, &bodies, &descriptors, rule, cancel);
    (receipt, checked)
}

fn load_sigma_case_row_proofs(
    receipt: &SigmaRunV2,
    bodies: &[(u8, Vec<u8>); 4],
    descriptors: &[irmind_app::v10_proofs::V10ProofDescriptor; 4],
    rule: SigmaRuleKeyV1,
    cancel: &CancellationToken,
) -> V10SigmaRunObjects {
    use irmind_app::v10_proofs::{
        SigmaPackManifestV1, SigmaPackRuleV1, V10ObjectSection, V10ProofFamily, read_v10_sigma_run,
        write_v10_object_section,
    };
    let family = V10ProofFamily::Sigma;
    let mut section = Vec::new();
    write_v10_object_section(
        &mut section,
        family,
        descriptors,
        |descriptor| Ok(bodies[usize::from(descriptor.kind() - 2)].1.as_slice()),
        cancel,
    )
    .unwrap();
    let mut section = std::io::Cursor::new(section);
    let section_index = V10ObjectSection::scan(&mut section, family, cancel).unwrap();
    let mut referenced = std::collections::BTreeSet::new();
    let admitted = SigmaPackManifestV1(vec![SigmaPackRuleV1 {
        path: "login.yml".into(),
        rule,
        version: None,
        author: None,
        size: 1,
    }]);
    let checked = read_v10_sigma_run(
        &section_index,
        &mut section,
        receipt,
        &admitted,
        &mut referenced,
        cancel,
    )
    .unwrap();
    section_index.check_union(&referenced).unwrap();
    checked
}

fn cloudtrail_table() -> ReviewedSigmaFieldTable {
    ReviewedSigmaFieldTable::parse(&cloudtrail_definition()).unwrap()
}

fn cloudtrail_definition() -> SigmaFieldTableV1 {
    SigmaFieldTableV1 {
        id: "synthetic-cloudtrail".into(),
        version: "1".into(),
        toml: r#"
[[variants]]
product = "aws"
service = "cloudtrail"
parser_id = "parser-json"
parser_version = "json-source-v1"
mapping_id = "mapping-cloudtrail"
mapping_version = "cloudtrail-tables-v1"
dataset = "cloudtrail"
[[variants.events]]
column = "event.action"
equals = "ConsoleLogin"
[[variants.fields]]
name = "Outcome"
column = "event.outcome"
value_type = "text"
null_policy = "absent"
"#
        .into(),
    }
}

fn digest(value: &str) -> [u8; 32] {
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

#[test]
fn signed_sigma_run_and_admitted_rules_verify_in_the_actual_sealed_v10_export() {
    let root = tempfile::tempdir().unwrap();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    );
    let (store, engine, catalog) = fixture_catalog(root.path(), catalog);
    let engine = engine.with_large_case_pipeline(store.clone(), Arc::new(json_source_parser()));
    let case = engine
        .create_case("Signed Sigma run", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    ingest_login_pair(&large, &case.id, root.path(), "aws.jsonl", &cancel);
    let pack = admit_test_sigma_pack(&store, &engine, root.path(), &cancel);
    let time = |text| {
        irmind_app::IndexedTime::from_rfc3339(text, false)
            .unwrap()
            .instant()
            .unix_micros()
    };
    let range = time("2026-11-01T00:00:00Z")..time("2026-11-01T00:00:02Z");
    let receipt = store
        .run_sigma(&engine, &case.id, pack, range, &cancel)
        .unwrap();
    assert_eq!(receipt.receipt.matched_rows, 1);
    assert_eq!(receipt.skipped_rules, 1);
    assert_eq!(receipt.class_coverage.no_rules, 1);
    assert_eq!(
        receipt.receipt.status,
        irmind_app::v10_proofs::SigmaRunStatusV1::CoverageLimited
    );
    assert_signed_coverage_notices(&store, &engine, &case.id, &cancel);
    let findings = engine.findings(&case.id).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(!findings[0].confirmed);
    let plan = store
        .plan_cited_report(
            &engine,
            &case.id,
            ReportDocumentLanguage::English,
            ReportDocumentFormat::Markdown,
            &cancel,
        )
        .unwrap();
    engine
        .publish_cited_report(&case.id, plan, &cancel)
        .unwrap();
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let package = root.path().join("sigma-executed.irmind");
    let key =
        irmind_app::export_case(&engine, store.as_ref(), &case.id, &package, &cancel).unwrap();
    let result = LocalExportVerifier
        .verify_export_details(&package, Some(&key))
        .unwrap();
    assert_eq!(result.format_version, 11);
    let mut bytes = fs::read(&package).unwrap();
    let rule = bytes
        .windows(SIGMA_RULE.len())
        .position(|bytes| bytes == SIGMA_RULE)
        .unwrap();
    bytes[rule] ^= 1;
    fs::write(&package, bytes).unwrap();
    assert!(
        LocalExportVerifier
            .verify_export_details(&package, Some(&key))
            .is_err()
    );
}

fn assert_signed_coverage_notices(
    store: &LocalStore,
    engine: &Engine<'_>,
    case: &CaseId,
    cancel: &CancellationToken,
) {
    let preview = store
        .preview_cited_report(engine, case, ReportDocumentLanguage::English, cancel)
        .unwrap();
    assert!(preview.markdown.contains("remains undetermined"));
    assert!(preview.markdown.contains(r"aws \/ cloudtrail \/"));
    assert!(preview.markdown.contains("1 missing bindings"));
    let notices = engine
        .verify_with_mapping_and_query_notices(case, cancel)
        .unwrap();
    let notice = &notices.sigma_runs[0];
    assert_eq!(notice.coverage.skipped_pairs, 1);
    assert_eq!(notice.skipped_classes[0].1, 1);
    assert!(notice.skipped_classes[0].0.contains("aws / cloudtrail /"));
}

fn admit_test_sigma_pack(
    store: &LocalStore,
    engine: &Engine<'_>,
    root: &Path,
    cancel: &CancellationToken,
) -> [u8; 32] {
    let rules = root.join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("auth.yml"), SIGMA_RULE).unwrap();
    fs::write(
        rules.join("unsupported.yml"),
        "title: Synthetic missing cloud field\nlogsource: {product: aws, service: cloudtrail}\ndetection: {selection: {SyntheticMissing: test}, condition: selection}\n",
    ).unwrap();
    let preview = crate::sigma_pack::inspect_local_sigma_pack(&rules, cancel).unwrap();
    let digest = sha256(&preview.manifest.encode().unwrap());
    store
        .admit_local_sigma_pack(engine, &rules, digest, "MIT", cancel)
        .unwrap();
    digest
}

fn write_failed_deliveries(originals: &Path) -> Vec<String> {
    fs::create_dir(originals).unwrap();
    let raw = include_bytes!("../../../../testkit/fixtures/common/cloudtrail-console-login.jsonl");
    let mut event: serde_json::Value = serde_json::from_slice(raw).unwrap();
    (0..4)
        .map(|source| {
            let name = format!("aws-{source}.json");
            event["sourceIPAddress"] = format!("203.0.113.{source}").into();
            event["eventID"] = format!("synthetic-console-failure-{source}").into();
            let delivery = serde_json::json!({ "Records": [&event] });
            let bytes = serde_json::to_vec(&delivery).unwrap();
            fs::write(originals.join(&name), bytes).unwrap();
            name
        })
        .collect()
}

#[test]
fn sigma_v3_signed_proofs_are_identical_across_ingest_worker_caps() {
    use irmind_testkit::FixedClock;
    use std::num::NonZeroU16;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let originals = root.join("originals");
    let paths = write_failed_deliveries(&originals);
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    );
    let seed = root.join("seed");
    let (_, engine, _) = fixture_catalog(&seed, catalog.clone());
    let case = engine
        .create_case("Sigma worker determinism", "local only")
        .unwrap();
    drop(engine);
    let clock = Arc::new(FixedClock::new(1_793_491_200));
    let cancel = CancellationToken::new();
    let mut expected = None;
    for cap in [1, 4] {
        let directory = root.join(format!("workers-{cap}"));
        fs::create_dir(&directory).unwrap();
        fs::copy(seed.join("irmind.db"), directory.join("irmind.db")).unwrap();
        let (store, engine, catalog) =
            fixture_with_clock(&directory, catalog.clone(), clock.clone());
        let engine = engine.with_large_case_pipeline(store.clone(), Arc::new(json_source_parser()));
        store.set_parallel_worker_limit(NonZeroU16::new(cap));
        let parser = catalog
            .decoder_selection("parser-json", "json-source-v1")
            .unwrap();
        let large = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &parser,
        };
        assert_eq!(
            large
                .ingest_local_batch(&case.id, &originals, &paths, false, &cancel)
                .unwrap()
                .len(),
            4
        );
        let pack = admit_test_sigma_pack(&store, &engine, &directory, &cancel);
        let run = store
            .run_sigma(&engine, &case.id, pack, 0..i64::MAX, &cancel)
            .unwrap();
        assert_eq!(run.receipt.matched_rows, 4);
        engine.verify(&case.id).unwrap();
        let entries = store.entries(&case.id).unwrap();
        let execution = entries
            .iter()
            .position(|entry| entry.kind == AuditEventKind::SigmaRunV2)
            .unwrap();
        // Finding drafts have independent UUIDs. Compare the entire signed
        // prefix through the run, which commits the exact rows and class plan.
        let hashes = entries[..=execution]
            .iter()
            .map(|entry| entry.hash)
            .collect::<Vec<_>>();
        let actual = (run.receipt.encode().unwrap(), hashes);
        if let Some(expected) = &expected {
            assert_eq!(&actual, expected);
        } else {
            expected = Some(actual);
        }
    }
}
