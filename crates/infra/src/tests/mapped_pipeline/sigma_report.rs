use super::*;
use crate::sigma_pack::{evaluation::SigmaVariantPrograms, field_table::ReviewedSigmaFieldTable};
use irmind_app::{
    EntityDetails, FindingKind, ReportDocumentFormat, ReportDocumentLanguage,
    v10_proofs::{
        CaseCheckpointV1, ReportCitationsV1, SigmaFieldTableV1, SigmaRuleKeyV1,
        V10ArtifactReference, V10AuditReference, V10CheckpointView, V10Citation,
        V10FindingCitations, V10RowReference, V10SourceReference,
    },
};
use irmind_domain::{ArtifactSchemaV2, SourceManifestV2};
use std::time::{Duration, Instant};

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
        10
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
    let rule = b"title: Synthetic failed AWS sign in\nlogsource: {product: aws, service: cloudtrail}\ndetection: {selection: {Outcome: failure}, condition: selection}\n";
    let key = SigmaRuleKeyV1 {
        id: "synthetic-login".into(),
        sha256: sha256(rule),
    };
    let programs =
        SigmaVariantPrograms::compile(&table.variants[0], [(key, rule.as_slice())]).unwrap();
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
                matches.push(V10RowReference {
                    source,
                    artifact: artifact_ref,
                    physical_row,
                    record: common.origin().record(),
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(matches.len(), 1);
    matches[0]
}

fn cloudtrail_table() -> ReviewedSigmaFieldTable {
    ReviewedSigmaFieldTable::parse(&SigmaFieldTableV1 {
        id: "synthetic-cloudtrail".into(),
        version: "1".into(),
        toml: r#"
[[variants]]
product = "aws"
service = "cloudtrail"
parser_id = "parser-json"
parser_version = "json-source-v1"
mapping_id = "cloudtrail-tables"
mapping_version = "v1"
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
    })
    .unwrap()
}

fn digest(value: &str) -> [u8; 32] {
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}
