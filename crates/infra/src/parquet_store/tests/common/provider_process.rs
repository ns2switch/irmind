use super::*;
use irmind_app::{
    AuditLog, CryptoPorts, Engine, EnginePorts, ExportVerifier, LargeCaseUseCases, ParserSelection,
    SourceDecoder,
    source_mapping::{
        DecodeBudget, MappingCatalog, SourceDecoderSelection, SourceFormatV1, SourceInput,
        SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source},
    },
};
use irmind_domain::{
    Actor, ExecutionMode, IndexedInstant, IndexedTime, ParserSelectionMode, TimePrecision,
};
use std::sync::Arc;

struct SyntheticFdrDecoder;
impl SourceDecoder for SyntheticFdrDecoder {
    fn identity(&self) -> irmind_app::ParserIdentity<'_> {
        irmind_app::ParserIdentity {
            name: "parser-fdr",
            version: "fdr-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(irmind_domain::Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<irmind_app::ParseReport, AppError> {
        decode_json_source(
            input,
            self.identity(),
            DecodeBudget::sequential(),
            &|fields| {
                let bad = || AppError::Fixed(irmind_app::FixedAppError::SourceFormat);
                let millis = fields
                    .field("timestamp")
                    .and_then(SourceValue::as_text)
                    .ok_or_else(bad)?
                    .parse::<i64>()
                    .map_err(|_| bad())?;
                let instant = IndexedInstant::new(millis.checked_mul(1000).ok_or_else(bad)?, 0)
                    .map_err(|_| bad())?;
                Ok(DecodedSourceFrame {
                    fields,
                    timestamp: Some(
                        IndexedTime::new(instant, TimePrecision::Millisecond, false)
                            .map_err(|_| bad())?,
                    ),
                    format: SourceFormatV1::try_new("falcon-fdr", "fdr-source-v1", BTreeMap::new())
                        .map_err(|_| bad())?,
                })
            },
            emit,
        )
    }
}
fn catalog() -> Arc<MappingCatalog> {
    let text = include_str!("../../../../../testkit/fixtures/common/fdr/provider-process.toml");
    let manifest = irmind_mapping_tables::TableMapping::review(text).unwrap();
    Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(SyntheticFdrDecoder)],
            vec![Arc::new(
                irmind_mapping_tables::TableMapping::bundled(
                    text,
                    manifest.identity().implementation(),
                )
                .unwrap(),
            )],
        )
        .unwrap(),
    )
}
#[test]
#[allow(clippy::too_many_lines)]
fn provider_process_namespaces_survive_parquet_compaction_rebuild_and_export() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let host = "00000000000000000000000000000100";
    let tenant = "00000000000000000000000000000001";
    let other = "00000000000000000000000000000002";
    let rows = [
        serde_json::json!({"event_simpleName":"NetworkConnectIP4","timestamp":"1794918896000","cid":tenant,"aid":host,"ContextProcessId":"42","RemoteAddressIP4":"203.0.113.1"}),
        serde_json::json!({"event_simpleName":"NetworkConnectIP4","timestamp":"1794918897000","cid":tenant,"aid":host,"ContextProcessId":"42","RemoteAddressIP4":"203.0.113.2"}),
        serde_json::json!({"event_simpleName":"NetworkConnectIP4","timestamp":"1794918898000","cid":other,"aid":host,"ContextProcessId":"42","RemoteAddressIP4":"203.0.113.3"}),
    ];
    let mut selections = BTreeMap::new();
    let mut paths = Vec::new();
    for (index, row) in rows.into_iter().enumerate() {
        let name = format!("synthetic-{index}.ndjson");
        let bytes = serde_json::to_vec(&row).unwrap();
        fs::write(originals.join(&name), &bytes).unwrap();
        selections.insert(
            name.clone(),
            ParserSelection {
                parser_id: "parser-fdr".into(),
                parser_version: "fdr-source-v1".into(),
                confidence: 98,
                mode: ParserSelectionMode::Analyst,
                timestamp_context: None,
                cluster_context: None,
                format_sample_sha256: irmind_app::sha256(&bytes),
            },
        );
        paths.push(name);
    }
    let store =
        Arc::new(crate::LocalStore::open_mapped(&root.path().join("data"), catalog()).unwrap());
    let signer = Arc::new(crate::LocalSigner {
        key: ed25519_dalek::SigningKey::from_bytes(&[88; 32]),
        actor: Actor::Analyst,
    });
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(crate::LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        )
        .with_source_evidence_reader(store.source_evidence_reader()),
        ExecutionMode::Attended,
        Arc::new(crate::SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("Synthetic provider process namespaces", "local only")
        .unwrap();
    let parser = SourceDecoderSelection::new(Arc::new(SyntheticFdrDecoder));
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    for path in &paths {
        large
            .ingest_local_batch_selected(
                &case.id,
                &originals,
                std::slice::from_ref(path),
                false,
                &selections,
                &cancel,
            )
            .unwrap();
    }
    let entries = store.entries(&case.id).unwrap();
    let artifacts = irmind_app::artifact_catalog(&entries).unwrap().active;
    let names = entries
        .iter()
        .filter(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .map(|e| {
            let manifest = irmind_domain::SourceManifestV2::decode(&e.payload).unwrap();
            (
                manifest.source.sha256.as_str().to_owned(),
                manifest.source.source,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let query = store.parquet.queries(&names);
    let filter = GraphQueryFilter::default();
    let before = query
        .entity_native(&case.id, &artifacts, &filter, "process", "42", &cancel)
        .unwrap();
    assert!(before.contains("provider_process"));
    let connected = query
        .path_native(
            &case.id,
            &artifacts,
            &filter,
            ("ip", "203.0.113.1"),
            ("ip", "203.0.113.2"),
            &cancel,
        )
        .unwrap();
    assert!(!connected.contains("no co-observation path"), "{connected}");
    let separate = query
        .path_native(
            &case.id,
            &artifacts,
            &filter,
            ("ip", "203.0.113.1"),
            ("ip", "203.0.113.3"),
            &cancel,
        )
        .unwrap();
    assert!(separate.contains("no co-observation path"), "{separate}");
    assert!(
        large
            .compact_case_with_threshold(&case.id, 2, &cancel)
            .unwrap()
            > 0
    );
    let active = irmind_app::artifact_catalog(&store.entries(&case.id).unwrap())
        .unwrap()
        .active;
    assert_eq!(
        before,
        query
            .entity_native(&case.id, &active, &filter, "process", "42", &cancel)
            .unwrap()
    );
    assert_eq!(
        separate,
        query
            .path_native(
                &case.id,
                &active,
                &filter,
                ("ip", "203.0.113.1"),
                ("ip", "203.0.113.3"),
                &cancel
            )
            .unwrap()
    );
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, &originals, &cancel)
            .unwrap(),
        3
    );
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let export = root.path().join("synthetic.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &export, &cancel).unwrap();
    assert_eq!(
        crate::LocalExportVerifier
            .verify_export_details(&export, Some(&key))
            .unwrap()
            .format_version,
        11
    );
}
