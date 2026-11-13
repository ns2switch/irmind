use super::*;
use irmind_app::source_mapping::{SourceInput, SourceRecordV1};
use irmind_app::{LogParser, ParseReport, ParserIdentity, SourceClusterContext};
use irmind_domain::{
    ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding, Tainted,
};

struct ContextDecoder;
impl SourceDecoder for ContextDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let identity = input
            .metadata
            .cluster_context
            .ok_or_else(|| AppError::Policy("synthetic source requires cluster context".into()))?
            .resolve(None)
            .map_err(|_| AppError::RemoteTool)?
            .clone();
        JsonSourceDecoder.decode_reader(input, &mut |record| {
            emit(
                record
                    .with_cluster_identity(identity.clone())
                    .map_err(|_| AppError::RemoteTool)?,
            )
        })
    }
}
fn context() -> SourceClusterContext {
    SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(
            ClusterIdentity::try_new(ClusterProvider::Kubernetes, "urn:k8s:synthetic").unwrap(),
            ClusterContextBasis::Analyst,
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}
#[test]
fn signed_cluster_context_survives_reconstruction_sealing_and_public_export_verification() {
    let root = tempfile::tempdir().unwrap();
    let catalog = Arc::new(MappingCatalog::freeze(vec![Arc::new(ContextDecoder)], vec![]).unwrap());
    let (store, engine, catalog) = fixture_catalog(root.path(), catalog);
    let case = engine
        .create_case("Synthetic acquisition context", "local only")
        .unwrap();
    let context = context();
    let selected = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap()
        .with_cluster_context(&context)
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: selected.as_ref(),
    };
    let raw = br#"{"eventTime":"2026-11-01T00:00:00Z","sourceIPAddress":"203.0.113.77"}"#;
    fs::write(root.path().join("synthetic.json"), raw).unwrap();
    let cancel = CancellationToken::new();
    let selection = ParserSelection {
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        confidence: 90,
        mode: ParserSelectionMode::Analyst,
        timestamp_context: None,
        cluster_context: Some(context.clone()),
        format_sample_sha256: sha256(raw),
    };
    large
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["synthetic.json".into()],
            false,
            &BTreeMap::from([("synthetic.json".into(), selection)]),
            &cancel,
        )
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let manifest = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::SourceManifestV2)
        .unwrap();
    assert_eq!(
        irmind_domain::SourceManifestV2::decode(&manifest.payload)
            .unwrap()
            .cluster_context,
        Some(context.clone())
    );
    let set = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::SourceRecordSetV1)
        .unwrap();
    assert_eq!(
        irmind_domain::SourceRecordSetV1::decode(&set.payload)
            .unwrap()
            .cluster_context(),
        Some(&context)
    );
    engine.verify(&case.id).unwrap();
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, root.path(), &cancel)
            .unwrap(),
        1
    );
    engine.seal(&case.id).unwrap();
    let target = root.path().join("cluster.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &target, &cancel).unwrap();
    assert_eq!(
        LocalExportVerifier
            .verify_export_details(&target, Some(&key))
            .unwrap()
            .format_version,
        7
    );
}

mod queries;
