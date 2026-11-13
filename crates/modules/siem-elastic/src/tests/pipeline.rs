use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AuditLog as _, CryptoPorts, Engine, EnginePorts, EvidenceGraph as _, EvidenceStore as _,
    Signer, SourceMapper as _, modules::ModuleRegistry,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, ProposedCall};
use std::{collections::BTreeMap, sync::Arc};
struct SyntheticSigner(SigningKey);
impl Signer for SyntheticSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.0.sign(bytes).to_bytes().to_vec())
    }
}
const SOURCE: &str = r#"{"@timestamp":"2026-10-23T00:00:00.123456789Z","ecs":{"version":"9.5.0"},"event":{"category":["authentication"],"type":["start"],"outcome":"failure","action":"login"},"host":{"name":"synthetic-host"},"user":{"name":"alice","domain":"CORP-A","target":{"name":"bob","domain":"CORP-B"}},"source":{"ip":"203.0.113.77"},"destination":{"ip":"203.0.113.77"}}"#;
fn response() -> String {
    format!(
        r#"{{"timed_out":false,"_shards":{{"failed":0}},"hits":{{"hits":[{{"_index":"logs-synthetic","_id":"event-1","_source":{SOURCE}}}]}}}}"#
    )
}
#[test]
#[allow(clippy::too_many_lines)]
fn authorized_response_becomes_signed_mapped_evidence_and_queryable_roles() {
    let root = tempfile::tempdir().unwrap();
    let raw = response();
    let server = MockServer::start(vec![MockResponse::json(&raw)]).unwrap();
    let mut registry = ModuleRegistry::new();
    registry
        .register(
            Box::new(irmind_mod_mapping_ecs::EcsMapping::for_elastic().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(Box::new(server_port(&server)), &config())
        .unwrap();
    let catalog = registry.mapping_catalog().unwrap();
    let parser = Arc::new(
        catalog
            .decoder_selection("siem-elastic", "elastic-source-v1")
            .unwrap(),
    );
    let store =
        Arc::new(irmind_infra::LocalStore::open_mapped(root.path(), Arc::new(catalog)).unwrap());
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[91; 32])));
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(irmind_infra::LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(irmind_testkit::FixedClock::new(1_793_491_200)),
    )
    .unwrap()
    .with_large_case_pipeline(store.clone(), parser);
    let engine = registry.bind(engine).unwrap();
    let scope = "v1;sources=elastic-prod;accounts=123456789012;hosts=synthetic-host;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine
        .create_case("Synthetic Elastic response", scope)
        .unwrap();
    let args = BTreeMap::from([
        ("source".into(), "elastic-prod".into()),
        ("account".into(), "123456789012".into()),
        ("from".into(), "2026-10-23T00:00:00Z".into()),
        ("to".into(), "2026-10-23T23:59:59Z".into()),
        ("field".into(), "user".into()),
        ("operator".into(), "eq".into()),
        ("value".into(), "alice".into()),
    ]);
    let result = engine
        .request_tool_as_analyst(
            &case.id,
            ProposedCall {
                tool: Tool::SiemSearch,
                args,
            },
            &CancellationToken::new(),
        )
        .unwrap();
    if result.starts_with("approval pending:") {
        let approval = engine.pending_approvals(&case.id).unwrap().remove(0);
        engine.approve(&case.id, &approval.id).unwrap();
    } else {
        assert!(!result.starts_with("denied:"), "{result}");
    }
    assert_eq!(server.finish().unwrap().len(), 1);
    let entries = store.entries(&case.id).unwrap();
    for kind in [
        AuditEventKind::ToolResult,
        AuditEventKind::SourceManifestV2,
        AuditEventKind::SourceRecordSetV1,
        AuditEventKind::MappingRunV1,
        AuditEventKind::ParquetArtifactV3,
    ] {
        assert!(
            entries.iter().any(|entry| entry.kind == kind),
            "missing {kind:?}"
        );
    }
    let hash = irmind_app::hex(&irmind_app::sha256(raw.as_bytes()));
    assert_eq!(store.get_evidence(&case.id, &hash).unwrap(), raw.as_bytes());
    let filter = irmind_domain::GraphQueryFilter::from_args(&BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_outcome".into(), "failure".into()),
    ]))
    .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &filter, 20)
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .entity_lookup(&case.id, "ip", "203.0.113.77")
            .unwrap()
            .contains("observations=")
    );
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let export = root.path().join("synthetic-elastic.irmind");
    let key = irmind_app::export_case(
        &engine,
        store.as_ref(),
        &case.id,
        &export,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        irmind_app::ExportVerifier::verify_export_details(
            &irmind_infra::LocalExportVerifier,
            &export,
            Some(&key)
        )
        .unwrap()
        .format_version,
        7
    );
}
#[test]
fn fields_arrays_and_source_objects_use_the_same_validated_ecs_mapping() {
    for body in [response(), r#"{"hits":{"hits":[{"fields":{"@timestamp":["2026-10-23T00:00:00.123456789Z"],"event.category":["authentication"],"event.type":["start"],"event.outcome":["failure"],"user.name":["alice"],"source.ip":["203.0.113.77"]}}]}}"#.into()] {
        let source = irmind_domain::SourceReferenceV1::file("synthetic-response.json").unwrap();
        let cancel = CancellationToken::new();
        let report = irmind_app::SourceDecoder::decode_reader(&ElasticSourceDecoder, irmind_app::source_mapping::SourceInput {
            reader: &mut body.as_bytes(), metadata: irmind_app::source_mapping::SourceMetadata {
                cluster_context: None,
                source: &source, evidence_hash: irmind_app::sha256(body.as_bytes()), time_context: None, cancel: &cancel,
            },
        }, &mut |record| {
            record.inspect(|record| {
                let output = irmind_mod_mapping_ecs::EcsMapping::for_elastic().unwrap().map(record).unwrap();
                assert_eq!(output.record().common.event().outcome(), irmind_domain::EventOutcome::Failure);
                assert!(output.record().common.observations().values().iter().any(|o| o.role() == irmind_domain::EntityRole::Source));
                assert!(record.origin().offset().is_none());
            });
            Ok(())
        }).unwrap();
        assert_eq!((report.accepted, report.rejected), (1,0));
    }
}
