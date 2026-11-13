#![forbid(unsafe_code)]
#![cfg(all(
    feature = "parser-zeek",
    feature = "parser-suricata",
    feature = "parser-json"
))]
#![allow(clippy::unwrap_used)]
#[path = "support/current_sources.rs"]
mod current_sources;

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, Signer, StreamingEventParser, modules::ParserSelectionRequest,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, ParquetArtifactV3, SourceManifestV2};
use irmind_infra::{LocalVerifier, SystemClock};
use std::{collections::BTreeMap, fs, sync::Arc};
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
#[test]
#[allow(clippy::too_many_lines)]
fn detected_network_sources_write_precise_v3_and_reconstruct() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[48; 32])));
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine.create_case("Synthetic network V2", "local").unwrap();
    let catalog = current_sources::catalog();
    let sources: [(&str, &[u8]); 3] = [
        (
            "conn.log",
            include_bytes!("../../testkit/fixtures/parser-zeek/source/events.log"),
        ),
        (
            "dns.jsonl",
            include_bytes!("../../testkit/fixtures/parser-zeek/source/dns.jsonl"),
        ),
        (
            "eve.jsonl",
            include_bytes!("../../testkit/fixtures/parser-suricata/source/eve.jsonl"),
        ),
    ];
    for (name, bytes) in sources {
        let bytes = sensor_source(name, bytes);
        fs::write(originals.join(name), &bytes).unwrap();
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
        let selections = BTreeMap::from([(name.into(), selected.selection)]);
        let use_cases = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: selected.parser.as_ref(),
        };
        use_cases
            .ingest_local_batch_selected(
                &case.id,
                &originals,
                &[name.into()],
                false,
                &selections,
                &CancellationToken::new(),
            )
            .unwrap();
    }
    let entries = store.entries(&case.id).unwrap();
    let manifests = entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::SourceManifestV2)
        .map(|e| SourceManifestV2::decode(&e.payload).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(manifests.len(), 3);
    assert!(
        manifests
            .iter()
            .all(|m| m.confidence == 95 && !m.source.copied)
    );
    let artifacts = entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::ParquetArtifactV3)
        .map(|e| ParquetArtifactV3::decode(&e.payload).unwrap())
        .collect::<Vec<_>>();
    assert!(!artifacts.is_empty());
    assert!(
        !entries
            .iter()
            .any(|e| e.kind == AuditEventKind::ParquetArtifactV1)
    );
    let timeline = store.timeline(&case.id, 20).unwrap();
    assert_eq!(timeline.len(), 5);
    assert!(timeline.iter().all(|row| row.at.contains(".12345")));
    for parser in [
        &irmind_mod_parser_zeek::ZeekParser as &dyn StreamingEventParser,
        &irmind_mod_parser_suricata::SuricataParser as &dyn StreamingEventParser,
    ] {
        assert!(
            artifacts
                .iter()
                .any(|a| a.core().parser_id == parser.parser_name())
        );
    }
    engine.verify(&case.id).unwrap();
    assert!(
        artifacts
            .iter()
            .any(|a| a.core().partition.scopes.iter().any(|p| {
                p.key == irmind_domain::ScopePartitionKey::Host
                    && matches!(
            &p.value, irmind_domain::ScopePartitionValue::Ordinary(value) if value == "sensor-a")
            }))
    );
    let filter = irmind_domain::GraphQueryFilter::parse_with_host(
        None,
        None,
        None,
        None,
        None,
        Some("sensor-a"),
    )
    .unwrap();
    assert_eq!(
        store
            .timeline_filtered(&case.id, &filter, 20)
            .unwrap()
            .len(),
        3
    );
    let pinned = catalog.rebuild_router(&entries).unwrap();
    let rebuilt = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &pinned,
    }
    .verify_parquet_rebuild(&case.id, &originals, &CancellationToken::new())
    .unwrap();
    assert_eq!(rebuilt, 3);
}

fn sensor_source(name: &str, bytes: &[u8]) -> Vec<u8> {
    if name == "conn.log" {
        return bytes.to_vec();
    }
    let mut output = Vec::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let mut value: serde_json::Value = serde_json::from_slice(line).unwrap();
        value[if name == "dns.jsonl" {
            "sensor_host"
        } else {
            "host"
        }] = serde_json::json!("sensor-a");
        serde_json::to_writer(&mut output, &value).unwrap();
        output.push(b'\n');
    }
    output
}
