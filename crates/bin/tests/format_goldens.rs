#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![cfg(all(
    feature = "parser-json",
    feature = "parser-ecs",
    feature = "parser-ocsf",
    feature = "parser-velociraptor",
    feature = "parser-hayabusa",
    feature = "parser-chainsaw",
    feature = "parser-plaso",
    feature = "parser-eztools",
    feature = "parser-declarative"
))]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CaseMutation, Clock, ConfigChange, ConfigurationStore,
    CryptoPorts, Engine, EnginePorts, LargeCaseStore, PersistentConfig, SignedEntry, Signer,
    SourceDecoder, hex, sha256,
};
use irmind_domain::{Actor, AuditEventKind, Case, CaseId, ExecutionMode, Severity};
use irmind_infra::{LocalStore, LocalVerifier, ParquetStore, TomlConfigurationStore};
use std::{collections::BTreeMap, fs, sync::Arc};

type Goldens = BTreeMap<String, String>;

#[path = "support/artifact_v2_goldens.rs"]
mod artifact_v2_goldens;
#[path = "support/common_event_goldens.rs"]
mod common_event_goldens;

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<u64, AppError> {
        Ok(1_792_756_800)
    }
}

struct FixedSigner(SigningKey);
impl Signer for FixedSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

fn record(out: &mut Goldens, name: &str, bytes: &[u8]) {
    assert!(out.insert(format!("{name}/bytes"), hex(bytes)).is_none());
    assert!(
        out.insert(format!("{name}/sha256"), hex(&sha256(bytes)))
            .is_none()
    );
}

fn decoders() -> Vec<(&'static str, Arc<dyn SourceDecoder>, &'static [u8])> {
    vec![
        (
            "json",
            Arc::new(irmind_mod_parser_json::JsonSourceDecoder),
            include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"),
        ),
        (
            "ecs",
            Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-ecs/source/events.ndjson"),
        ),
        (
            "ocsf",
            Arc::new(irmind_mod_parser_ocsf::OcsfSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-ocsf/source/events.ndjson"),
        ),
        (
            "velociraptor",
            Arc::new(irmind_mod_parser_velociraptor::VelociraptorSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-velociraptor/source/events.jsonl"),
        ),
        (
            "hayabusa",
            Arc::new(irmind_mod_parser_hayabusa::HayabusaSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-hayabusa/source/events.jsonl"),
        ),
        (
            "chainsaw",
            Arc::new(irmind_mod_parser_chainsaw::ChainsawSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-chainsaw/source/events.jsonl"),
        ),
        (
            "plaso",
            Arc::new(irmind_mod_parser_plaso::PlasoSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-plaso/source/events.jsonl"),
        ),
        (
            "eztools",
            Arc::new(irmind_mod_parser_eztools::EztoolsSourceDecoder),
            include_bytes!("../../testkit/fixtures/parser-eztools/source/events.csv"),
        ),
        (
            "declarative",
            irmind_app::DefinitionCompiler::compile(
                &irmind_mod_parser_declarative::DeclarativeCompiler,
                include_str!("../../../docs/examples/parsers/nested-ndjson.toml"),
            )
            .unwrap()
            .decoder()
            .clone(),
            include_bytes!("../../testkit/fixtures/parser-declarative/source/events.ndjson"),
        ),
    ]
}

type Relation = (String, String, String, String, String);
type Row = (
    usize,
    String,
    String,
    String,
    Vec<(String, String)>,
    Vec<Relation>,
);

fn normalized_rows(
    parser: &dyn SourceDecoder,
    source: &str,
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Vec<Row> {
    let mut rows = Vec::new();
    let mapping = irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap();
    let source_ref = irmind_domain::SourceReferenceV1::file(source).unwrap();
    parser
        .decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    source: &source_ref,
                    evidence_hash: sha256(bytes),
                    time_context: None,
                    cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |row| {
                row.inspect(|raw| {
                    let mapped = irmind_app::SourceMapper::map(&mapping, raw).unwrap();
                    let row = &mapped.record().indexed.record;
                    rows.push((
                        row.index,
                        row.at.clone(),
                        row.event.clone(),
                        row.text.clone(),
                        row.entities.clone(),
                        row.relations
                            .iter()
                            .map(|r| {
                                (
                                    r.from_kind.clone(),
                                    r.from_value.clone(),
                                    r.relation.clone(),
                                    r.to_kind.clone(),
                                    r.to_value.clone(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    ));
                });
                Ok(())
            },
        )
        .unwrap();
    rows
}

fn parser_goldens(out: &mut Goldens) {
    one_parser_golden(
        out,
        "json",
        &irmind_mod_parser_json::JsonSourceDecoder,
        include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"),
    );
}

fn one_parser_golden(out: &mut Goldens, name: &str, parser: &dyn SourceDecoder, bytes: &[u8]) {
    let cancel = CancellationToken::new();
    let source = format!("{name}.log");
    let rows = normalized_rows(parser, &source, bytes, &cancel);
    assert!(!rows.is_empty(), "{name}");
    record(
        out,
        &format!("parser/{name}"),
        &serde_json::to_vec(&rows).unwrap(),
    );
}

fn engine(store: &Arc<LocalStore>) -> Engine<'static> {
    let signer = Arc::new(FixedSigner(SigningKey::from_bytes(&[17; 32])));
    Engine::new(
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
        Arc::new(FixedClock),
    )
    .unwrap()
}

fn signed_configuration_goldens(
    out: &mut Goldens,
    store: &LocalStore,
    engine: &Engine<'_>,
    root: &std::path::Path,
) {
    let config = TomlConfigurationStore::new(root);
    config.save(&PersistentConfig::default()).unwrap();
    engine
        .apply_configuration_change(&config, &[], ConfigChange::SetResumeLastCase(false), true)
        .unwrap();
    record(
        out,
        "configuration/json",
        &serde_json::to_vec(&config.load().unwrap()).unwrap(),
    );
    for operation in store.global_operations().unwrap() {
        record(out, "operation/canonical", &operation.canonical());
        record(
            out,
            "operation/json",
            &serde_json::to_vec(&operation).unwrap(),
        );
    }
    let definitions = irmind_infra::FileDefinitionStore::new(root);
    engine
        .install_parser_definition(
            &definitions,
            &irmind_mod_parser_declarative::DeclarativeCompiler,
            include_str!("../../../docs/examples/parsers/nested-ndjson.toml"),
        )
        .unwrap();
    let operation = store.global_operations().unwrap().pop().unwrap();
    record(out, "definition/canonical", &operation.canonical());
    record(
        out,
        "definition/json",
        &serde_json::to_vec(&operation).unwrap(),
    );
}

fn export_goldens(
    out: &mut Goldens,
    store: &LocalStore,
    engine: &Engine<'_>,
    root: &std::path::Path,
) {
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let mut entry = SignedEntry {
        seq: 1,
        case_id: id.as_str().into(),
        at: 1_792_756_800,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind: AuditEventKind::CaseCreated,
        payload: r#"{"version":3,"title":"Synthetic","severity":"medium","scope":"local"}"#.into(),
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: engine.signer.public_key(),
    };
    entry.hash = sha256(&entry.canonical());
    entry.sig = engine.signer.sign(&entry.hash).unwrap();
    record(out, "entry/canonical", &entry.canonical());
    record(out, "entry/json", &serde_json::to_vec(&entry).unwrap());
    store
        .transact(
            &entry,
            CaseMutation::Create(Case {
                id: id.clone(),
                title: "Synthetic".into(),
                severity: Severity::Medium,
                scope: "local".into(),
                sealed: false,
            }),
        )
        .unwrap();
    engine.seal(&id).unwrap();
    let seal_path = root.join("seals").join(format!("{}.json", id.as_str()));
    record(out, "seal/file", &fs::read(seal_path).unwrap());
    let cancel = CancellationToken::new();
    let current = root.join("export-v6.bin");
    irmind_app::export_case_v6(engine, store, &id, &current, None, false, &cancel).unwrap();
    assert!(fs::read(current).unwrap().starts_with(b"IRMIND-EXPORT-V6"));
}

#[test]
fn signed_and_reconstructed_format_goldens_are_unchanged() {
    if std::env::var("IRMIND_EXPECT_PRESERVE_ORDER").as_deref() == Ok("1") {
        let mut map = serde_json::Map::new();
        map.insert("z".into(), serde_json::Value::Null);
        map.insert("a".into(), serde_json::Value::Null);
        assert_eq!(
            map.keys().map(String::as_str).collect::<Vec<_>>(),
            ["z", "a"]
        );
    }
    let mut actual = Goldens::new();
    parser_goldens(&mut actual);
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&store);
    signed_configuration_goldens(&mut actual, &store, &engine, root.path());
    export_goldens(&mut actual, &store, &engine, root.path());
    let expected: Goldens =
        serde_json::from_str(include_str!("fixtures/formats-readers-v3.json")).unwrap();
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (key, value) in &expected {
        assert_eq!(actual.get(key), Some(value), "format golden {key}");
    }
}

#[path = "support/indexed_parser_contracts.rs"]
mod indexed_parser_contracts;

#[path = "support/json_order_contracts.rs"]
mod json_order_contracts;

#[test]
fn declarative_source_pipeline_is_independent_of_json_map_features() {
    use irmind_app::DefinitionCompiler;
    let pipeline = irmind_mod_parser_declarative::DeclarativeCompiler
        .compile(include_str!(
            "../../../docs/examples/parsers/nested-ndjson.toml"
        ))
        .unwrap();
    let sample = include_bytes!("../../testkit/fixtures/parser-declarative/source/events.ndjson");
    irmind_testkit::run_source_mapping_contract(
        pipeline.decoder().clone(),
        pipeline.extraction_mapper().clone(),
        "synthetic.ndjson",
        sample,
        2,
    )
    .unwrap();
}

#[cfg(feature = "mapping-ecs")]
#[test]
fn ecs_source_and_mapping_contract_is_independent_of_json_map_features() {
    use std::sync::Arc;
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder),
        Arc::new(irmind_mod_mapping_ecs::EcsMapping::new().unwrap()),
        "synthetic.ndjson",
        include_bytes!("../../testkit/fixtures/parser-ecs/source/events.ndjson"),
        2,
    )
    .unwrap();
}

#[cfg(any(
    feature = "mapping-ocsf",
    feature = "mapping-dfir",
    feature = "mapping-syslog",
    feature = "mapping-network"
))]
#[path = "support/source_pipeline_goldens.rs"]
mod source_pipeline_goldens;

#[cfg(feature = "mapping-ocsf")]
#[test]
fn ocsf_source_and_projection_bytes_are_independent_of_json_map_features() {
    let mapper = irmind_mod_mapping_ocsf::OcsfMapping::new().unwrap();
    let actual = source_pipeline_goldens::digest(
        &irmind_mod_parser_ocsf::OcsfSourceDecoder,
        &mapper,
        include_bytes!("../../testkit/fixtures/parser-ocsf/source/events.ndjson"),
        2,
    );
    assert_eq!(
        actual,
        "90c05707e91b29ae5b676a583d42c9f991450f5ea08c4ae0094208e768337095"
    );
}
#[cfg(feature = "mapping-dfir")]
#[path = "support/dfir_source_goldens.rs"]
mod dfir_source_goldens;

#[cfg(feature = "mapping-dfir")]
#[path = "support/source_worker_contracts.rs"]
mod source_worker_contracts;

#[cfg(feature = "mapping-syslog")]
#[test]
fn syslog_source_and_projection_bytes_are_independent_of_json_map_features() {
    let mapper = irmind_mod_mapping_syslog::SyslogExtractionMapping::new().unwrap();
    let sample =
        b"<34>1 2026-11-01T00:00:00.123456789Z synthetic-host app 42 ID47 - synthetic message\n";
    let actual = source_pipeline_goldens::digest(
        &irmind_mod_parser_syslog::SyslogSourceDecoder,
        &mapper,
        sample,
        1,
    );
    assert_eq!(
        actual,
        "83a7d4584d9a83b95abe71bdb2a0ae02146874b1bacc2f3859368ff1f6b91deb"
    );
}

#[cfg(feature = "mapping-network")]
#[test]
fn network_source_and_projection_bytes_are_independent_of_json_map_features() {
    let zeek = irmind_mod_mapping_network::NetworkExtractionMapping::new("parser-zeek").unwrap();
    let suricata =
        irmind_mod_mapping_network::NetworkExtractionMapping::new("parser-suricata").unwrap();
    let actual = [
        source_pipeline_goldens::digest(
            &irmind_mod_parser_zeek::ZeekSourceDecoder,
            &zeek,
            include_bytes!("../../testkit/fixtures/parser-zeek/source/dns.jsonl"),
            1,
        ),
        source_pipeline_goldens::digest(
            &irmind_mod_parser_suricata::SuricataSourceDecoder,
            &suricata,
            include_bytes!("../../testkit/fixtures/parser-suricata/source/eve.jsonl"),
            2,
        ),
    ];
    assert_eq!(
        actual,
        [
            "997c13d7a5840fec396e743a057a2cb7e7a5a0e408fd7748a28b556220d19694",
            "16d352ec9785d3431326eddb39bdda28a25e86ded552cb310de6a734f125745a"
        ]
    );
}
