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
    AppError, AuditLog, CancellationToken, CaseExporter, CaseMutation, Clock, ConfigChange,
    ConfigurationStore, CryptoPorts, Engine, EnginePorts, LargeCaseStore, PersistentConfig,
    SignedEntry, Signer, StreamingEventParser, hex, sha256,
};
use irmind_domain::{Actor, AuditEventKind, Case, CaseId, ExecutionMode, Severity};
use irmind_infra::{LocalStore, LocalVerifier, ParquetStore, TomlConfigurationStore};
use irmind_mod_parser_json::JsonParser;
use std::{collections::BTreeMap, fs, sync::Arc};

type Goldens = BTreeMap<String, String>;

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

fn parsers() -> Vec<(&'static str, Box<dyn StreamingEventParser>, &'static [u8])> {
    vec![
        (
            "json",
            Box::new(JsonParser),
            include_bytes!("../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"),
        ),
        (
            "ecs",
            Box::new(irmind_mod_parser_ecs::EcsParser),
            include_bytes!("../../testkit/fixtures/parser-ecs/source/events.ndjson"),
        ),
        (
            "ocsf",
            Box::new(irmind_mod_parser_ocsf::OcsfParser),
            include_bytes!("../../testkit/fixtures/parser-ocsf/source/events.ndjson"),
        ),
        (
            "velociraptor",
            Box::new(irmind_mod_parser_velociraptor::VelociraptorParser),
            include_bytes!("../../testkit/fixtures/parser-velociraptor/source/events.jsonl"),
        ),
        (
            "hayabusa",
            Box::new(irmind_mod_parser_hayabusa::HayabusaParser),
            include_bytes!("../../testkit/fixtures/parser-hayabusa/source/events.jsonl"),
        ),
        (
            "chainsaw",
            Box::new(irmind_mod_parser_chainsaw::ChainsawParser),
            include_bytes!("../../testkit/fixtures/parser-chainsaw/source/events.jsonl"),
        ),
        (
            "plaso",
            Box::new(irmind_mod_parser_plaso::PlasoParser),
            include_bytes!("../../testkit/fixtures/parser-plaso/source/events.jsonl"),
        ),
        (
            "eztools",
            Box::new(irmind_mod_parser_eztools::EztoolsParser),
            include_bytes!("../../testkit/fixtures/parser-eztools/source/events.csv"),
        ),
        (
            "declarative",
            Box::new(
                irmind_mod_parser_declarative::DeclarativeParser::from_toml(include_str!(
                    "../../../docs/examples/parsers/nested-ndjson.toml"
                ))
                .unwrap(),
            ),
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
    parser: &dyn StreamingEventParser,
    source: &str,
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Vec<Row> {
    let mut rows = Vec::new();
    parser
        .parse_reader(source, &mut &bytes[..], sha256(bytes), cancel, &mut |row| {
            row.inspect(|row| {
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
        })
        .unwrap();
    rows
}

fn parser_goldens(out: &mut Goldens) {
    for (name, parser, bytes) in parsers() {
        one_parser_golden(out, name, parser.as_ref(), bytes);
    }
}

fn one_parser_golden(
    out: &mut Goldens,
    name: &str,
    parser: &dyn StreamingEventParser,
    bytes: &[u8],
) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let store = ParquetStore::open(root).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let cancel = CancellationToken::new();
    let source = format!("{name}.log");
    let path = root.join(&source);
    fs::write(&path, bytes).unwrap();
    // Windows requires a writable handle for setting file timestamps.
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(FixedClock.now().unwrap()),
        )
        .unwrap();
    let rows = normalized_rows(parser, &source, bytes, &cancel);
    assert!(!rows.is_empty(), "{name}");
    record(
        out,
        &format!("parser/{name}"),
        &serde_json::to_vec(&rows).unwrap(),
    );
    let prepared = store
        .prepare_local(&id, root, &source, false, parser, &cancel)
        .unwrap();
    record(
        out,
        &format!("manifest/{name}"),
        prepared.manifest.encode().unwrap().as_bytes(),
    );
    let manifest_v2 = irmind_domain::SourceManifestV2 {
        source: prepared.manifest.clone(),
        parser_id: parser.identity().name.into(),
        parser_version: parser.identity().version.into(),
        confidence: 90,
        selection: irmind_domain::ParserSelectionMode::Automatic,
        timestamp_context: parser.timestamp_context().map(str::to_owned),
        rejected_records: 0,
        rejected_sample: vec![],
    };
    record(
        out,
        &format!("manifest-v2/{name}"),
        manifest_v2.encode().unwrap().as_bytes(),
    );
    for artifact in &prepared.artifacts {
        store.verify_artifact(&id, artifact, &cancel).unwrap();
        record(
            out,
            &format!(
                "artifact/{name}/{}/{}/{}/{}",
                artifact.schema_version,
                artifact.partition_date,
                artifact.partition_account,
                artifact.partition_region
            ),
            artifact.encode().unwrap().as_bytes(),
        );
    }
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
            Arc::new(JsonParser),
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
    let v3 = root.join("export-v3.json");
    store.export_case(&id, &v3, &cancel).unwrap();
    record(out, "export/v3", &fs::read(v3).unwrap());
    let v4 = root.join("export-v4.bin");
    irmind_app::export_case_v4(engine, store, &id, &v4, None, false, &cancel).unwrap();
    record(out, "export/v4", &fs::read(v4).unwrap());
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
    let expected: Goldens = serde_json::from_str(include_str!("fixtures/formats-v1.json")).unwrap();
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (key, value) in &expected {
        assert_eq!(actual.get(key), Some(value), "format golden {key}");
    }
}

#[test]
#[cfg(feature = "parser-syslog")]
fn syslog_signed_and_reconstructed_format_goldens_are_unchanged() {
    use irmind_mod_parser_syslog::{LegacyTimestamp, SyslogParser};
    let mut actual = Goldens::new();
    let modern = SyslogParser::from_version("syslog-v1").unwrap();
    let classic = SyslogParser::new(Some(LegacyTimestamp::new(2026, 60).unwrap()));
    for (name, parser, bytes) in [
        (
            "syslog",
            &modern,
            include_bytes!("../../testkit/fixtures/parser-syslog/source/events.log").as_slice(),
        ),
        (
            "syslog-classic",
            &classic,
            include_bytes!("../../../fuzz/seeds/parser_syslog/classic.log").as_slice(),
        ),
        (
            "syslog-gzip",
            &modern,
            include_bytes!("../../../fuzz/seeds/parser_syslog/compressed.gz").as_slice(),
        ),
    ] {
        one_parser_golden(&mut actual, name, parser, bytes);
    }
    let expected: Goldens =
        serde_json::from_str(include_str!("fixtures/formats-syslog-v1.json")).unwrap();
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (key, value) in &expected {
        assert_eq!(actual.get(key), Some(value), "syslog format golden {key}");
    }
}
