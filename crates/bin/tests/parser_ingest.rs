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
    feature = "parser-zeek",
    feature = "parser-suricata"
))]

use arrow::{
    array::{Array, ArrayRef, Int64Array, StringArray, StructArray},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, ParserSelection, Signer, StreamingEventParser, sha256,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, ParserSelectionMode};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use irmind_mod_parser_chainsaw::ChainsawParser;
use irmind_mod_parser_ecs::EcsParser;
use irmind_mod_parser_eztools::EztoolsParser;
use irmind_mod_parser_hayabusa::HayabusaParser;
use irmind_mod_parser_json::JsonParser;
use irmind_mod_parser_ocsf::OcsfParser;
use irmind_mod_parser_plaso::PlasoParser;
use irmind_mod_parser_suricata::SuricataParser;
use irmind_mod_parser_velociraptor::VelociraptorParser;
use irmind_mod_parser_zeek::ZeekParser;

use irmind_security::MandatoryGuard;
use parquet::arrow::ArrowWriter;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufWriter, Read as _, Seek as _, SeekFrom, Write as _},
    sync::Arc,
    time::Instant,
};

struct SyntheticSigner(SigningKey);

impl Signer for SyntheticSigner {
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

#[test]
#[allow(clippy::too_many_lines)]
fn local_ocsf_parquet_is_signed_and_rebuilds_without_a_parser_spool()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let source_root = root.path().join("sources");
    fs::create_dir(&source_root)?;
    let source_path = source_root.join("ocsf.parquet");
    let metadata = StructArray::from(vec![(
        Arc::new(Field::new("version", DataType::Utf8, false)),
        Arc::new(StringArray::from(vec!["1.4.0"])) as ArrayRef,
    )]);
    let schema = Arc::new(Schema::new(vec![
        Field::new("class_uid", DataType::Int64, false),
        Field::new("category_uid", DataType::Int64, false),
        Field::new("metadata", metadata.data_type().clone(), false),
        Field::new("time", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![3002])) as ArrayRef,
            Arc::new(Int64Array::from(vec![3])) as ArrayRef,
            Arc::new(metadata) as ArrayRef,
            Arc::new(Int64Array::from(vec![1_767_323_045_000_i64])) as ArrayRef,
        ],
    )?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&source_path)?;
    let mut writer = ArrowWriter::try_new(file.try_clone()?, schema, None)?;
    writer.write(&batch)?;
    writer.close()?;
    file.seek(SeekFrom::Start(0))?;
    let mut sample = vec![0u8; 64 * 1024];
    let sample_size = file.read(&mut sample)?;
    let store = Arc::new(LocalStore::open(&root.path().join("data"))?);
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[44; 32])));
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
            Arc::new(MandatoryGuard::new()?),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )?;
    let case = engine.create_case("Synthetic OCSF Parquet", "local evidence only")?;
    let parser = OcsfParser;
    let selection = BTreeMap::from([(
        "ocsf.parquet".to_owned(),
        ParserSelection {
            parser_id: parser.parser_name().into(),
            parser_version: parser.streaming_version().into(),
            confidence: 55,
            mode: ParserSelectionMode::Analyst,
            timestamp_context: None,
            format_sample_sha256: sha256(&sample[..sample_size]),
        },
    )]);
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    use_cases.ingest_local_batch_selected(
        &case.id,
        &source_root,
        &["ocsf.parquet".into()],
        false,
        &selection,
        &CancellationToken::new(),
    )?;
    assert_eq!(fs::read_dir(&source_root)?.count(), 1);
    assert_eq!(store.timeline(&case.id, 10)?.len(), 1);
    assert_eq!(
        use_cases.verify_parquet_rebuild(&case.id, &source_root, &CancellationToken::new())?,
        1
    );
    engine.verify(&case.id)?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn parser_modules_ingest_sign_and_rebuild_without_private_answers() {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("sources");
    fs::create_dir(&source_root).unwrap();
    let store = Arc::new(LocalStore::open(&root.path().join("data")).unwrap());
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[42; 32])));
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
            Arc::new(MandatoryGuard::new().unwrap()),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    for (name, bytes, parser, private_answer) in [
        (
            "ecs.ndjson",
            include_bytes!("../../testkit/fixtures/parser-ecs/source/events.ndjson").as_slice(),
            &EcsParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-ecs/private/ground-truth.json"),
        ),
        (
            "ocsf.ndjson",
            include_bytes!("../../testkit/fixtures/parser-ocsf/source/events.ndjson").as_slice(),
            &OcsfParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-ocsf/private/ground-truth.json"),
        ),
        (
            "velociraptor.jsonl",
            include_bytes!("../../testkit/fixtures/parser-velociraptor/source/events.jsonl")
                .as_slice(),
            &VelociraptorParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-velociraptor/private/ground-truth.json"),
        ),
        (
            "hayabusa.jsonl",
            include_bytes!("../../testkit/fixtures/parser-hayabusa/source/events.jsonl").as_slice(),
            &HayabusaParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-hayabusa/private/ground-truth.json"),
        ),
        (
            "chainsaw.jsonl",
            include_bytes!("../../testkit/fixtures/parser-chainsaw/source/events.jsonl").as_slice(),
            &ChainsawParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-chainsaw/private/ground-truth.json"),
        ),
        (
            "plaso.jsonl",
            include_bytes!("../../testkit/fixtures/parser-plaso/source/events.jsonl").as_slice(),
            &PlasoParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-plaso/private/ground-truth.json"),
        ),
        (
            "eztools.csv",
            include_bytes!("../../testkit/fixtures/parser-eztools/source/events.csv").as_slice(),
            &EztoolsParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-eztools/private/ground-truth.json"),
        ),
        (
            "zeek.log",
            include_bytes!("../../testkit/fixtures/parser-zeek/source/events.log").as_slice(),
            &ZeekParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-zeek/private/ground-truth.json"),
        ),
        (
            "suricata.jsonl",
            include_bytes!("../../testkit/fixtures/parser-suricata/source/eve.jsonl").as_slice(),
            &SuricataParser as &dyn StreamingEventParser,
            include_str!("../../testkit/fixtures/parser-suricata/private/ground-truth.json"),
        ),
    ] {
        fs::write(source_root.join(name), bytes).unwrap();
        let case = engine.create_case(name, "local evidence only").unwrap();
        let selection = BTreeMap::from([(
            name.to_owned(),
            ParserSelection {
                parser_id: parser.parser_name().into(),
                parser_version: parser.streaming_version().into(),
                confidence: 95,
                mode: ParserSelectionMode::Automatic,
                timestamp_context: None,
                format_sample_sha256: sha256(bytes),
            },
        )]);
        let use_cases = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser,
        };
        use_cases
            .ingest_local_batch_selected(
                &case.id,
                &source_root,
                &[name.into()],
                false,
                &selection,
                &CancellationToken::new(),
            )
            .unwrap();
        let manifest = store
            .entries(&case.id)
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind == AuditEventKind::SourceManifestV2)
            .unwrap();
        let decoded = irmind_domain::SourceManifestV2::decode(&manifest.payload).unwrap();
        assert_eq!(decoded.parser_id, parser.parser_name());
        assert_eq!(decoded.parser_version, parser.streaming_version());
        assert_eq!(decoded.confidence, 95);
        assert_eq!(decoded.selection, ParserSelectionMode::Automatic);
        assert_eq!(decoded.timestamp_context.as_deref(), Some("normalized-utc"));
        let timeline = store.timeline(&case.id, 10).unwrap();
        assert_eq!(timeline.len(), 2);
        if matches!(parser.parser_name(), "parser-zeek" | "parser-suricata") {
            assert_eq!((timeline[0].record_index, timeline[1].record_index), (0, 1));
        }
        check_ground_truth(store.as_ref(), &case.id, &timeline, private_answer, parser);
        assert_eq!(
            use_cases
                .verify_parquet_rebuild(&case.id, &source_root, &CancellationToken::new())
                .unwrap(),
            1
        );
        assert!(engine.verify(&case.id).is_ok());
        assert!(
            !store
                .graph_summary(&case.id)
                .unwrap()
                .contains(private_answer)
        );
    }
}

fn check_ground_truth(
    store: &LocalStore,
    case_id: &irmind_domain::CaseId,
    timeline: &[irmind_app::TimelineEvent],
    private_answer: &str,
    parser: &dyn StreamingEventParser,
) {
    let Ok(answer) = serde_json::from_str::<serde_json::Value>(private_answer) else {
        return;
    };
    if let Some(events) = answer
        .get("malicious_events")
        .and_then(serde_json::Value::as_array)
    {
        for event in events.iter().filter_map(serde_json::Value::as_str) {
            assert!(timeline.iter().any(|entry| entry.event == event));
        }
    }
    if let Some(entities) = answer
        .get("malicious_entities")
        .and_then(serde_json::Value::as_array)
    {
        for entity in entities.iter().filter_map(serde_json::Value::as_str) {
            assert!(
                store
                    .entity_lookup(case_id, "host", entity)
                    .unwrap()
                    .contains(entity)
            );
        }
    }
    if matches!(parser.parser_name(), "parser-zeek" | "parser-suricata") {
        for entity in answer
            .get("entities")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(pair) = entity.as_array() else {
                continue;
            };
            let Some(kind) = pair.first().and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Some(value) = pair.get(1).and_then(serde_json::Value::as_str) else {
                continue;
            };
            assert!(
                store
                    .entity_lookup(case_id, kind, value)
                    .unwrap()
                    .contains(value)
            );
        }
    }
    if let Some(marker) = answer
        .get("private_marker")
        .and_then(serde_json::Value::as_str)
    {
        assert!(!store.graph_summary(case_id).unwrap().contains(marker));
        assert!(!store.entries(case_id).unwrap().iter().any(|entry| {
            entry
                .payload
                .as_bytes()
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        }));
    }
}

/// Manual benchmark. Its temporary source and derived artifacts are removed
/// when each parser finishes; CI runs only the small contract above.
#[test]
#[ignore = "manual 1 GiB benchmark; not part of pull-request CI"]
#[allow(clippy::too_many_lines)]
fn benchmark_one_gib_synthetic_ingest_per_parser() {
    for (name, line, parser) in [
        (
            "ecs.ndjson",
            include_bytes!("../../testkit/fixtures/parser-ecs/source/events.ndjson")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &EcsParser as &dyn StreamingEventParser,
        ),
        (
            "ocsf.ndjson",
            include_bytes!("../../testkit/fixtures/parser-ocsf/source/events.ndjson")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &OcsfParser as &dyn StreamingEventParser,
        ),
        (
            "velociraptor.jsonl",
            include_bytes!("../../testkit/fixtures/parser-velociraptor/source/events.jsonl")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &VelociraptorParser as &dyn StreamingEventParser,
        ),
        (
            "hayabusa.jsonl",
            include_bytes!("../../testkit/fixtures/parser-hayabusa/source/events.jsonl")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &HayabusaParser as &dyn StreamingEventParser,
        ),
        (
            "chainsaw.jsonl",
            include_bytes!("../../testkit/fixtures/parser-chainsaw/source/events.jsonl")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &ChainsawParser as &dyn StreamingEventParser,
        ),
        (
            "plaso.jsonl",
            include_bytes!("../../testkit/fixtures/parser-plaso/source/events.jsonl")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &PlasoParser as &dyn StreamingEventParser,
        ),
        (
            "eztools.csv",
            include_bytes!("../../testkit/fixtures/parser-eztools/source/events.csv")
                .split(|byte| *byte == b'\n')
                .nth(1)
                .unwrap(),
            &EztoolsParser as &dyn StreamingEventParser,
        ),
        (
            "zeek.log",
            include_bytes!("../../testkit/fixtures/parser-zeek/source/events.log")
                .split(|byte| *byte == b'\n')
                .nth(8)
                .unwrap(),
            &ZeekParser as &dyn StreamingEventParser,
        ),
        (
            "suricata.jsonl",
            include_bytes!("../../testkit/fixtures/parser-suricata/source/eve.jsonl")
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            &SuricataParser as &dyn StreamingEventParser,
        ),
    ] {
        if std::env::var("IRMIND_BENCH_PARSER").is_ok_and(|filter| !name.starts_with(&filter)) {
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("sources");
        fs::create_dir(&source_root).unwrap();
        let source_path = source_root.join(name);
        let is_csv = std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("csv"));
        let is_zeek = name == "zeek.log";
        let encoded = if is_zeek {
            let source = std::str::from_utf8(line).unwrap().trim_end();
            format!("{source}\t{}", "x".repeat(900))
        } else if is_csv {
            let source = std::str::from_utf8(line).unwrap().trim_end();
            format!("{source},{}", "x".repeat(900))
        } else {
            let mut row: serde_json::Value = serde_json::from_slice(line).unwrap();
            row.as_object_mut().unwrap().insert(
                "synthetic_padding".into(),
                serde_json::Value::String("x".repeat(900)),
            );
            row.to_string()
        };
        let mut writer = BufWriter::new(fs::File::create(&source_path).unwrap());
        if is_csv {
            writer
                .write_all(
                    b"RunTime,ExecutableName,SourceFilename,PathValidated,SyntheticPadding\n",
                )
                .unwrap();
        }
        if is_zeek {
            writer.write_all(b"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\t2026-09-22-12-00-00\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tsynthetic_padding\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\n").unwrap();
        }
        let target = 1024_u64 * 1024 * 1024;
        let mut written = 0_u64;
        while written < target {
            writer.write_all(encoded.as_bytes()).unwrap();
            writer.write_all(b"\n").unwrap();
            written += encoded.len() as u64 + 1;
        }
        writer.flush().unwrap();
        drop(writer);
        let mut sample = vec![0u8; 64 * 1024];
        let sample_size = fs::File::open(&source_path)
            .unwrap()
            .read(&mut sample)
            .unwrap();
        let store = Arc::new(LocalStore::open(&root.path().join("data")).unwrap());
        let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[43; 32])));
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
                Arc::new(MandatoryGuard::new().unwrap()),
                Arc::new(JsonParser),
            ),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )
        .unwrap();
        let case = engine
            .create_case("Synthetic parser benchmark", "local evidence only")
            .unwrap();
        let selection = BTreeMap::from([(
            name.to_owned(),
            ParserSelection {
                parser_id: parser.parser_name().into(),
                parser_version: parser.streaming_version().into(),
                confidence: 95,
                mode: ParserSelectionMode::Automatic,
                timestamp_context: None,
                format_sample_sha256: sha256(&sample[..sample_size]),
            },
        )]);
        let started = Instant::now();
        LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser,
        }
        .ingest_local_batch_selected(
            &case.id,
            &source_root,
            &[name.into()],
            false,
            &selection,
            &CancellationToken::new(),
        )
        .unwrap();
        let seconds = started.elapsed().as_secs_f64();
        println!(
            "{name}: {written} bytes in {seconds:.3} s ({:.2} MiB/s)",
            f64::from(u32::try_from(written / 1024 / 1024).unwrap()) / seconds
        );
        assert!(engine.verify(&case.id).is_ok());
    }
}
