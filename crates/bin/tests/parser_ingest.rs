#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![cfg(all(
    feature = "parser-json",
    feature = "parser-ecs",
    feature = "parser-ocsf"
))]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, ParserSelection, Signer, StreamingEventParser, sha256,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, ParserSelectionMode};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use irmind_mod_parser_ecs::EcsParser;
use irmind_mod_parser_json::JsonParser;
use irmind_mod_parser_ocsf::OcsfParser;
use irmind_security::MandatoryGuard;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufWriter, Read as _, Write as _},
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
fn ecs_and_ocsf_ingest_sign_and_rebuild_without_private_answers() {
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
        assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 2);
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
    ] {
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("sources");
        fs::create_dir(&source_root).unwrap();
        let source_path = source_root.join(name);
        let mut row: serde_json::Value = serde_json::from_slice(line).unwrap();
        row.as_object_mut().unwrap().insert(
            "synthetic_padding".into(),
            serde_json::Value::String("x".repeat(900)),
        );
        let encoded = row.to_string();
        let mut writer = BufWriter::new(fs::File::create(&source_path).unwrap());
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
