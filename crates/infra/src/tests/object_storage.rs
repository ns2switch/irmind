use super::*;
use futures_util::stream;
use irmind_app::{LargeCaseStore, ObjectEntry, ObjectSource, ObjectSourceOutput, async_trait};
use std::sync::atomic::{AtomicUsize, Ordering};

const FROM: &str = "2026-10-23T00:00:00Z";
const TO: &str = "2026-10-23T23:59:59Z";
const URI: &str = "s3://synthetic-audit/AWSLogs/123/a.json";

struct FakeObjectSource {
    bytes: Vec<u8>,
    reads: AtomicUsize,
}

impl FakeObjectSource {
    fn entry(&self) -> ObjectEntry {
        ObjectEntry {
            uri: URI.into(),
            key: "AWSLogs/123/a.json".into(),
            size: self.bytes.len() as u64,
            modified_unix_seconds: Some(1_792_756_800),
            version: Some("v1".into()),
            provider_checksum: Some("etag:synthetic".into()),
        }
    }
}

#[async_trait]
impl ObjectSource for FakeObjectSource {
    fn source_id(&self) -> &'static str {
        "storage"
    }

    async fn execute(
        &self,
        call: &irmind_domain::AuthorizedCall,
        _: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        let entry = self.entry();
        if call.tool() == &Tool::ObjectList {
            return Ok(ObjectSourceOutput::Listing {
                total_bytes: entry.size,
                objects: vec![entry],
                truncated: false,
            });
        }
        if call.tool() != &Tool::ObjectRead {
            return Err(AppError::RemoteTool);
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        let chunks = stream::iter(vec![Ok(self.bytes.clone())]);
        Ok(ObjectSourceOutput::Object {
            metadata: entry,
            chunks: Box::pin(chunks),
        })
    }
}

fn object_proposal(tool: Tool, max_bytes: &str) -> ProposedCall {
    let mut args = BTreeMap::from([
        ("source".into(), "storage".into()),
        ("scheme".into(), "s3".into()),
        ("container".into(), "synthetic-audit".into()),
        ("from".into(), FROM.into()),
        ("to".into(), TO.into()),
    ]);
    if tool == Tool::ObjectRead {
        args.insert("key".into(), "AWSLogs/123/a.json".into());
        args.insert("version".into(), "v1".into());
        args.insert("max_bytes".into(), max_bytes.into());
    } else {
        args.insert("prefix".into(), "AWSLogs/123/".into());
        args.insert("limit".into(), "20".into());
    }
    ProposedCall { tool, args }
}

#[test]
#[allow(clippy::too_many_lines)]
fn scoped_object_uses_signed_approval_streams_once_and_verifies_parquet() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[93; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
    let source = FakeObjectSource {
        bytes: br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","recipientAccountId":"123","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.8"}]}"#.to_vec(),
        reads: AtomicUsize::new(0),
    };
    let rules = PolicyRules {
        max_object_read_bytes: 1_024,
        max_object_bytes_per_case: 2_048,
        object_transfer_approval_bytes: 128,
        ..PolicyRules::default()
    };
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
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_large_case_pipeline(store.clone(), parser)
    .with_object_source(&source)
    .unwrap()
    .with_policy(rules, "f".repeat(64))
    .unwrap();
    let scope = format!(
        "v3;sources=storage;accounts=;projects=;hosts=;objects=s3://synthetic-audit/AWSLogs/123/;from={FROM};to={TO}"
    );
    let case = engine.create_case("Remote object", &scope).unwrap();
    let listed = engine
        .request_tool_as_analyst(
            &case.id,
            object_proposal(Tool::ObjectList, "0"),
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(listed.contains(URI));
    let pending = engine
        .request_tool_as_analyst(
            &case.id,
            object_proposal(Tool::ObjectRead, "1024"),
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(pending.starts_with("approval pending:"));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    let approvals = engine.pending_approvals(&case.id).unwrap();
    assert_eq!(approvals.len(), 1);
    let executed = engine.approve(&case.id, &approvals[0].id).unwrap();
    assert!(executed.starts_with("approval executed; evidence "));
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    let progress = engine.object_transfer_progress(&case.id).unwrap().unwrap();
    assert_eq!(
        progress,
        (source.bytes.len() as u64, source.bytes.len() as u64)
    );
    let second = engine
        .request_tool_as_analyst(
            &case.id,
            object_proposal(Tool::ObjectRead, "1024"),
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(second.starts_with("approval pending:"));
    let approval = engine.pending_approvals(&case.id).unwrap();
    engine.approve(&case.id, &approval[0].id).unwrap();
    assert_eq!(source.reads.load(Ordering::SeqCst), 2);
    let third = engine
        .request_tool_as_analyst(
            &case.id,
            object_proposal(Tool::ObjectRead, "1024"),
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(third.starts_with("approval pending:"));
    let approval = engine.pending_approvals(&case.id).unwrap();
    assert!(engine.approve(&case.id, &approval[0].id).is_err());
    assert_eq!(source.reads.load(Ordering::SeqCst), 2);
    assert!(store.entries(&case.id).unwrap().iter().any(|entry| {
        entry.kind == irmind_domain::AuditEventKind::Denied
            && entry.payload == "object read blocked before transfer"
    }));
    assert!(engine.verify(&case.id).is_ok());
    assert!(engine.verify_graph(&case.id).is_ok());
    let entries = store.entries(&case.id).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV1)
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV1)
            .count(),
        1
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::ParquetArtifactV1)
    );

    let copied_case = engine.create_case("Copied cloud original", &scope).unwrap();
    engine
        .request_tool_as_analyst(
            &copied_case.id,
            object_proposal(Tool::ObjectList, "0"),
            &CancellationToken::new(),
        )
        .unwrap();
    let mut copied_call = object_proposal(Tool::ObjectRead, "1024");
    copied_call
        .args
        .insert("copy_original".into(), "true".into());
    let pending = engine
        .request_tool_as_analyst(&copied_case.id, copied_call, &CancellationToken::new())
        .unwrap();
    assert!(pending.starts_with("approval pending:"));
    let approvals = engine.pending_approvals(&copied_case.id).unwrap();
    engine.approve(&copied_case.id, &approvals[0].id).unwrap();
    let copied_entry = store
        .entries(&copied_case.id)
        .unwrap()
        .into_iter()
        .find(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV1)
        .unwrap();
    let manifest = irmind_domain::SourceManifestV1::decode(&copied_entry.payload).unwrap();
    assert!(manifest.copied);
    store
        .verify_copied_source(&copied_case.id, &manifest, &CancellationToken::new())
        .unwrap();
    assert!(engine.verify(&copied_case.id).is_ok());
    engine.seal(&copied_case.id).unwrap();
    let package = root.path().join("copied-cloud.irmind");
    irmind_app::export_case_v4(
        &engine,
        store.as_ref(),
        &copied_case.id,
        &package,
        None,
        true,
        &CancellationToken::new(),
    )
    .unwrap();
    let report = irmind_app::verify_export_details(&LocalExportVerifier, &package, None).unwrap();
    assert_eq!(report.source_bytes_verified, 1);
}
