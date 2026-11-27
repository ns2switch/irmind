//! Shared test source included by the three provider crates. The fixture uses
//! each real adapter and the production `SQLite`, mapping and export adapters.
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog as _, CancellationToken, Clock as _, CryptoPorts, Engine, EnginePorts,
    EntityDetails, EvidenceGraph as _, Finding, FindingKind, SignedEntry, Signer, SkillServices,
    modules::ModuleRegistry,
    source_mapping::{SourceInput, SourceMapper, SourceMetadata},
    source_queries::{
        ResolvedQuerySourceV1, SourceQueryAllocationV1, SourceQueryExecutor, SourceQueryLimits,
        SourceQueryPageDecoder, SourceQueryPlanV1, SourceQueryPorts, SourceQueryResultV1,
        canonical_query_json,
    },
};
use irmind_domain::{
    Actor, AgentId, AuditEventKind, CaseScope, ExecutionMode, IndexedTime, PolicyRules,
    ProposedCall, Tool,
};
use irmind_infra::{
    FileSkillPackageStore, LocalExportVerifier, LocalStore, LocalVerifier, SystemClock,
    TomlSkillCompiler,
};
use irmind_security::MandatoryGuard;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Cursor, Read as _},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub(super) const AT: &str = "2026-11-16T12:00:00Z";
pub(super) const FIRST: &str = "unreferenced-capture-row";
pub(super) const CITED: &str = "cited-capture-row";

#[derive(Default)]
pub(super) struct ObservedClock(AtomicU64);

impl irmind_app::Clock for ObservedClock {
    fn now(&self) -> Result<u64, AppError> {
        let seconds = SystemClock.now()?;
        self.0.store(seconds, Ordering::SeqCst);
        Ok(seconds)
    }
}

struct FixtureSigner(Actor, SigningKey);
impl Signer for FixtureSigner {
    fn actor(&self) -> Actor {
        self.0.clone()
    }
    fn public_key(&self) -> Vec<u8> {
        self.1.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.1.sign(bytes).to_bytes().to_vec())
    }
}

pub(super) struct Fixture {
    pub(super) source: ResolvedQuerySourceV1,
    pub(super) limits: SourceQueryLimits,
    pub(super) query: Value,
    pub(super) billed_bytes: u64,
    pub(super) citation_field: &'static str,
}

pub(super) fn acquire_and_export<D: SourceQueryPageDecoder + 'static>(
    fixture: &Fixture,
    executor: impl SourceQueryExecutor + 'static,
    decoder: D,
    mapping: impl SourceMapper + 'static,
    preflight_clock: &ObservedClock,
) -> Vec<u8> {
    let root = tempfile::tempdir().unwrap();
    let source = &fixture.source;
    let analytics = source.module() == "query-azure-log-analytics";
    let bigquery = source.module() == "query-bigquery";
    let account = if bigquery { "" } else { source.owner() };
    let project = if bigquery { source.owner() } else { "" };
    let scope = format!(
        "v2;sources={};accounts={account};projects={project};hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z",
        source.id()
    );
    let allocation = SourceQueryAllocationV1 {
        enabled: true,
        analytics_allowed: analytics,
        scan_bytes: fixture.limits.scan_bytes,
        retained_rows: fixture.limits.rows,
        retained_bytes: fixture.limits.retained_bytes,
    };
    let decoder = Arc::new(decoder);
    let (engine, store, expected_key) = build_engine(
        root.path(),
        fixture,
        executor,
        decoder.clone(),
        mapping,
        allocation,
        &scope,
    );
    let cancel = CancellationToken::new();
    let case = engine
        .create_case("Synthetic provider capture", &scope)
        .unwrap();
    engine
        .adopt_source_query_configuration(&adoption(fixture, analytics, bigquery))
        .unwrap();
    assert!(
        engine
            .change_source_query_budget(&case.id, allocation, "Synthetic allocation", &cancel)
            .unwrap()
    );
    let result = run_query(&engine, &store, &case.id, fixture, &cancel, preflight_clock);
    let (hash, _) = result.capture_identity();
    let finding_id = engine
        .add_entity(
            &case.id,
            FindingKind::Timeline,
            "Second captured event",
            hash,
            EntityDetails::Timeline {
                at: AT.into(),
                source: result.capture_path(),
                record_index: Some(1),
            },
        )
        .unwrap();
    engine.confirm_finding(&case.id, &finding_id).unwrap();
    engine.seal(&case.id).unwrap();
    assert!(
        engine
            .report(&case.id)
            .unwrap()
            .contains(&format!("[evidence: {hash}#1]"))
    );
    assert!(store.raw_record(&case.id, hash, 1).unwrap().contains(CITED));
    let export = root.path().join("provider.irmind");
    irmind_app::export_case(&engine, store.as_ref(), &case.id, &export, &cancel).unwrap();
    let verified =
        irmind_app::verify_export_details(&LocalExportVerifier, &export, Some(&expected_key))
            .unwrap();
    assert_eq!(verified.format_version, 12);
    assert_eq!(verified.source_bytes_verified, 1);
    let bytes = fs::read(export).unwrap();
    assert_exported_citation(
        &bytes,
        &finding_id,
        &result,
        decoder.as_ref(),
        fixture.citation_field,
        &cancel,
    );
    bytes
}

fn adoption(fixture: &Fixture, analytics: bool, bigquery: bool) -> Vec<u8> {
    let source = &fixture.source;
    let limits = &fixture.limits;
    let owner = [source.owner()];
    let (accounts, projects, workspaces) = match (analytics, bigquery) {
        (true, _) => (&[][..], &[][..], &owner[..]),
        (_, true) => (&[][..], &owner[..], &[][..]),
        _ => (&owner[..], &[][..], &[][..]),
    };
    canonical_query_json(&json!({"version":1,"source":source,"policy":{
        "accounts":accounts,"projects":projects,"workspaces":workspaces,
        "regions":[source.location()],"sources":[source.id()],
        "interval_seconds":limits.interval_seconds,"query_retained_bytes":limits.retained_bytes,
        "query_rows":limits.rows,"query_scan_bytes":limits.scan_bytes,"scan_approval_threshold":null
    }}))
    .unwrap()
}

fn run_query(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &irmind_domain::CaseId,
    fixture: &Fixture,
    cancel: &CancellationToken,
    preflight_clock: &ObservedClock,
) -> SourceQueryResultV1 {
    let args = fixture
        .query
        .as_object()
        .unwrap()
        .iter()
        .map(|(field, value)| {
            (
                field.clone(),
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned),
            )
        })
        .collect();
    let before = i64::try_from(SystemClock.now().unwrap()).unwrap();
    let feedback = engine
        .request_tool_as_analyst(
            case,
            ProposedCall {
                tool: Tool::SourceQuery,
                args,
            },
            cancel,
        )
        .unwrap();
    let after = i64::try_from(SystemClock.now().unwrap()).unwrap();
    let entries = store.entries(case).unwrap();
    let plan = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceQueryPlanV1)
        .unwrap();
    let wire: Value = serde_json::from_str(&plan.payload).unwrap();
    let observed = wire["preflight"]["observed_at"].as_str().unwrap();
    let time = IndexedTime::from_rfc3339(observed, false)
        .unwrap()
        .instant()
        .unix_micros();
    assert!(observed.ends_with(".000000000Z"));
    let observed_seconds = time.div_euclid(1_000_000);
    assert!((before..=after).contains(&observed_seconds));
    assert_eq!(
        u64::try_from(observed_seconds).unwrap(),
        preflight_clock.0.load(Ordering::SeqCst),
        "the preflight must read the injected clock"
    );
    if feedback.contains("requires analyst approval") {
        let plan = SourceQueryPlanV1::decode(plan.payload.as_bytes()).unwrap();
        engine
            .run_source_query_plan_blocking(
                case,
                &plan.content_id().unwrap(),
                "Synthetic confirmed plan",
                cancel,
            )
            .unwrap();
    } else {
        assert!(feedback.contains("Source query capture"), "{feedback}");
    }
    assert_eq!(
        engine
            .source_query_budget(case, cancel)
            .unwrap()
            .used
            .scan_bytes,
        fixture.billed_bytes
    );
    let entries = store.entries(case).unwrap();
    let result = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceQueryResultV1)
        .unwrap();
    let result = SourceQueryResultV1::decode(result.payload.as_bytes()).unwrap();
    assert!(result.matches_rows(2, 0));
    result
}

fn assert_exported_citation(
    bytes: &[u8],
    finding_id: &str,
    receipt: &SourceQueryResultV1,
    decoder: &dyn SourceQueryPageDecoder,
    citation_field: &'static str,
    cancel: &CancellationToken,
) {
    let mut export = Cursor::new(bytes.strip_prefix(b"IRMIND-EXPORT-V12\0").unwrap());
    frame(&mut export);
    let count = length(&mut export);
    let mut entries =
        (0..count).map(|_| serde_json::from_slice::<SignedEntry>(&frame(&mut export)).unwrap());
    let finding = entries
        .by_ref()
        .find_map(|entry| {
            if entry.kind != AuditEventKind::FindingProposed {
                return None;
            }
            let finding: Finding = serde_json::from_str(&entry.payload).unwrap();
            (finding.id == finding_id).then_some(finding)
        })
        .unwrap();
    assert!(entries.any(|entry| {
        entry.kind == AuditEventKind::FindingConfirmed && entry.payload == finding_id
    }));
    let (source, index) = finding
        .details
        .and_then(|details| match details {
            EntityDetails::Timeline {
                source,
                record_index: Some(index),
                ..
            } => Some((source, index)),
            _ => None,
        })
        .unwrap();
    let (hash, size) = receipt.capture_identity();
    assert_eq!(finding.evidence_hash, hash);
    assert_eq!(source, receipt.capture_path());
    assert_eq!(index, 1);
    // This fixture exports one capture smaller than one export chunk. The package
    // verifier already authenticated section framing; select the capture chunk before the empty extension sections.
    assert!((1..=512 * 1024).contains(&size));
    let (package, extension_counts) = bytes.split_at(bytes.len() - 16);
    assert_eq!(extension_counts, [0; 16]);
    let start = package.len() - usize::try_from(size).unwrap();
    assert_eq!(bytes[start - 8..start], size.to_be_bytes());
    let capture = &package[start..];
    let digest = irmind_app::sha256(capture);
    assert_eq!(irmind_app::hex(&digest), hash);
    let mut rows = Vec::new();
    let report = decoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &receipt.source_reference().unwrap(),
                    evidence_hash: digest,
                    time_context: None,
                    cluster_context: None,
                    cancel,
                },
                reader: &mut &*capture,
            },
            &mut |row| {
                row.inspect(|source| {
                    let field = source
                        .fields()
                        .field(citation_field)
                        .and_then(irmind_domain::SourceValue::as_text)
                        .unwrap()
                        .to_owned();
                    assert_eq!(
                        row.provenance().record_index(),
                        Some(source.origin().record())
                    );
                    rows.push((source.origin().record(), field));
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(rows[index].0, u64::try_from(index).unwrap());
    assert_eq!(rows[0].1, FIRST);
    assert_eq!(rows[index].1, CITED);
}

fn length(input: &mut impl std::io::Read) -> u64 {
    let mut raw = [0; 8];
    input.read_exact(&mut raw).unwrap();
    u64::from_be_bytes(raw)
}

fn frame(input: &mut Cursor<&[u8]>) -> Vec<u8> {
    let size = length(input);
    assert!((1..=1024 * 1024).contains(&size));
    let mut raw = vec![0; usize::try_from(size).unwrap()];
    input.read_exact(&mut raw).unwrap();
    raw
}

fn build_engine<D: SourceQueryPageDecoder + 'static>(
    root: &Path,
    fixture: &Fixture,
    executor: impl SourceQueryExecutor + 'static,
    decoder: Arc<D>,
    mapping: impl SourceMapper + 'static,
    allocation: SourceQueryAllocationV1,
    scope: &str,
) -> (Engine<'static>, Arc<LocalStore>, String) {
    let mut registry = ModuleRegistry::new();
    let identity = decoder.identity();
    registry.add_source_decoder(decoder.clone()).unwrap();
    registry.add_source_mapper(Arc::new(mapping)).unwrap();
    let catalog = Arc::new(registry.mapping_catalog().unwrap());
    let parser = Arc::new(
        catalog
            .decoder_selection(identity.name, identity.version)
            .unwrap(),
    );
    let store = Arc::new(LocalStore::open_mapped(root, catalog.clone()).unwrap());
    let analyst = Arc::new(FixtureSigner(
        Actor::Analyst,
        SigningKey::from_bytes(&[61; 32]),
    ));
    let agent = Arc::new(FixtureSigner(
        Actor::Agent(AgentId::parse("main").unwrap()),
        SigningKey::from_bytes(&[62; 32]),
    ));
    let expected_key = irmind_app::hex(&irmind_app::sha256(&analyst.public_key()));
    let verifier = LocalVerifier::from_signer(analyst.as_ref())
        .with_trusted_key(&agent.actor(), &agent.public_key())
        .unwrap();
    let mut queries = SourceQueryPorts::new()
        .with_organization_ceiling(allocation)
        .unwrap();
    queries
        .register_configured_source(
            fixture.source.clone(),
            fixture.limits.clone(),
            catalog.manifests().next().unwrap().identity().clone(),
            Arc::new(executor),
            decoder,
        )
        .unwrap();
    let ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(analyst, Arc::new(verifier)),
        Arc::new(MandatoryGuard::new().unwrap()),
    )
    .with_source_queries(queries);
    let engine = Engine::new(ports, ExecutionMode::Attended, Arc::new(SystemClock))
        .unwrap()
        .with_policy(
            PolicyRules {
                scope: Some(CaseScope::parse(scope).unwrap()),
                ..PolicyRules::default()
            },
            "a".repeat(64),
        )
        .unwrap()
        .with_large_case_pipeline(store.clone(), parser)
        .with_skills(
            SkillServices::new(
                Arc::new(FileSkillPackageStore::new(root)),
                Arc::new(TomlSkillCompiler),
                agent,
                vec![],
            )
            .unwrap(),
        )
        .unwrap();
    (engine, store, expected_key)
}
