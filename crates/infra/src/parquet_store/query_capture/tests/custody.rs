use super::*;
use crate::{
    AuditLog, CaseMutation, FileSkillPackageStore, LocalSigner, LocalStore, LocalVerifier, Signer,
    TomlSkillCompiler,
};
use ed25519_dalek::SigningKey;
use irmind_app::source_queries::{
    SignedSourceQueryAdmission, SourceQueryReservationV1, query_content_id,
};
use irmind_app::{
    CryptoPorts, Engine, EnginePorts, LargeCaseExporter, SignedEntry, SignedOperation,
};
use irmind_domain::{
    Actor, AgentId, AuditEventKind, Case, CaseScope, ExecutionMode, PolicyRules, Severity,
};
use irmind_security::MandatoryGuard;

const CONFIGURATION: &[u8] = include_bytes!(
    "../../../../../../docs/development/source-query-format-vectors/signed-configuration.json"
);
const CHAIN: &[u8] = include_bytes!(
    "../../../../../../crates/testkit/fixtures/contracts/signed-record-chain-case-v6.json"
);
const IDS: &[u8] = include_bytes!(
    "../../../../../../docs/development/source-query-format-vectors/identities.json"
);

#[test]
fn engine_query_capture_survives_reopen_reconstruction_seal_and_v10_export() {
    assert_eq!(query_capture_roundtrip(1), query_capture_roundtrip(4));
}

fn query_capture_roundtrip(workers: u16) -> (EvidenceHash, Vec<[u8; 32]>) {
    let root = tempfile::tempdir().unwrap();
    let decoder = TestDecoder.identity();
    let (catalog, template) = synthetic_catalog_and_result(decoder);
    let analyst = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[77; 32]),
        actor: Actor::Analyst,
    });
    let agent = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[88; 32]),
        actor: Actor::Agent(AgentId::parse("main").unwrap()),
    });
    let (chain, capture) = remap_vector(&template, agent.as_ref(), analyst.as_ref());
    let case = case();
    let store = Arc::new(LocalStore::open_mapped(root.path(), catalog.clone()).unwrap());
    store.set_parallel_worker_limit(std::num::NonZeroU16::new(workers));
    record_query_prefix(store.as_ref(), &case, &chain);
    let decoder = Arc::new(
        catalog
            .decoder_selection(decoder.name, decoder.version)
            .unwrap(),
    );
    let engine = engine(
        root.path(),
        store.clone(),
        decoder.clone(),
        analyst,
        agent,
        None,
    );
    let cancel = CancellationToken::new();
    let mut spool = reserve_and_stage(&engine, &case, &chain, &cancel);
    spool.write_all(&capture).unwrap();
    check_append_rollback(
        &engine,
        store.as_ref(),
        &case,
        &chain,
        &spool,
        decoder.as_ref(),
        &cancel,
    );
    let hash = engine
        .publish_source_query_capture(
            &case,
            &chain[7].payload,
            &chain[8].payload,
            &spool,
            decoder.as_ref(),
            &cancel,
        )
        .unwrap();
    drop(spool);
    assert_eq!(hash, EvidenceHash::from_bytes(irmind_app::sha256(&capture)));
    assert!(engine.open_case_verified(&case, &cancel).is_ok());
    assert_eq!(
        irmind_app::LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: decoder.as_ref(),
        }
        .verify_parquet_rebuild(&case, root.path(), &cancel)
        .unwrap(),
        1
    );
    check_missing_capture_decoder(&engine, &case, root.path(), decoder.as_ref(), &cancel);
    let acquisition = store.entries(&case).unwrap();
    let notices = check_citation_notices(&engine, &case, &hash, &cancel);
    engine.seal(&case).unwrap();
    check_v10_export(root.path(), store.as_ref(), &case, &notices, &cancel);
    (
        hash,
        acquisition.into_iter().map(|entry| entry.hash).collect(),
    )
}

fn check_missing_capture_decoder(
    engine: &Engine<'_>,
    case: &CaseId,
    root: &Path,
    parser: &dyn irmind_app::StreamingEventParser,
    cancel: &CancellationToken,
) {
    let empty_catalog = Arc::new(irmind_app::source_mapping::MappingCatalog::default());
    let store = LocalStore::open_mapped(root, empty_catalog).unwrap();
    let error = irmind_app::LargeCaseUseCases {
        engine,
        store: &store,
        parser,
    }
    .verify_parquet_rebuild(case, root, cancel)
    .unwrap_err()
    .to_string();
    let identity = TestDecoder.identity();
    assert!(
        error.contains(&format!(
            "Capture reconstruction requires source decoder {} {}.",
            identity.name, identity.version
        )),
        "{error}"
    );
    assert!(
        error.contains("Use an IRMind build that includes that version"),
        "{error}"
    );
}

fn check_citation_notices(
    engine: &Engine<'_>,
    case: &CaseId,
    hash: &EvidenceHash,
    cancel: &CancellationToken,
) -> Vec<irmind_app::source_queries::SourceQueryLimitNotice> {
    let (_, notices) = engine.verify_with_query_limits(case, cancel).unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].capture_sha256(), hash.as_str());
    assert!(notices[0].message().contains("after 2 captured rows"));
    let finding = engine
        .add_finding(
            case,
            irmind_app::FindingKind::Hypothesis,
            "Synthetic bounded acquisition",
            hash.as_str(),
        )
        .unwrap();
    engine.confirm_finding(case, &finding).unwrap();
    assert!(engine.findings(case).unwrap()[0].source_query_limited);
    assert!(
        engine
            .report(case)
            .unwrap()
            .contains("More results may exist.")
    );
    notices
}

fn check_append_rollback(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &CaseId,
    chain: &[SignedEntry],
    spool: &tempfile::NamedTempFile,
    decoder: &dyn irmind_app::StreamingEventParser,
    cancel: &CancellationToken,
) {
    let prior = store.last_entry(case).unwrap().unwrap().hash;
    store
        .conn()
        .unwrap()
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER refuse_query_settlement BEFORE INSERT ON audit
         WHEN NEW.kind = '{}' BEGIN SELECT RAISE(ABORT, 'synthetic append failure'); END;",
            AuditEventKind::SourceQuerySettlementV1.as_str()
        ))
        .unwrap();
    assert!(
        engine
            .publish_source_query_capture(
                case,
                &chain[7].payload,
                &chain[8].payload,
                spool,
                decoder,
                cancel
            )
            .is_err()
    );
    assert_eq!(store.last_entry(case).unwrap().unwrap().hash, prior);
    let root = store.parquet.owned_case_path(case);
    assert_eq!(fs::read_dir(root.join("queries")).unwrap().count(), 0);
    assert!(store.signed_parquet_artifacts(case).unwrap().is_none());
    store
        .conn()
        .unwrap()
        .execute_batch("DROP TRIGGER refuse_query_settlement")
        .unwrap();
}

fn engine(
    root: &Path,
    store: Arc<LocalStore>,
    decoder: Arc<dyn irmind_app::StreamingEventParser>,
    analyst: Arc<LocalSigner>,
    agent: Arc<LocalSigner>,
    queries: Option<irmind_app::source_queries::SourceQueryPorts>,
) -> Engine<'static> {
    let verifier = LocalVerifier::from_signer(analyst.as_ref())
        .with_trusted_key(&agent.actor(), &agent.public_key())
        .unwrap();
    let ports = EnginePorts::new(
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        CryptoPorts::new(analyst, Arc::new(verifier)),
        Arc::new(MandatoryGuard::new().unwrap()),
    );
    let ports = if let Some(queries) = queries {
        ports.with_source_queries(queries)
    } else {
        ports
    };
    Engine::new(
        ports,
        ExecutionMode::Attended,
        Arc::new(irmind_testkit::FixedClock::new(1_794_960_000)),
    )
    .unwrap()
    .with_policy(PolicyRules {
        scope: Some(CaseScope::parse("v1;sources=aws-lab;accounts=111122223333;hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z").unwrap()),
        ..PolicyRules::default()
    }, "a".repeat(64)).unwrap()
    .with_large_case_pipeline(store, decoder)
    .with_skills(
        irmind_app::SkillServices::new(
            Arc::new(FileSkillPackageStore::new(root)),
            Arc::new(TomlSkillCompiler),
            agent,
            vec![],
        )
        .unwrap(),
    )
    .unwrap()
}

fn reserve_and_stage(
    engine: &Engine<'_>,
    case: &CaseId,
    chain: &[SignedEntry],
    cancel: &CancellationToken,
) -> tempfile::NamedTempFile {
    let reservation = SourceQueryReservationV1::decode(chain[4].payload.as_bytes())
        .unwrap()
        .content_id()
        .unwrap();
    assert!(
        engine
            .prepare_source_query_capture_spools(case, &reservation, cancel)
            .is_err()
    );
    let configuration: SignedOperation = serde_json::from_slice(CONFIGURATION).unwrap();
    let admission = SignedSourceQueryAdmission {
        plan: &chain[2],
        approval: Some(&chain[3]),
        reservation: &chain[4],
        intent: &chain[5],
        configuration: &configuration,
    };
    engine
        .persist_source_query_reservation(case, admission, false, cancel)
        .unwrap();
    assert!(
        engine
            .persist_source_query_reservation(case, admission, false, cancel)
            .is_err()
    );
    engine
        .persist_source_query_observation(case, &chain[6], cancel)
        .unwrap();
    let (writer, output) = engine
        .prepare_source_query_capture_spools(case, &reservation, cancel)
        .unwrap();
    drop(writer);
    output
}

fn check_v10_export(
    root: &Path,
    store: &LocalStore,
    case: &CaseId,
    notices: &[irmind_app::source_queries::SourceQueryLimitNotice],
    cancel: &CancellationToken,
) {
    for include_originals in [false, true] {
        let export = root.join(format!("query-{include_originals}.irmind"));
        let fingerprint =
            LargeCaseExporter::export_case(store, case, &export, None, include_originals, cancel)
                .unwrap();
        let verified = irmind_app::verify_export_details(
            &crate::LocalExportVerifier,
            &export,
            Some(&fingerprint),
        )
        .unwrap();
        assert_eq!(verified.analyst_key_fingerprint, fingerprint);
        assert_eq!(verified.source_query_limits, notices);
        let mut changed = fs::read(&export).unwrap();
        let capture_body_end = changed.len() - 16;
        changed[capture_body_end - 1] ^= 1;
        fs::write(&export, changed).unwrap();
        assert!(crate::verify_export_expected(&export, Some(&fingerprint)).is_err());
    }
}

fn record_query_prefix(store: &LocalStore, case: &CaseId, chain: &[SignedEntry]) {
    let configuration: SignedOperation = serde_json::from_slice(CONFIGURATION).unwrap();
    store.append_global_operation(&configuration).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&chain[0].payload).unwrap();
    store
        .transact(
            &chain[0],
            CaseMutation::Create(Case {
                id: case.clone(),
                title: meta["title"].as_str().unwrap().into(),
                severity: Severity::Medium,
                scope: meta["scope"].as_str().unwrap().into(),
                sealed: false,
            }),
        )
        .unwrap();
    store.append_batch(&chain[1..4]).unwrap();
}

/// Use the approved wire vectors with a deterministic synthetic mapper whose
/// implementation digest is known to the test. Provider page bytes stay exact.
fn remap_vector(
    template: &SourceQueryResultV1,
    agent: &dyn Signer,
    analyst: &dyn Signer,
) -> (Vec<SignedEntry>, Vec<u8>) {
    let mut chain: Vec<SignedEntry> = serde_json::from_slice(CHAIN).unwrap();
    let ids: BTreeMap<String, String> = serde_json::from_slice(IDS).unwrap();
    let template_json = serde_json::to_value(template).unwrap();
    let mut replacements: Vec<(&str, String)> = vec![(
        "a799cf54941b7079db5e92f8c94431a4607e70890796d12fbfd4092402b33383",
        template_json["mapping"]["sha256"].as_str().unwrap().into(),
    )];
    let mut captured = capture();
    let mut prior = chain[1].hash;
    let sequence = [
        "plan",
        "approval",
        "reservation",
        "intent",
        "execution",
        "result",
        "settlement",
    ];
    for (entry, name) in chain.iter_mut().skip(2).zip(sequence) {
        for (before, after) in &replacements {
            entry.payload = entry.payload.replace(before, after);
        }
        let mut value: serde_json::Value = serde_json::from_str(&entry.payload).unwrap();
        if name == "plan" {
            value["query"]["limit"] = serde_json::json!(2);
            value["compiled"]["text"] = serde_json::json!(
                value["compiled"]["text"]
                    .as_str()
                    .unwrap()
                    .replace("LIMIT 100000", "LIMIT 2")
            );
            let preflight = serde_json::json!({
                "compiled": value["compiled"], "source": value["source"],
                "scope": value["scope"], "limits": value["limits"]
            });
            value["preflight"]["plan_digest"] =
                serde_json::json!(irmind_app::hex(&irmind_app::sha256(
                    &irmind_app::source_queries::canonical_query_json(&preflight).unwrap()
                )));
        } else if name == "result" {
            value["completeness"] = serde_json::json!(["local_limit"]);
        }
        entry.payload =
            String::from_utf8(irmind_app::source_queries::canonical_query_json(&value).unwrap())
                .unwrap();
        let kind = if name == "intent" { "execution" } else { name };
        let identity = query_content_id(&format!("irmind-source-query-{kind}-v1"), &value).unwrap();
        replacements.push((ids[name].as_str(), identity.clone()));
        if name == "plan" {
            let old = ids[name].as_bytes();
            let offset = captured
                .windows(old.len())
                .position(|part| part == old)
                .unwrap();
            captured[offset..offset + old.len()].copy_from_slice(identity.as_bytes());
            replacements.push((
                ids["capture_sha256"].as_str(),
                irmind_app::hex(&irmind_app::sha256(&captured)),
            ));
        }
        entry.prev = prior;
        let signer = if entry.kind == AuditEventKind::SourceQueryApprovalV1 {
            analyst
        } else {
            agent
        };
        entry.hash = irmind_app::sha256(&entry.canonical());
        entry.sig = signer.sign(&entry.hash).unwrap();
        prior = entry.hash;
    }
    (chain, captured)
}

mod signed_dispatch {
    use super::*;
    use irmind_app::{AppError, async_trait, source_queries::*};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SimulatedExecutor {
        store: Arc<LocalStore>,
        compiled: CompiledSourceQueryV1,
        preflights: AtomicUsize,
        submissions: AtomicUsize,
        complete: bool,
    }

    impl SourceQueryPageDecoder for TestDecoder {
        fn inspect_page(
            &self,
            input: &mut dyn QueryPageInput,
            _: u64,
            _: Option<&QueryPageSchema>,
            _: &CancellationToken,
        ) -> Result<InspectedQueryPage, AppError> {
            let mut body = Vec::new();
            input.take(256).read_to_end(&mut body).map_err(storage)?;
            if body != b"synthetic page" {
                return Err(SourceQueryError::Invalid.into());
            }
            Ok(InspectedQueryPage {
                schema: QueryPageSchema::new(
                    vec![CaptureColumn {
                        name: "synthetic".into(),
                        native_type: "varchar".into(),
                    }],
                    vec![],
                )?,
                rows: 2,
                rejected: 0,
                provider_partial: true,
                total_rows: None,
                next_token: None,
            })
        }
    }

    #[async_trait]
    impl SourceQueryExecutor for SimulatedExecutor {
        fn descriptor(&self) -> SourceQueryModuleV1 {
            SourceQueryModuleV1 {
                id: "query-athena".into(),
                version: "1".into(),
                datasets: vec!["cloudtrail-management".into()],
                fields: vec!["@timestamp".into()],
                operators: vec![QueryOperator::Eq],
                result_kinds: vec![QueryResultKind::Events],
                accounting: QueryAccounting::ScanPriced,
                recoverable_submit: true,
                cancellation: true,
                api_version: "2017-05-18".into(),
            }
        }

        fn compile(
            &self,
            _: &ResolvedQuerySourceV1,
            _: &SourceQueryV1,
        ) -> Result<CompiledSourceQueryV1, AppError> {
            Ok(self.compiled.clone())
        }

        async fn preflight(
            &self,
            _: &irmind_domain::AuthorizedCall,
            compiled: &CompiledSourceQueryV1,
            _: &CancellationToken,
        ) -> Result<QueryPreflightV1, AppError> {
            self.preflights.fetch_add(1, Ordering::SeqCst);
            let plan: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../../../../docs/development/source-query-format-vectors/plan.json"
            ))
            .unwrap();
            let mut preflight: QueryPreflightV1 =
                serde_json::from_value(plan["preflight"].clone()).unwrap();
            preflight.plan_digest =
                irmind_app::hex(&irmind_app::sha256(&canonical_query_json(compiled)?));
            Ok(preflight)
        }

        async fn submit(
            &self,
            lease: &AdmittedSourceQuery,
            _: &CancellationToken,
        ) -> Result<SubmitObservationV1, AppError> {
            lease.check(
                "query-athena",
                "aws-lab",
                SourceQueryLeasePhase::Submit,
                None,
            )?;
            let _lock = irmind_app::Repository::lock_case(self.store.as_ref(), lease.case_id())?;
            let entries = self.store.entries(lease.case_id())?;
            assert!(
                matches!(&entries[entries.len() - 3..], [reservation, intent, dispatch]
                if dispatch.kind == AuditEventKind::Allowed
                    && reservation.kind == AuditEventKind::SourceQueryReservationV1
                    && intent.kind == AuditEventKind::SourceQueryExecutionV1
                    && intent.prev == reservation.hash)
            );
            self.submissions.fetch_add(1, Ordering::SeqCst);
            if self.complete {
                return Ok(SubmitObservationV1::Accepted(QueryExecutionRef::new(
                    lease.plan(),
                    lease.attempt(),
                    "synthetic-query-job",
                )?));
            }
            Ok(SubmitObservationV1::Unknown)
        }

        async fn reconcile(
            &self,
            lease: &AdmittedSourceQuery,
            job: &QueryExecutionRef,
            _: &CancellationToken,
        ) -> Result<ExecutionObservationV1, AppError> {
            lease.check(
                "query-athena",
                "aws-lab",
                SourceQueryLeasePhase::Reconcile,
                Some(job),
            )?;
            Ok(ExecutionObservationV1 {
                status: QueryExecutionStatus::Succeeded,
                request_id: None,
                usage: SourceQueryUsage {
                    scanned_bytes: Some(64),
                    processed_bytes: None,
                    billed_bytes: Some(10 << 20),
                    returned_wire_bytes: 0,
                    returned_decoded_bytes: 0,
                    query_price_basis: QueryAccounting::ScanPriced,
                },
                source_observation: None,
            })
        }

        async fn fetch(
            &self,
            lease: &AdmittedSourceQuery,
            job: &QueryExecutionRef,
            cursor: &QueryResultCursor,
            _: &CancellationToken,
        ) -> Result<QueryResponsePage, AppError> {
            lease.check(
                "query-athena",
                "aws-lab",
                SourceQueryLeasePhase::Fetch,
                Some(job),
            )?;
            cursor.check(job)?;
            Ok(QueryResponsePage {
                request_id: None,
                next_token: None,
                content_encoding: "identity".into(),
                chunks: Box::pin(futures_util::stream::iter([Ok(b"synthetic page".to_vec())])),
            })
        }

        async fn cancel(
            &self,
            _: &AdmittedSourceQuery,
            _: &QueryExecutionRef,
            _: &CancellationToken,
        ) -> Result<CancelObservationV1, AppError> {
            Err(SourceQueryError::Unavailable.into())
        }
    }

    fn authorize(
        engine: &Engine<'_>,
        case: &CaseId,
        plan: &serde_json::Value,
    ) -> Option<irmind_domain::AuthorizedCall> {
        let args = plan["query"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned),
                )
            })
            .collect();
        let decision = irmind_domain::evaluate_with_rules(
            &engine.repo.get_case(case).unwrap(),
            irmind_domain::ProposedCall {
                tool: irmind_domain::Tool::SourceQuery,
                args,
            },
            3,
            ExecutionMode::Attended,
            1_794_960_000,
            &PolicyRules::default(),
        );
        match decision {
            irmind_domain::Decision::Allow(call) => Some(call),
            _ => None,
        }
    }

    #[test]
    fn ambiguous_submission_is_only_called_once_after_durable_intent() {
        signed_dispatch(false, false);
    }

    #[test]
    fn signed_dispatch_fetches_and_atomically_publishes_a_partial_capture() {
        signed_dispatch(true, false);
    }

    #[test]
    fn signed_dispatch_through_the_normal_tool_path_requires_exact_approval() {
        signed_dispatch(true, true);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Use one signed fixture for both dispatch outcomes"
    )]
    fn signed_dispatch(complete: bool, from_tool: bool) {
        let root = tempfile::tempdir().unwrap();
        let identity = TestDecoder.identity();
        let (catalog, template) = synthetic_catalog_and_result(identity);
        let analyst = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[77; 32]),
            actor: Actor::Analyst,
        });
        let agent = Arc::new(LocalSigner {
            key: SigningKey::from_bytes(&[88; 32]),
            actor: Actor::Agent(AgentId::parse("main").unwrap()),
        });
        let (chain, _) = remap_vector(&template, agent.as_ref(), analyst.as_ref());
        let case = case();
        let store = Arc::new(LocalStore::open_mapped(root.path(), catalog.clone()).unwrap());
        record_query_prefix(store.as_ref(), &case, &chain);
        let plan: serde_json::Value = serde_json::from_str(&chain[2].payload).unwrap();
        let executor = Arc::new(SimulatedExecutor {
            store: store.clone(),
            compiled: serde_json::from_value(plan["compiled"].clone()).unwrap(),
            preflights: AtomicUsize::new(0),
            submissions: AtomicUsize::new(0),
            complete,
        });
        let mut queries = SourceQueryPorts::new()
            .with_organization_ceiling(SourceQueryAllocationV1 {
                enabled: true,
                analytics_allowed: true,
                scan_bytes: Some(128 << 20),
                retained_rows: QUERY_CASE_MAX_ROWS,
                retained_bytes: QUERY_CASE_MAX_BYTES,
            })
            .unwrap();
        queries.add(executor.clone()).unwrap();
        queries
            .add_page_decoder(
                "query-athena",
                "1",
                "cloudtrail-management",
                Arc::new(TestDecoder),
            )
            .unwrap();
        queries
            .bind_source(
                serde_json::from_value(plan["source"].clone()).unwrap(),
                serde_json::from_value(plan["limits"].clone()).unwrap(),
                catalog.manifests().next().unwrap().identity().clone(),
            )
            .unwrap();
        let decoder = Arc::new(
            catalog
                .decoder_selection(identity.name, identity.version)
                .unwrap(),
        );
        let engine = engine(
            root.path(),
            store.clone(),
            decoder,
            analyst,
            agent,
            Some(queries),
        );
        let authorized = authorize(&engine, &case, &plan).unwrap();
        let configuration: SignedOperation = serde_json::from_slice(CONFIGURATION).unwrap();
        let admission = SignedSourceQueryAdmission {
            plan: &chain[2],
            approval: Some(&chain[3]),
            reservation: &chain[4],
            intent: &chain[5],
            configuration: &configuration,
        };
        let cancel = CancellationToken::new();
        if from_tool {
            check_tool_plan(&engine, &case, &store, &authorized, &executor, &cancel);
            return;
        }
        let mut tampered = chain[3].clone();
        tampered.sig[0] ^= 1;
        assert!(
            engine
                .submit_signed_source_query(
                    &authorized,
                    SignedSourceQueryAdmission {
                        approval: Some(&tampered),
                        ..admission
                    },
                    &cancel
                )
                .is_err()
        );
        assert_eq!(executor.submissions.load(Ordering::SeqCst), 0);
        if complete {
            check_acquired(&engine, &case, &authorized, admission, &cancel);
            assert_eq!(executor.submissions.load(Ordering::SeqCst), 1);
            return;
        }
        assert!(matches!(
            engine
                .submit_signed_source_query(&authorized, admission, &cancel)
                .unwrap(),
            SubmitObservationV1::Unknown
        ));
        assert!(
            engine
                .submit_signed_source_query(&authorized, admission, &cancel)
                .is_err()
        );
        assert_eq!(executor.submissions.load(Ordering::SeqCst), 1);
        verify_unknown_observation(&engine, &store, &case);
        let retry = engine
            .request_tool_as_analyst(
                &case,
                irmind_app::ProposedCall {
                    tool: irmind_app::Tool::SourceQuery,
                    args: authorized.proposal_args().clone(),
                },
                &cancel,
            )
            .unwrap_or_else(|error| error.to_string());
        assert!(!retry.contains("requires analyst approval"), "{retry}");
        assert_eq!(executor.preflights.load(Ordering::SeqCst), 0);
        assert!(engine.verify(&case).is_ok());
    }

    fn check_tool_plan(
        engine: &Engine<'_>,
        case: &CaseId,
        store: &LocalStore,
        authorized: &irmind_domain::AuthorizedCall,
        executor: &SimulatedExecutor,
        cancel: &CancellationToken,
    ) {
        let feedback = engine
            .request_tool_as_analyst(
                case,
                irmind_app::ProposedCall {
                    tool: irmind_app::Tool::SourceQuery,
                    args: authorized.proposal_args().clone(),
                },
                cancel,
            )
            .unwrap();
        assert!(feedback.contains("requires analyst approval"));
        assert_eq!(executor.preflights.load(Ordering::SeqCst), 1);
        assert_eq!(executor.submissions.load(Ordering::SeqCst), 0);
        let last = store.last_entry(case).unwrap().unwrap();
        assert_eq!(last.kind, AuditEventKind::SourceQueryPlanV1);
        let plan = SourceQueryPlanV1::decode(last.payload.as_bytes()).unwrap();
        let id = plan.content_id().unwrap();
        assert!(feedback.contains(&id));
        assert!(
            engine
                .source_query_plan_text(case, &id, cancel)
                .unwrap()
                .contains("aws-lab")
        );
        let result = engine
            .run_source_query_plan_blocking(
                case,
                &id,
                "Synthetic analyst confirmed the exact plan",
                cancel,
            )
            .unwrap();
        assert_eq!(result.rows, 2);
        assert!(engine.verify(case).is_ok());
        assert_eq!(executor.submissions.load(Ordering::SeqCst), 1);
        check_released_dispatch_slot(store, case);
        let status = engine.source_query_budget(case, cancel).unwrap();
        assert_eq!(status.used.scan_bytes, 10 << 20);
        assert_eq!(status.used.retained_rows, 2);
        assert_eq!(status.held, SourceQueryResources::default());
        check_authenticated_budget_display(engine, case, store, &status, cancel);
        assert!(
            engine
                .change_source_query_budget(
                    case,
                    SourceQueryAllocationV1 {
                        scan_bytes: Some(129 << 20),
                        ..status.allocation
                    },
                    "Synthetic above the organization ceiling",
                    cancel,
                )
                .is_err()
        );
        assert!(
            engine
                .change_source_query_budget(
                    case,
                    SourceQueryAllocationV1 {
                        scan_bytes: Some(64 << 20),
                        ..status.allocation
                    },
                    "Synthetic case allocation",
                    cancel,
                )
                .unwrap()
        );
        let current = engine.source_query_budget(case, cancel).unwrap();
        assert_eq!(current.revision, status.revision + 1);
        assert_eq!(current.allocation.scan_bytes, Some(64 << 20));
        assert_eq!(current.used, status.used);
        assert!(engine.verify(case).is_ok());
    }

    fn check_authenticated_budget_display(
        engine: &Engine<'_>,
        case: &CaseId,
        store: &LocalStore,
        status: &irmind_app::source_queries::SourceQueryBudgetStatus,
        cancel: &CancellationToken,
    ) {
        let mut receipts = store.entries(case).unwrap();
        let display = engine
            .source_query_budget_display(case, &receipts, cancel)
            .unwrap();
        assert_eq!(display.used, status.used);
        assert_eq!(display.held, status.held);
        receipts.last_mut().unwrap().payload.push(' ');
        assert!(
            engine
                .source_query_budget_display(case, &receipts, cancel)
                .is_err()
        );
    }

    fn check_released_dispatch_slot(store: &LocalStore, case: &CaseId) {
        let settlement = store
            .entries(case)
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind == AuditEventKind::SourceQuerySettlementV1)
            .unwrap();
        let release: Vec<u8> = store
            .conn()
            .unwrap()
            .query_row(
                "SELECT release_hash FROM source_query_dispatch WHERE case_id=?1",
                [case.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(release, settlement.hash);
    }

    fn check_acquired(
        engine: &Engine<'_>,
        case: &CaseId,
        authorized: &irmind_domain::AuthorizedCall,
        admission: SignedSourceQueryAdmission<'_>,
        cancel: &CancellationToken,
    ) {
        let acquired = engine
            .acquire_signed_source_query(authorized, admission, cancel)
            .unwrap();
        assert_eq!((acquired.rows, acquired.rejected_rows), (2, 0));
        assert_eq!(acquired.completeness, ["local_limit", "provider_partial"]);
        assert!(engine.verify(case).is_ok());
        assert_eq!(
            engine.verify_with_query_limits(case, cancel).unwrap().1[0].capture_sha256(),
            acquired.capture.as_str()
        );
    }

    fn verify_unknown_observation(engine: &Engine<'_>, store: &LocalStore, case: &CaseId) {
        let last = store.last_entry(case).unwrap().unwrap();
        assert_eq!(last.kind, AuditEventKind::SourceQueryExecutionV1);
        let observation: serde_json::Value = serde_json::from_str(&last.payload).unwrap();
        assert_eq!(observation["status"], "unknown");
        assert!(observation["usage"]["billed_bytes"].is_null());
        assert!(engine.verify(case).is_ok());
    }
}
