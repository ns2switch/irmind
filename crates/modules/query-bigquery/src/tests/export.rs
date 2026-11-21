use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AuditLog as _, CryptoPorts, Engine, EnginePorts, Signer, SkillServices,
    modules::ModuleRegistry,
    source_queries::{SourceQueryAllocationV1, SourceQueryPlanV1, SourceQueryPorts},
};
use irmind_domain::{
    Actor, AgentId, AuditEventKind, CaseScope, ExecutionMode, PolicyRules, ProposedCall,
};
use irmind_infra::{
    FileSkillPackageStore, LocalExportVerifier, LocalStore, LocalVerifier, TomlSkillCompiler,
};
use irmind_mod_mapping_gcp_audit::CloudAuditMapping;
use irmind_security::MandatoryGuard;
use std::{fs, path::Path, sync::Arc};

const TOKEN: &str = "synthetic-bigquery-export-bearer";
const KEY: &str =
    include_str!("../../../siem-chronicle/tests/fixtures/synthetic-service-account.pem");
const SCOPE: &str = "v2;sources=gcp-lab;accounts=;projects=synthetic-project;hosts=;from=2026-11-01T00:00:00Z;to=2026-12-01T00:00:00Z";
const PAGE: &[u8] = include_bytes!("../../../../../fuzz/seeds/query_page_bigquery/page.json");

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

#[test]
fn oauth_capture_is_exported_and_verified_without_credentials() {
    let (source, limits, mut query) = compiled_fixture();
    query["filters"] = json!([]);
    let source = serde_json::from_value::<ResolvedQuerySourceV1>(source).unwrap();
    let allocation = SourceQueryAllocationV1 {
        enabled: true,
        analytics_allowed: false,
        scan_bytes: limits.scan_bytes,
        retained_rows: limits.rows,
        retained_bytes: limits.retained_bytes,
    };
    let root = tempfile::tempdir().unwrap();
    let server = query_server();
    let oauth = MockServer::start(vec![MockResponse::json(
        &json!({
            "access_token":TOKEN,"token_type":"Bearer","expires_in":300
        })
        .to_string(),
    )])
    .unwrap();
    let executor = connect(&source, &limits, &server, &oauth);
    let (engine, store, expected_key) = build_case_engine(root.path(), executor, allocation);
    let cancel = CancellationToken::new();
    let case = engine
        .create_case("Synthetic BigQuery capture", SCOPE)
        .unwrap();
    engine.adopt_source_query_configuration(&canonical_query_json(&json!({
        "version":1,"source":source,"policy":{
            "accounts":[],"projects":[source.owner()],"workspaces":[],
            "regions":[source.location()],"sources":[source.id()],
            "interval_seconds":limits.interval_seconds,"query_retained_bytes":limits.retained_bytes,
            "query_rows":limits.rows,"query_scan_bytes":limits.scan_bytes,"scan_approval_threshold":null
        }
    })).unwrap()).unwrap();
    assert!(
        engine
            .change_source_query_budget(&case.id, allocation, "Synthetic test", &cancel)
            .unwrap()
    );
    run_query(&engine, store.as_ref(), &case.id, &query, &cancel);
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let requests = oauth.finish().unwrap();
    let oauth_body = std::str::from_utf8(&requests[0].body).unwrap();
    let assertion = oauth_body.split("assertion=").nth(1).unwrap();
    assert_eq!(assertion.split('.').count(), 3);
    assert_eq!(server.finish().unwrap().len(), 4);
    let export = root.path().join("bigquery.irmind");
    irmind_app::export_case(&engine, store.as_ref(), &case.id, &export, &cancel).unwrap();
    let detail =
        irmind_app::verify_export_details(&LocalExportVerifier, &export, Some(&expected_key))
            .unwrap();
    assert_eq!(detail.format_version, 9);
    let bytes = fs::read(export).unwrap();
    assert!(contains(&bytes, b"IRMIND-QUERY-CAPTURE-V1"));
    assert!(contains(&bytes, b"compute.googleapis.com"));
    for secret in [TOKEN, assertion].into_iter().chain(KEY.lines()) {
        assert!(
            !contains(&bytes, secret.as_bytes()),
            "authentication material in export"
        );
    }
}

fn run_query(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &irmind_domain::CaseId,
    query: &Value,
    cancel: &CancellationToken,
) {
    let args = query
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
    assert!(feedback.contains("requires analyst approval"), "{feedback}");
    let entry = store.last_entry(case).unwrap().unwrap();
    assert_eq!(entry.kind, AuditEventKind::SourceQueryPlanV1);
    let plan = SourceQueryPlanV1::decode(entry.payload.as_bytes()).unwrap();
    let result = engine
        .run_source_query_plan_blocking(
            case,
            &plan.content_id().unwrap(),
            "Synthetic confirmed plan",
            cancel,
        )
        .unwrap();
    assert_eq!(result.rows, 1);
    assert_eq!(
        engine
            .source_query_budget(case, cancel)
            .unwrap()
            .used
            .scan_bytes,
        10 << 20
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn connect(
    source: &ResolvedQuerySourceV1,
    limits: &SourceQueryLimits,
    server: &MockServer,
    oauth: &MockServer,
) -> BigQuery {
    let account = SecretString::from(json!({
        "type":"service_account","client_email":"synthetic-export@gcp-test.iam.gserviceaccount.com",
        "private_key":KEY,"token_uri":"https://oauth2.googleapis.com/token"
    }).to_string());
    let mut executor =
        BigQuery::with_service_account(source.clone(), limits.clone(), &account).unwrap();
    executor.endpoint = reqwest::Url::parse(server.origin())
        .unwrap()
        .join("bigquery/v2/")
        .unwrap();
    let Credentials::ServiceAccount { endpoint, .. } = &mut executor.credentials else {
        unreachable!()
    };
    *endpoint = reqwest::Url::parse(oauth.origin())
        .unwrap()
        .join("token")
        .unwrap();
    executor
}

fn query_server() -> MockServer {
    let mut submission = Value::Null;
    MockServer::start_with(4, move |step, request| {
        assert_eq!(request.headers.get("authorization").map(String::as_str), Some("Bearer synthetic-bigquery-export-bearer"));
        let response = match step {
            0 => json!({"configuration":{"dryRun":true},"statistics":{"query":{"totalBytesProcessed":"128"}}}),
            1 => {
                submission = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(submission["configuration"]["query"]["maximumBytesBilled"], "67108864");
                json!({"jobReference":submission["jobReference"]})
            }
            2 => {
                let job_id = submission["jobReference"]["jobId"].as_str().unwrap();
                assert!(request.target.contains(&format!("/jobs/{job_id}?")));
                json!({"jobReference":submission["jobReference"],"configuration":submission["configuration"],
                    "status":{"state":"DONE"},"statistics":{"query":{"totalBytesProcessed":"128","totalBytesBilled":"10485760"}}})
            }
            3 => {
                let job_id = submission["jobReference"]["jobId"].as_str().unwrap();
                assert!(request.target.contains(&format!("/queries/{job_id}?")));
                let mut page: Value = serde_json::from_slice(PAGE).unwrap();
                page["jobReference"] = submission["jobReference"].clone();
                page["rows"][0]["f"][0]["v"] = json!("1794787200123456");
                page
            }
            _ => unreachable!(),
        };
        Ok(MockResponse::json(&response.to_string()))
    }).unwrap()
}

fn build_case_engine(
    root: &Path,
    executor: BigQuery,
    allocation: SourceQueryAllocationV1,
) -> (Engine<'static>, Arc<LocalStore>, String) {
    let mapping = Arc::new(CloudAuditMapping::for_capture().unwrap());
    let decoder = Arc::new(BigQueryCaptureDecoder);
    let mut registry = ModuleRegistry::new();
    registry.add_source_decoder(decoder.clone()).unwrap();
    registry.add_source_mapper(mapping.clone()).unwrap();
    let catalog = Arc::new(registry.mapping_catalog().unwrap());
    let parser = Arc::new(
        catalog
            .decoder_selection("query-bigquery-cloud-audit", "1")
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
            executor.source.clone(),
            executor.limits.clone(),
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
    let engine = Engine::new(
        ports,
        ExecutionMode::Attended,
        Arc::new(irmind_infra::SystemClock),
    )
    .unwrap()
    .with_policy(
        PolicyRules {
            scope: Some(CaseScope::parse(SCOPE).unwrap()),
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
