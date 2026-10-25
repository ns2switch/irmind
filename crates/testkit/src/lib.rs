#![forbid(unsafe_code)]

//! Shared, offline contract suites for product adapters.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use irmind_app::{
    AppError, CancellationToken, CloudAuditPort, CompletionMessage, CompletionRequest, EdrPort,
    InternalIntelPort, LlmPort, MessageRole, SiemPort, ThreatIntelPort, collect_model_stream,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{
    AnalystApprovalVerifier, AuthorizedCall, Case, CaseId, Decision, ExecutionMode, ProposedCall,
    Severity, Tool, evaluate,
};
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const HOST: &str = "host-1";
pub const FROM: &str = "2026-10-23T12:00:00Z";
pub const TO: &str = "2026-10-23T13:00:00Z";
pub const OUTSIDE: &str = "2026-10-23T14:00:00Z";

/// In-memory EDR for application tests. The manifest exposes only detections.
pub struct FakeEdr {
    source_id: String,
    host: String,
    evidence: Vec<u8>,
    calls: Arc<Mutex<usize>>,
}

static FAKE_EDR_MANIFEST: ModuleManifest = ModuleManifest {
    id: "edr-testkit",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrDetections],
    config: &[],
};

impl FakeEdr {
    #[must_use]
    pub fn new(source_id: &str, host: &str, evidence: Vec<u8>, calls: Arc<Mutex<usize>>) -> Self {
        Self {
            source_id: source_id.into(),
            host: host.into(),
            evidence,
            calls,
        }
    }
}

impl Module for FakeEdr {
    fn manifest(&self) -> &'static ModuleManifest {
        &FAKE_EDR_MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_edr(self)
    }
}

#[irmind_app::async_trait]
impl EdrPort for FakeEdr {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn supports(&self, tool: &Tool) -> bool {
        tool == &Tool::EdrDetections
    }
    async fn execute(
        &self,
        call: &AuthorizedCall,
        _cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if call.tool() != &Tool::EdrDetections
            || call.arg("source") != Some(self.source_id())
            || call.arg("host") != Some(self.host.as_str())
        {
            return Err(AppError::Policy(
                "fake EDR source, host or tool mismatch".into(),
            ));
        }
        *self
            .calls
            .lock()
            .map_err(|_| AppError::Storage("fake EDR counter poisoned".into()))? += 1;
        Ok(self.evidence.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdrScenario {
    Host,
    DifferentHost,
    AmbiguousHost,
    MissingScopeFields,
    Detections,
    CrossHostDetection,
    CrossScopeDetection,
    OutsideWindowDetection,
    HttpError,
    OversizedResponse,
    Redirect,
    ProcessTree,
    ProcessTreeCrossHost,
}

pub struct MockResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub location: Option<&'static str>,
}

impl MockResponse {
    #[must_use]
    pub fn json(body: &str) -> Self {
        Self {
            status: 200,
            body: body.as_bytes().to_vec(),
            location: None,
        }
    }
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: b"{}".to_vec(),
            location: None,
        }
    }
    #[must_use]
    pub fn redirect() -> Self {
        Self {
            status: 302,
            body: Vec::new(),
            location: Some("/unexpected-redirect"),
        }
    }
}

#[derive(Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub trait EdrFixture {
    fn source_id(&self) -> &'static str;
    fn build(&self, origin: &str) -> Box<dyn EdrPort>;
    fn responses(&self, scenario: EdrScenario) -> Vec<MockResponse>;
    fn check_requests(
        &self,
        scenario: EdrScenario,
        requests: &[RecordedRequest],
    ) -> Result<(), String>;
}

/// Exercises the same scope, transport, response and capability cases for every EDR.
/// Product fixtures provide only their protocol responses and request assertions.
pub fn run_edr_contract(fixture: &impl EdrFixture) -> Result<(), String> {
    let source = fixture.source_id();
    let scoped = proposal(Tool::EdrHostInfo, source, HOST, FROM, TO);
    let case = case(source, HOST, "2026-10-23T00:00:00Z", "2026-10-23T23:59:59Z")?;
    if !matches!(
        evaluate(&case, scoped, 1, ExecutionMode::Unattended),
        Decision::Allow(_)
    ) {
        return Err("scoped unattended host read was not allowed".into());
    }
    if !matches!(
        evaluate(
            &case,
            proposal(Tool::EdrHostInfo, source, "host-2", FROM, TO),
            2,
            ExecutionMode::Unattended
        ),
        Decision::NeedsApproval(_)
    ) {
        return Err("out-of-scope host did not require approval".into());
    }
    if !matches!(
        evaluate(
            &case,
            proposal(
                Tool::EdrDetections,
                source,
                HOST,
                "2026-10-22T12:00:00Z",
                TO
            ),
            3,
            ExecutionMode::Unattended
        ),
        Decision::NeedsApproval(_)
    ) {
        return Err("out-of-scope detection window did not require approval".into());
    }

    for scenario in [
        EdrScenario::Host,
        EdrScenario::DifferentHost,
        EdrScenario::AmbiguousHost,
        EdrScenario::MissingScopeFields,
        EdrScenario::Detections,
        EdrScenario::CrossHostDetection,
        EdrScenario::CrossScopeDetection,
        EdrScenario::OutsideWindowDetection,
        EdrScenario::HttpError,
        EdrScenario::OversizedResponse,
        EdrScenario::Redirect,
    ] {
        run_scenario(fixture, scenario)?;
    }
    run_preflight(fixture, Tool::EdrHostInfo, "another-edr", true)?;
    run_preflight(fixture, Tool::EdrDetections, "another-edr", true)?;
    run_long_window(fixture)?;
    run_scenario(fixture, EdrScenario::ProcessTree)?;
    run_scenario(fixture, EdrScenario::ProcessTreeCrossHost)?;
    Ok(())
}

fn run_scenario(fixture: &impl EdrFixture, scenario: EdrScenario) -> Result<(), String> {
    let script = fixture.responses(scenario);
    let server = MockServer::start(script)?;
    let port = fixture.build(server.origin());
    if port.source_id() != fixture.source_id() {
        return Err("fixture registered a different EDR source".into());
    }
    let tool = if matches!(
        scenario,
        EdrScenario::ProcessTree | EdrScenario::ProcessTreeCrossHost
    ) {
        Tool::EdrProcessTree
    } else if matches!(
        scenario,
        EdrScenario::Detections
            | EdrScenario::CrossHostDetection
            | EdrScenario::CrossScopeDetection
            | EdrScenario::OutsideWindowDetection
    ) {
        Tool::EdrDetections
    } else {
        Tool::EdrHostInfo
    };
    let expected_support = !matches!(
        scenario,
        EdrScenario::ProcessTree | EdrScenario::ProcessTreeCrossHost
    ) || !fixture.responses(scenario).is_empty();
    if port.supports(&tool) != expected_support {
        return Err(format!("EDR capability mismatch for {scenario:?}"));
    }
    let call = authorized(
        tool.clone(),
        fixture.source_id(),
        HOST,
        FROM,
        TO,
        "2026-10-23T00:00:00Z",
        "2026-10-23T23:59:59Z",
    )?;
    let result = dispatch(port.as_ref(), &call);
    let requests = server.finish()?;
    fixture.check_requests(scenario, &requests)?;
    let should_succeed = matches!(scenario, EdrScenario::Host | EdrScenario::Detections)
        || (scenario == EdrScenario::ProcessTree && expected_support);
    if should_succeed {
        let bytes = result.map_err(|error| format!("{scenario:?} failed: {error}"))?;
        if bytes.is_empty() || serde_json::from_slice::<serde_json::Value>(&bytes).is_err() {
            return Err(format!("{scenario:?} returned no valid JSON evidence"));
        }
    } else if result.is_ok() {
        return Err(format!("{scenario:?} unexpectedly succeeded"));
    }
    Ok(())
}

fn run_preflight(
    fixture: &impl EdrFixture,
    tool: Tool,
    source: &str,
    should_fail: bool,
) -> Result<(), String> {
    let server = MockServer::start(Vec::new())?;
    let port = fixture.build(server.origin());
    let call = authorized(
        tool,
        source,
        HOST,
        FROM,
        TO,
        "2026-10-23T00:00:00Z",
        "2026-10-23T23:59:59Z",
    )?;
    let cancel = CancellationToken::new();
    let result = run_port(port.execute(&call, &cancel));
    let requests = server.finish()?;
    if !requests.is_empty() || (should_fail && result.is_ok()) {
        return Err("wrong source or tool reached the EDR network".into());
    }
    Ok(())
}

fn run_long_window(fixture: &impl EdrFixture) -> Result<(), String> {
    let server = MockServer::start(Vec::new())?;
    let port = fixture.build(server.origin());
    let call = authorized(
        Tool::EdrDetections,
        fixture.source_id(),
        HOST,
        "2026-10-22T11:00:00Z",
        TO,
        "2026-10-22T00:00:00Z",
        "2026-10-23T23:59:59Z",
    )?;
    let cancel = CancellationToken::new();
    let result = run_port(port.execute(&call, &cancel));
    let requests = server.finish()?;
    if result.is_ok() || !requests.is_empty() {
        return Err("overlong detection window reached the EDR network".into());
    }
    Ok(())
}

fn dispatch(port: &dyn EdrPort, call: &AuthorizedCall) -> Result<Vec<u8>, irmind_app::AppError> {
    let cancel = CancellationToken::new();
    match call.tool() {
        Tool::EdrHostInfo | Tool::EdrDetections | Tool::EdrProcessTree => {
            run_port(port.execute(call, &cancel))
        }
        _ => Err(irmind_app::AppError::Policy(
            "non-EDR tool in contract".into(),
        )),
    }
}

fn run_port<F>(future: F) -> Result<Vec<u8>, AppError>
where
    F: std::future::Future<Output = Result<Vec<u8>, AppError>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| AppError::Storage(error.to_string()))?;
    runtime.block_on(future)
}

fn authorized(
    tool: Tool,
    source: &str,
    host: &str,
    from: &str,
    to: &str,
    scope_from: &str,
    scope_to: &str,
) -> Result<AuthorizedCall, String> {
    let case = case(source, host, scope_from, scope_to)?;
    let decision = evaluate(
        &case,
        proposal(tool, source, host, from, to),
        1,
        ExecutionMode::Attended,
    );
    match decision {
        Decision::Allow(call) => Ok(call),
        other => Err(format!("fixture call was not authorized: {other:?}")),
    }
}

fn proposal(tool: Tool, source: &str, host: &str, from: &str, to: &str) -> ProposedCall {
    let mut args = BTreeMap::from([
        ("source".into(), source.into()),
        ("host".into(), host.into()),
    ]);
    if tool == Tool::EdrDetections {
        args.insert("from".into(), from.into());
        args.insert("to".into(), to.into());
    }
    if tool == Tool::EdrProcessTree {
        args.insert("process_id".into(), "789:event1".into());
    }
    ProposedCall { tool, args }
}

fn case(source: &str, host: &str, from: &str, to: &str) -> Result<Case, String> {
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111")
        .map_err(|error| format!("{error:?}"))?;
    Ok(Case {
        id,
        title: "EDR contract".into(),
        severity: Severity::High,
        scope: format!("v1;sources={source};accounts=;hosts={host};from={from};to={to}"),
        sealed: false,
    })
}

struct ContractAnalyst(SigningKey);

impl AnalystApprovalVerifier for ContractAnalyst {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(bytes): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        self.0
            .verifying_key()
            .verify(message, &ed25519_dalek::Signature::from_bytes(&bytes))
            .is_ok()
    }
}

fn contract_call(
    tool: Tool,
    source: &str,
    args: BTreeMap<String, String>,
) -> Result<AuthorizedCall, String> {
    let case = Case {
        id: CaseId::parse("22222222-2222-2222-2222-222222222222")
            .map_err(|error| format!("{error:?}"))?,
        title: "port contract".into(),
        severity: Severity::High,
        scope: format!(
            "v1;sources={source};accounts=123456789012;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z"
        ),
        sealed: false,
    };
    match evaluate(
        &case,
        ProposedCall { tool, args },
        1,
        ExecutionMode::Attended,
    ) {
        Decision::Allow(call) => Ok(call),
        Decision::NeedsApproval(pending) => {
            let analyst = ContractAnalyst(SigningKey::from_bytes(&[49; 32]));
            let signature = analyst.0.sign(&pending.challenge());
            pending
                .resolve(&signature.to_bytes(), &analyst)
                .map_err(|error| format!("signed approval failed: {error:?}"))
        }
        Decision::Deny(reason) => Err(format!("contract proposal denied: {reason}")),
    }
}

fn contract_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
}

pub fn run_siem_contract(port: &dyn SiemPort) -> Result<(), String> {
    if port.source_id().is_empty() || port.dialect().is_empty() {
        return Err("SIEM source or dialect is empty".into());
    }
    let args = |source: &str| {
        BTreeMap::from([
            ("source".into(), source.into()),
            ("account".into(), "123456789012".into()),
            ("from".into(), FROM.into()),
            ("to".into(), TO.into()),
            ("query".into(), "AssumeRole".into()),
        ])
    };
    let call = contract_call(Tool::SiemSearch, port.source_id(), args(port.source_id()))?;
    let wrong = contract_call(Tool::SiemSearch, "other-source", args("other-source"))?;
    contract_runtime()?.block_on(async {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        if !matches!(
            port.execute(&call, &cancelled).await,
            Err(AppError::Cancelled)
        ) {
            return Err("SIEM did not cancel a scoped search".into());
        }
        if port
            .execute(&wrong, &CancellationToken::new())
            .await
            .is_ok()
        {
            return Err("SIEM accepted another source".into());
        }
        Ok(())
    })
}

pub fn run_siem_recorded(
    port: &dyn SiemPort,
    server: MockServer,
    expected_body: &[u8],
) -> Result<Vec<RecordedRequest>, String> {
    let call = contract_call(
        Tool::SiemSearch,
        port.source_id(),
        BTreeMap::from([
            ("source".into(), port.source_id().into()),
            ("account".into(), "123456789012".into()),
            ("from".into(), FROM.into()),
            ("to".into(), TO.into()),
            ("query".into(), "AssumeRole".into()),
        ]),
    )?;
    let result = contract_runtime()?.block_on(port.execute(&call, &CancellationToken::new()));
    let requests = server.finish()?;
    if result.map_err(|error| error.to_string())? != expected_body {
        return Err("SIEM recorded response differs".into());
    }
    Ok(requests)
}

pub fn run_cloud_audit_contract(port: &dyn CloudAuditPort) -> Result<(), String> {
    if port.source_id().is_empty() {
        return Err("cloud source is empty".into());
    }
    let events = |source: &str| {
        BTreeMap::from([
            ("source".into(), source.into()),
            ("account".into(), "123456789012".into()),
            ("from".into(), FROM.into()),
            ("to".into(), TO.into()),
            ("event_name".into(), "AssumeRole".into()),
        ])
    };
    let identity = BTreeMap::from([
        ("source".into(), port.source_id().into()),
        ("account".into(), "123456789012".into()),
        ("kind".into(), "role".into()),
        ("name".into(), "SecurityAudit".into()),
    ]);
    let scoped = contract_call(
        Tool::CloudAuditEvents,
        port.source_id(),
        events(port.source_id()),
    )?;
    let wrong = contract_call(
        Tool::CloudAuditEvents,
        "other-source",
        events("other-source"),
    )?;
    let named = contract_call(Tool::CloudIdentity, port.source_id(), identity)?;
    contract_runtime()?.block_on(async {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        if !matches!(
            port.execute(&scoped, &cancelled).await,
            Err(AppError::Cancelled)
        ) || !matches!(
            port.execute(&named, &cancelled).await,
            Err(AppError::Cancelled)
        ) {
            return Err("cloud read did not cancel".into());
        }
        if port
            .execute(&wrong, &CancellationToken::new())
            .await
            .is_ok()
        {
            return Err("cloud module accepted another source".into());
        }
        Ok(())
    })
}

pub fn run_cloud_audit_recorded(
    port: &dyn CloudAuditPort,
    expected_fragment: &str,
) -> Result<Vec<u8>, String> {
    let call = contract_call(
        Tool::CloudAuditEvents,
        port.source_id(),
        BTreeMap::from([
            ("source".into(), port.source_id().into()),
            ("account".into(), "123456789012".into()),
            ("from".into(), FROM.into()),
            ("to".into(), TO.into()),
            ("event_name".into(), "AssumeRole".into()),
        ]),
    )?;
    let bytes = contract_runtime()?
        .block_on(port.execute(&call, &CancellationToken::new()))
        .map_err(|error| error.to_string())?;
    if !String::from_utf8_lossy(&bytes).contains(expected_fragment) {
        return Err("cloud recorded event missing from evidence".into());
    }
    Ok(bytes)
}

pub fn run_threat_intel_contract(port: &dyn ThreatIntelPort) -> Result<(), String> {
    let proposal = ProposedCall {
        tool: Tool::ThreatIntelExternal,
        args: BTreeMap::from([("ioc".into(), "example.org".into())]),
    };
    let case = Case {
        id: CaseId::parse("22222222-2222-2222-2222-222222222222")
            .map_err(|error| format!("{error:?}"))?,
        title: "TI contract".into(),
        severity: Severity::High,
        scope: "v1;sources=;accounts=;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z"
            .into(),
        sealed: false,
    };
    if !matches!(
        evaluate(&case, proposal.clone(), 1, ExecutionMode::Attended),
        Decision::NeedsApproval(_)
    ) {
        return Err("external intelligence did not require approval".into());
    }
    let call = contract_call(Tool::ThreatIntelExternal, "", proposal.args)?;
    contract_runtime()?.block_on(async {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        if !matches!(
            port.execute(&call, &cancelled).await,
            Err(AppError::Cancelled)
        ) {
            return Err("external intelligence did not cancel".into());
        }
        Ok(())
    })
}

pub fn run_threat_intel_recorded(
    port: &dyn ThreatIntelPort,
    server: MockServer,
    expected_body: &[u8],
) -> Result<Vec<RecordedRequest>, String> {
    let call = contract_call(
        Tool::ThreatIntelExternal,
        "",
        BTreeMap::from([("ioc".into(), "example.org".into())]),
    )?;
    let result = contract_runtime()?.block_on(port.execute(&call, &CancellationToken::new()));
    let requests = server.finish()?;
    if result.map_err(|error| error.to_string())? != expected_body {
        return Err("external intel recorded response differs".into());
    }
    Ok(requests)
}

pub fn run_internal_intel_contract(port: &dyn InternalIntelPort) -> Result<(), String> {
    let args = BTreeMap::from([
        ("source".into(), port.source_id().into()),
        ("ioc".into(), "example.org".into()),
    ]);
    let call = contract_call(Tool::ThreatIntelInternal, port.source_id(), args)?;
    contract_runtime()?.block_on(async {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        if !matches!(
            port.execute(&call, &cancelled).await,
            Err(AppError::Cancelled)
        ) {
            return Err("internal intelligence did not cancel".into());
        }
        Ok(())
    })
}

pub fn run_internal_intel_recorded(
    port: &dyn InternalIntelPort,
    server: MockServer,
    expected_body: &[u8],
) -> Result<Vec<RecordedRequest>, String> {
    let call = contract_call(
        Tool::ThreatIntelInternal,
        port.source_id(),
        BTreeMap::from([
            ("source".into(), port.source_id().into()),
            ("ioc".into(), "example.org".into()),
        ]),
    )?;
    let result = contract_runtime()?.block_on(port.execute(&call, &CancellationToken::new()));
    let requests = server.finish()?;
    if result.map_err(|error| error.to_string())? != expected_body {
        return Err("internal intel recorded response differs".into());
    }
    Ok(requests)
}

pub fn run_llm_contract(port: &dyn LlmPort) -> Result<(), String> {
    if port.descriptor().is_empty() {
        return Err("LLM descriptor is empty".into());
    }
    let request = |limit| CompletionRequest {
        messages: vec![CompletionMessage {
            role: MessageRole::User,
            content: "synthetic incident".into(),
        }],
        tools: Vec::new(),
        max_output_tokens: limit,
        remaining_case_tokens: 100,
    };
    contract_runtime()?.block_on(async {
        if port
            .complete(request(0), &CancellationToken::new())
            .await
            .is_ok()
        {
            return Err("LLM accepted an empty output budget".into());
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        match port.complete(request(10), &cancelled).await {
            Err(AppError::Cancelled) => Ok(()),
            Ok(stream) => match collect_model_stream(stream, &cancelled).await {
                Err(AppError::Cancelled) => Ok(()),
                _ => Err("LLM ignored cancellation".into()),
            },
            _ => Err("LLM ignored cancellation".into()),
        }
    })
}

pub struct MockServer {
    origin: String,
    task: JoinHandle<Result<Vec<RecordedRequest>, String>>,
}

impl MockServer {
    pub fn start(script: Vec<MockResponse>) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let task = thread::spawn(move || serve(&listener, &script));
        Ok(Self {
            origin: format!("http://127.0.0.1:{port}/"),
            task,
        })
    }
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn finish(self) -> Result<Vec<RecordedRequest>, String> {
        self.task
            .join()
            .map_err(|_| "mock HTTP server thread failed".to_owned())?
    }
}

fn serve(listener: &TcpListener, script: &[MockResponse]) -> Result<Vec<RecordedRequest>, String> {
    let mut requests = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut quiet_until = if script.is_empty() {
        Some(Instant::now() + Duration::from_millis(80))
    } else {
        None
    };
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "mock server received {} of {} expected requests",
                requests.len(),
                script.len()
            ));
        }
        if quiet_until.is_some_and(|until| Instant::now() >= until) {
            return Ok(requests);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if requests.len() >= script.len() {
                    return Err("EDR followed a redirect or made an unexpected request".into());
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                let request = read_request(&stream)?;
                let response = &script[requests.len()];
                requests.push(request);
                write_response(&mut stream, response)?;
                if requests.len() == script.len() {
                    quiet_until = Some(Instant::now() + Duration::from_millis(80));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_request(stream: &TcpStream) -> Result<RecordedRequest, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    if line.len() > 8192 {
        return Err("mock request line too long".into());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_owned();
    let target = parts.next().ok_or("missing target")?.to_owned();
    let mut headers = BTreeMap::new();
    for _ in 0..64 {
        line.clear();
        reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        if line.is_empty() || line.len() > 8192 {
            return Err("malformed mock request headers".into());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or("malformed mock request header")?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let len = headers
        .get("content-length")
        .map_or(Ok(0), |value| value.parse::<usize>())
        .map_err(|error| error.to_string())?;
    if len > 65_536 {
        return Err("mock request body too large".into());
    }
    let mut body = vec![0; len];
    reader
        .read_exact(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(RecordedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) -> Result<(), String> {
    let reason = match response.status {
        200 => "OK",
        302 => "Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let location = response
        .location
        .map_or(String::new(), |url| format!("Location: {url}\r\n"));
    let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&response.body)
        .map_err(|error| error.to_string())
}
