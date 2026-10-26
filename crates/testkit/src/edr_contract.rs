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
    pub delay: Duration,
}

impl MockResponse {
    #[must_use]
    pub fn json(body: &str) -> Self {
        Self {
            status: 200,
            body: body.as_bytes().to_vec(),
            location: None,
            delay: Duration::ZERO,
        }
    }
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: b"{}".to_vec(),
            location: None,
            delay: Duration::ZERO,
        }
    }
    #[must_use]
    pub fn redirect() -> Self {
        Self {
            status: 302,
            body: Vec::new(),
            location: Some("/unexpected-redirect"),
            delay: Duration::ZERO,
        }
    }

    #[must_use]
    pub fn delayed(body: &str, delay: Duration) -> Self {
        Self {
            delay,
            ..Self::json(body)
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
        evaluate(&case, scoped, 1, ExecutionMode::Unattended, 1_700_000_000),
        Decision::Allow(_)
    ) {
        return Err("scoped unattended host read was not allowed".into());
    }
    if !matches!(
        evaluate(
            &case,
            proposal(Tool::EdrHostInfo, source, "host-2", FROM, TO),
            2,
            ExecutionMode::Unattended,
            1_700_000_000
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
            ExecutionMode::Unattended,
            1_700_000_000
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
        _ => Err(irmind_app::AppError::Fixed(
            irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::NonEDRToolInContract,
            ),
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
        1_700_000_000,
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
        1_700_000_000,
    ) {
        Decision::Allow(call) => Ok(call),
        Decision::NeedsApproval(pending) => {
            let analyst = ContractAnalyst(SigningKey::from_bytes(&[49; 32]));
            let signature = analyst.0.sign(&pending.challenge());
            pending
                .resolve(&signature.to_bytes(), &analyst, 1_700_000_000)
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
