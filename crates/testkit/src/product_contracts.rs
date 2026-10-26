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
        evaluate(
            &case,
            proposal.clone(),
            1,
            ExecutionMode::Attended,
            1_700_000_000
        ),
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
