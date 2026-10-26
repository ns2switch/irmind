#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_testkit::{
        EdrFixture, EdrScenario, FROM, HOST, MockResponse, OUTSIDE, RecordedRequest,
        run_edr_contract,
    };

    const TOKEN: &str = r#"{"access_token":"TEST_TOKEN"}"#;
    const HOST_RESPONSE: &str = r#"{"resources":[{"hostname":"host-1","device_id":"aid1"}]}"#;

    struct Fixture;

    impl EdrFixture for Fixture {
        fn source_id(&self) -> &'static str {
            "falcon-test"
        }

        fn build(&self, origin: &str) -> Box<dyn EdrPort> {
            Box::new(CrowdStrike {
                async_client: reqwest::Client::builder()
                    .use_rustls_tls()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
                base: Url::parse(origin).unwrap(),
                client_id: SecretString::from("TEST_CLIENT".to_owned()),
                client_secret: SecretString::from("TEST_SECRET".to_owned()),
                source_id: self.source_id().into(),
            })
        }

        fn responses(&self, scenario: EdrScenario) -> Vec<MockResponse> {
            let mut responses = vec![MockResponse::json(TOKEN)];
            match scenario {
                EdrScenario::Host => responses.push(MockResponse::json(HOST_RESPONSE)),
                EdrScenario::DifferentHost => responses.push(MockResponse::json(
                    r#"{"resources":[{"hostname":"host-2","device_id":"aid2"}]}"#,
                )),
                EdrScenario::AmbiguousHost => responses.push(MockResponse::json(
                    r#"{"resources":[{"hostname":"host-1","device_id":"aid1"},{"hostname":"host-1","device_id":"aid2"}]}"#,
                )),
                EdrScenario::MissingScopeFields => responses.push(MockResponse::json(
                    r#"{"resources":[{"device_id":"aid1"}]}"#,
                )),
                EdrScenario::Detections | EdrScenario::CrossHostDetection | EdrScenario::CrossScopeDetection | EdrScenario::OutsideWindowDetection => {
                    responses.push(MockResponse::json(HOST_RESPONSE));
                    let aid = if matches!(scenario, EdrScenario::CrossHostDetection | EdrScenario::CrossScopeDetection) { "aid2" } else { "aid1" };
                    let at = if scenario == EdrScenario::OutsideWindowDetection { OUTSIDE } else { FROM };
                    responses.push(MockResponse::json(&format!(r#"{{"resources":[{{"agent_id":"{aid}","created_timestamp":"{at}","email":"alice@example.com"}}]}}"#)));
                }
                EdrScenario::HttpError => responses.push(MockResponse::status(503)),
                EdrScenario::OversizedResponse => responses.push(MockResponse { status: 200, body: vec![b'X'; 5_000_001], location: None, delay: Duration::ZERO }),
                EdrScenario::Redirect => responses.push(MockResponse::redirect()),
                EdrScenario::ProcessTree | EdrScenario::ProcessTreeCrossHost => responses.clear(),
            }
            responses
        }

        fn check_requests(
            &self,
            scenario: EdrScenario,
            requests: &[RecordedRequest],
        ) -> Result<(), String> {
            if matches!(
                scenario,
                EdrScenario::ProcessTree | EdrScenario::ProcessTreeCrossHost
            ) {
                return if requests.is_empty() {
                    Ok(())
                } else {
                    Err("unsupported process tree made a request".into())
                };
            }
            if requests.len() != self.responses(scenario).len() {
                return Err("unexpected CrowdStrike request count".into());
            }
            let token = &requests[0];
            if token.method != "POST"
                || token.target != "/oauth2/token"
                || !String::from_utf8_lossy(&token.body).contains("client_id=TEST_CLIENT")
                || !String::from_utf8_lossy(&token.body).contains("client_secret=TEST_SECRET")
            {
                return Err("CrowdStrike OAuth request differs from contract".into());
            }
            let host = &requests[1];
            if host.method != "GET"
                || !host.target.starts_with("/devices/combined/devices/v1?")
                || !host.target.contains(HOST)
                || !host.target.contains("limit=2")
                || host.headers.get("authorization").map(String::as_str)
                    != Some("Bearer TEST_TOKEN")
            {
                return Err("CrowdStrike host request is unscoped or unauthenticated".into());
            }
            if requests.len() == 3 {
                let alerts = &requests[2];
                let body: Value =
                    serde_json::from_slice(&alerts.body).map_err(|error| error.to_string())?;
                let filter = body["filter"]
                    .as_str()
                    .ok_or("missing CrowdStrike alert filter")?;
                if alerts.method != "POST"
                    || alerts.target != "/alerts/combined/alerts/v1"
                    || body["limit"] != 20
                    || !filter.contains("agent_id:'aid1'")
                    || !filter.contains(FROM)
                    || !filter.contains(irmind_testkit::TO)
                    || alerts.headers.get("authorization").map(String::as_str)
                        != Some("Bearer TEST_TOKEN")
                {
                    return Err("CrowdStrike alert request is unscoped or unauthenticated".into());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn edr_contract() {
        run_edr_contract(&Fixture).unwrap();
        irmind_testkit::run_http_safety_contract().unwrap();
    }
    #[test]
    fn identifiers_cannot_escape_fql_literals() {
        assert!(safe_host("host-1.example"));
        assert!(!safe_host("host' OR true"));
        assert!(!safe_id("aid+other"));
    }

    #[test]
    fn rejects_ambiguous_hosts_and_cross_host_alerts() {
        let host = json!({"resources":[{"hostname":"HOST-1","device_id":"aid1"}]});
        assert!(select_host(&host, "host-1").is_ok());
        assert!(select_host(&host, "host-2").is_err());
        assert!(
            select_host(
                &json!({"resources":[host["resources"][0],host["resources"][0]]}),
                "host-1"
            )
            .is_err()
        );
        let from = "2026-10-23T12:00:00Z";
        let to = "2026-10-23T13:00:00Z";
        assert!(
            validate_alerts(
                &json!({"resources":[{"agent_id":"aid1","created_timestamp":from}]}),
                "aid1",
                from,
                to
            )
            .is_ok()
        );
        assert!(
            validate_alerts(
                &json!({"resources":[{"agent_id":"aid2","created_timestamp":from}]}),
                "aid1",
                from,
                to
            )
            .is_err()
        );
        assert!(
            validate_alerts(
                &json!({"resources":[{"agent_id":"aid1"}]}),
                "aid1",
                from,
                to
            )
            .is_err()
        );
    }
}
