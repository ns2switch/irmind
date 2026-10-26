#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_testkit::{
        EdrFixture, EdrScenario, FROM, MockResponse, OUTSIDE, RecordedRequest, run_edr_contract,
    };
    use serde_json::json;

    const AGENT: &str = r#"{"data":[{"id":"123","computerName":"host-1","siteId":"456"}]}"#;

    struct Fixture;

    impl EdrFixture for Fixture {
        fn source_id(&self) -> &'static str {
            "s1-test"
        }

        fn build(&self, origin: &str) -> Box<dyn EdrPort> {
            Box::new(SentinelOne {
                async_client: reqwest::Client::builder()
                    .use_rustls_tls()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
                base: Url::parse(origin).unwrap(),
                token: SecretString::from("TEST_TOKEN".to_owned()),
                source_id: self.source_id().into(),
                site_id: "456".into(),
            })
        }

        fn responses(&self, scenario: EdrScenario) -> Vec<MockResponse> {
            match scenario {
                EdrScenario::Host => vec![MockResponse::json(AGENT)],
                EdrScenario::DifferentHost => vec![MockResponse::json(
                    r#"{"data":[{"id":"124","computerName":"host-2","siteId":"456"}]}"#,
                )],
                EdrScenario::AmbiguousHost => vec![MockResponse::json(
                    r#"{"data":[{"id":"123","computerName":"host-1","siteId":"456"},{"id":"124","computerName":"host-1","siteId":"456"}]}"#,
                )],
                EdrScenario::MissingScopeFields => vec![MockResponse::json(
                    r#"{"data":[{"id":"123","siteId":"456"}]}"#,
                )],
                EdrScenario::Detections
                | EdrScenario::CrossHostDetection
                | EdrScenario::CrossScopeDetection
                | EdrScenario::OutsideWindowDetection => {
                    let agent_id = if scenario == EdrScenario::CrossHostDetection {
                        "124"
                    } else {
                        "123"
                    };
                    let at = if scenario == EdrScenario::OutsideWindowDetection {
                        OUTSIDE
                    } else {
                        FROM
                    };
                    let site_id = if scenario == EdrScenario::CrossScopeDetection {
                        "789"
                    } else {
                        "456"
                    };
                    vec![
                        MockResponse::json(AGENT),
                        MockResponse::json(&format!(
                            r#"{{"data":[{{"id":"789","agentRealtimeInfo":{{"agentId":"{agent_id}","siteId":"{site_id}"}},"threatInfo":{{"createdAt":"{at}"}},"email":"alice@example.com"}}]}}"#
                        )),
                    ]
                }
                EdrScenario::HttpError => vec![MockResponse::status(503)],
                EdrScenario::OversizedResponse => vec![MockResponse {
                    status: 200,
                    body: vec![b'X'; 5_000_001],
                    location: None,
                    delay: Duration::ZERO,
                }],
                EdrScenario::Redirect => vec![MockResponse::redirect()],
                EdrScenario::ProcessTree => vec![
                    MockResponse::json(AGENT),
                    MockResponse::json(
                        r#"{"data":[{"id":"789","agentRealtimeInfo":{"agentId":"123","siteId":"456"}}]}"#,
                    ),
                    MockResponse::json(
                        r#"{"data":[{"id":"event1","eventType":"PROCESSCREATION"}]}"#,
                    ),
                ],
                EdrScenario::ProcessTreeCrossHost => vec![
                    MockResponse::json(AGENT),
                    MockResponse::json(
                        r#"{"data":[{"id":"789","agentRealtimeInfo":{"agentId":"124","siteId":"456"}}]}"#,
                    ),
                ],
            }
        }

        fn check_requests(
            &self,
            scenario: EdrScenario,
            requests: &[RecordedRequest],
        ) -> Result<(), String> {
            if requests.len() != self.responses(scenario).len() {
                return Err("unexpected SentinelOne request count".into());
            }
            let first = &requests[0];
            if first.method != "GET"
                || !first.target.starts_with("/web/api/v2.1/agents?")
                || !first.target.contains("siteIds=456")
                || !first.target.contains("computerName=host-1")
                || !first.target.contains("limit=2")
                || first.headers.get("authorization").map(String::as_str)
                    != Some("ApiToken TEST_TOKEN")
            {
                return Err("SentinelOne agent request is unscoped or unauthenticated".into());
            }
            if requests.len() >= 2 {
                let threat = &requests[1];
                if threat.method != "GET"
                    || !threat.target.starts_with("/web/api/v2.1/threats?")
                    || !threat.target.contains("siteIds=456")
                    || !threat.target.contains("agentIds=123")
                    || threat.headers.get("authorization").map(String::as_str)
                        != Some("ApiToken TEST_TOKEN")
                {
                    return Err("SentinelOne threat request is unscoped or unauthenticated".into());
                }
                if matches!(
                    scenario,
                    EdrScenario::ProcessTree | EdrScenario::ProcessTreeCrossHost
                ) {
                    if !threat.target.contains("ids=789") {
                        return Err("process threat ID missing".into());
                    }
                } else if !threat.target.contains("createdAt__gte=")
                    || !threat.target.contains("createdAt__lte=")
                    || !threat.target.contains("limit=20")
                {
                    return Err("SentinelOne detection window or limit missing".into());
                }
            }
            if requests.len() == 3 {
                let tree = &requests[2];
                if tree.method != "GET"
                    || !tree
                        .target
                        .starts_with("/web/api/v2.1/threats/789/explore/events?")
                    || !tree.target.contains("eventId=event1")
                    || !tree.target.contains("limit=20")
                {
                    return Err("SentinelOne process tree request is unbounded".into());
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
    fn rejects_unsafe_identifiers_and_invalid_windows() {
        assert!(safe_host("host-1.example"));
        assert!(!safe_host("host' OR true"));
        assert!(!digits("123/456"));
        assert!(!within(
            Some("2026-10-23T13:00:00Z"),
            "2026-10-23T14:00:00Z",
            "2026-10-23T15:00:00Z"
        ));
    }

    #[test]
    fn rejects_ambiguous_agents_and_cross_site_threats() {
        let agent = json!({"data":[{"id":"123","computerName":"HOST-1","siteId":"456"}]});
        assert!(select_agent(&agent, "host-1", "456").is_ok());
        assert!(select_agent(&agent, "host-1", "789").is_err());
        assert!(
            select_agent(
                &json!({"data":[agent["data"][0],agent["data"][0]]}),
                "host-1",
                "456"
            )
            .is_err()
        );
        let from = "2026-10-23T12:00:00Z";
        let to = "2026-10-23T13:00:00Z";
        let threat = json!({"data":[{"agentRealtimeInfo":{"agentId":"123","siteId":"456"},"threatInfo":{"createdAt":from}}]});
        assert!(validate_threats(&threat, "123", "456", from, to).is_ok());
        assert!(validate_threats(&threat, "123", "789", from, to).is_err());
        assert!(validate_threats(&threat, "789", "456", from, to).is_err());
    }
}
