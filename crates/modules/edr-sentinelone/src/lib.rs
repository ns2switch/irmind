#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, EdrPort,
    modules::{ConfigField, Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use reqwest::{
    Url,
    blocking::{Client, RequestBuilder},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::{io::Read as _, time::Duration};

pub struct SentinelOne {
    client: Client,
    base: Url,
    token: SecretString,
    source_id: String,
    site_id: String,
}

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "edr-sentinelone",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrHostInfo, Tool::EdrProcessTree, Tool::EdrDetections],
    config: &[
        ConfigField {
            name: "IRMIND_SENTINELONE_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_SITE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_API_TOKEN",
            required: true,
            secret: true,
        },
    ],
};

impl Module for SentinelOne {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_edr(self)
    }
}

impl SentinelOne {
    pub fn from_env() -> Result<Self, AppError> {
        let setting = |name| {
            std::env::var(name)
                .map_err(|_| AppError::Policy(format!("{name} is required for SentinelOne")))
        };
        let base = Url::parse(&setting("IRMIND_SENTINELONE_URL")?)
            .map_err(|_| AppError::Policy("invalid SentinelOne URL".into()))?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(AppError::Policy(
                "SentinelOne URL must be an HTTPS origin".into(),
            ));
        }
        let source_id = setting("IRMIND_SENTINELONE_SOURCE_ID")?;
        if !safe_id(&source_id) {
            return Err(AppError::Policy("invalid SentinelOne source ID".into()));
        }
        let site_id = setting("IRMIND_SENTINELONE_SITE_ID")?;
        if !digits(&site_id) {
            return Err(AppError::Policy("invalid SentinelOne site ID".into()));
        }
        let token = setting("IRMIND_SENTINELONE_API_TOKEN")?;
        if token.trim().is_empty() {
            return Err(AppError::Policy("empty SentinelOne API token".into()));
        }
        let client = Self::http_client()?;
        Ok(Self {
            client,
            base,
            token: SecretString::from(token),
            source_id,
            site_id,
        })
    }

    fn http_client() -> Result<Client, AppError> {
        Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Storage("cannot create SentinelOne HTTP client".into()))
    }

    fn endpoint(&self, path: &str) -> Result<Url, AppError> {
        self.base
            .join(path)
            .map_err(|_| AppError::Policy("invalid SentinelOne endpoint".into()))
    }

    fn get(&self, path: &str, params: &[(&str, &str)]) -> Result<Value, AppError> {
        let url = self.endpoint(path)?;
        Self::request(
            self.client
                .get(url)
                .header(
                    "Authorization",
                    format!("ApiToken {}", self.token.expose_secret()),
                )
                .query(params),
        )
    }

    fn request(request: RequestBuilder) -> Result<Value, AppError> {
        let mut response = request
            .send()
            .map_err(|_| AppError::Storage("SentinelOne request failed".into()))?;
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "SentinelOne returned status {}",
                response.status()
            )));
        }
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(5_000_001)
            .read_to_end(&mut raw)
            .map_err(|_| AppError::Storage("SentinelOne response failed".into()))?;
        if raw.len() > 5_000_000 {
            return Err(AppError::Policy("SentinelOne response exceeds 5 MB".into()));
        }
        serde_json::from_slice(&raw)
            .map_err(|_| AppError::Storage("invalid SentinelOne JSON".into()))
    }

    fn checked_call<'a>(&self, call: &'a AuthorizedCall, tool: &Tool) -> Result<&'a str, AppError> {
        if call.tool() != tool || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Policy("wrong SentinelOne source or tool".into()));
        }
        let host = call
            .arg("host")
            .ok_or_else(|| AppError::Policy("missing host".into()))?;
        if !safe_host(host) {
            return Err(AppError::Policy("invalid SentinelOne host".into()));
        }
        Ok(host)
    }

    fn agent(&self, host: &str) -> Result<Value, AppError> {
        let response = self.get(
            "/web/api/v2.1/agents",
            &[
                ("siteIds", &self.site_id),
                ("computerName", host),
                ("limit", "2"),
            ],
        )?;
        select_agent(&response, host, &self.site_id)
    }

    fn agent_id(agent: &Value) -> Result<&str, AppError> {
        agent["id"]
            .as_str()
            .filter(|id| digits(id))
            .ok_or_else(|| AppError::Storage("SentinelOne agent has no valid ID".into()))
    }
}

impl EdrPort for SentinelOne {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn supports(&self, tool: &Tool) -> bool {
        matches!(
            tool,
            Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections
        )
    }
    fn process_tree_hint(&self) -> Option<&'static str> {
        Some("use threat_id:event_id from a threat's Explore process event")
    }

    fn host_info(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrHostInfo)?;
        encode(&self.agent(host)?)
    }

    fn detections(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrDetections)?;
        let (from, to) = window(call)?;
        let agent = self.agent(host)?;
        let id = Self::agent_id(&agent)?;
        let response = self.get(
            "/web/api/v2.1/threats",
            &[
                ("siteIds", &self.site_id),
                ("agentIds", id),
                ("createdAt__gte", from),
                ("createdAt__lte", to),
                ("limit", "20"),
            ],
        )?;
        validate_threats(&response, id, &self.site_id, from, to)?;
        encode(&response)
    }

    fn process_tree(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrProcessTree)?;
        let process_id = call
            .arg("process_id")
            .ok_or_else(|| AppError::Policy("missing process ID".into()))?;
        let (threat_id, event_id) = process_id.split_once(':').ok_or_else(|| {
            AppError::Policy("SentinelOne process ID must be threat_id:event_id".into())
        })?;
        if !digits(threat_id) || !safe_id(event_id) {
            return Err(AppError::Policy("invalid SentinelOne process ID".into()));
        }
        let agent = self.agent(host)?;
        let id = Self::agent_id(&agent)?;
        let threats = self.get(
            "/web/api/v2.1/threats",
            &[
                ("siteIds", &self.site_id),
                ("agentIds", id),
                ("ids", threat_id),
                ("limit", "2"),
            ],
        )?;
        let rows = data_array(&threats)?;
        if rows.len() != 1
            || rows[0]["id"].as_str() != Some(threat_id)
            || rows[0]["agentRealtimeInfo"]["agentId"].as_str() != Some(id)
            || rows[0]["agentRealtimeInfo"]["siteId"].as_str() != Some(&self.site_id)
        {
            return Err(AppError::Policy(
                "SentinelOne threat is outside the selected host".into(),
            ));
        }
        let path = format!("/web/api/v2.1/threats/{threat_id}/explore/events");
        let events = self.get(&path, &[("eventId", event_id), ("limit", "20")])?;
        if data_array(&events)?.len() > 20 {
            return Err(AppError::Policy(
                "SentinelOne process tree exceeds limit".into(),
            ));
        }
        encode(&events)
    }
}

fn data_array(value: &Value) -> Result<&Vec<Value>, AppError> {
    value["data"]
        .as_array()
        .ok_or_else(|| AppError::Storage("SentinelOne response has no data array".into()))
}
fn select_agent(response: &Value, host: &str, site_id: &str) -> Result<Value, AppError> {
    let data = data_array(response)?;
    if data.len() != 1
        || !data[0]["computerName"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(host))
        || data[0]["siteId"].as_str() != Some(site_id)
    {
        return Err(AppError::Policy(
            "SentinelOne host is missing or ambiguous".into(),
        ));
    }
    Ok(data[0].clone())
}
fn validate_threats(
    response: &Value,
    id: &str,
    site_id: &str,
    from: &str,
    to: &str,
) -> Result<(), AppError> {
    for threat in data_array(response)? {
        if threat["agentRealtimeInfo"]["agentId"].as_str() != Some(id)
            || threat["agentRealtimeInfo"]["siteId"].as_str() != Some(site_id)
            || !within(threat["threatInfo"]["createdAt"].as_str(), from, to)
        {
            return Err(AppError::Policy(
                "SentinelOne returned a threat outside the host or window".into(),
            ));
        }
    }
    Ok(())
}
fn encode(value: &Value) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(value)
        .map_err(|_| AppError::Storage("cannot encode SentinelOne evidence".into()))
}
fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
fn digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_digit())
}
fn safe_host(value: &str) -> bool {
    safe_id(value) && value.len() <= 253
}
fn window(call: &AuthorizedCall) -> Result<(&str, &str), AppError> {
    let from = call
        .arg("from")
        .ok_or_else(|| AppError::Policy("missing start time".into()))?;
    let to = call
        .arg("to")
        .ok_or_else(|| AppError::Policy("missing end time".into()))?;
    let start = DateTime::parse_from_rfc3339(from)
        .map_err(|_| AppError::Policy("invalid start time".into()))?;
    let end = DateTime::parse_from_rfc3339(to)
        .map_err(|_| AppError::Policy("invalid end time".into()))?;
    if !(1..=86_400).contains(&end.signed_duration_since(start).num_seconds()) {
        return Err(AppError::Policy(
            "SentinelOne detection window must be at most 24 hours".into(),
        ));
    }
    Ok((from, to))
}
fn within(value: Option<&str>, from: &str, to: &str) -> bool {
    let Some(value) = value else { return false };
    let (Ok(value), Ok(from), Ok(to)) = (
        DateTime::parse_from_rfc3339(value),
        DateTime::parse_from_rfc3339(from),
        DateTime::parse_from_rfc3339(to),
    ) else {
        return false;
    };
    value >= from && value <= to
}

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
                client: SentinelOne::http_client().unwrap(),
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
