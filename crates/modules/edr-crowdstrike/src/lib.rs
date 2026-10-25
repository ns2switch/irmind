#![forbid(unsafe_code)]

use chrono::DateTime;
use irmind_app::{
    AppError, CancellationToken, EdrPort, async_trait,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::time::Duration;

pub struct CrowdStrike {
    async_client: reqwest::Client,
    base: Url,
    client_id: SecretString,
    client_secret: SecretString,
    source_id: String,
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "edr-crowdstrike",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrHostInfo, Tool::EdrDetections],
    config: &[
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_CLIENT_ID",
            required: true,
            secret: true,
        },
        ConfigField {
            name: "IRMIND_CROWDSTRIKE_CLIENT_SECRET",
            required: true,
            secret: true,
        },
    ],
};

impl Module for CrowdStrike {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_edr(self)
    }
}

impl CrowdStrike {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let setting = |name| config.required_value(name).map(str::to_owned);
        let base = Url::parse(&setting("IRMIND_CROWDSTRIKE_URL")?)
            .map_err(|_| AppError::Policy("invalid CrowdStrike URL".into()))?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(AppError::Policy(
                "CrowdStrike URL must be an HTTPS origin".into(),
            ));
        }
        let source_id = setting("IRMIND_CROWDSTRIKE_SOURCE_ID")?;
        if !safe_id(&source_id) {
            return Err(AppError::Policy("invalid CrowdStrike source ID".into()));
        }
        let client_id = config
            .required_secret("IRMIND_CROWDSTRIKE_CLIENT_ID")?
            .expose_secret()
            .to_owned();
        let client_secret = config
            .required_secret("IRMIND_CROWDSTRIKE_CLIENT_SECRET")?
            .expose_secret()
            .to_owned();
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return Err(AppError::Policy("empty CrowdStrike credential".into()));
        }
        let async_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Storage("cannot create CrowdStrike HTTP client".into()))?;
        Ok(Self {
            async_client,
            base,
            client_id: SecretString::from(client_id),
            client_secret: SecretString::from(client_secret),
            source_id,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, AppError> {
        self.base
            .join(path)
            .map_err(|_| AppError::Policy("invalid CrowdStrike endpoint".into()))
    }

    fn checked_call<'a>(&self, call: &'a AuthorizedCall, tool: &Tool) -> Result<&'a str, AppError> {
        if call.tool() != tool || call.arg("source") != Some(self.source_id()) {
            return Err(AppError::Policy("wrong CrowdStrike source or tool".into()));
        }
        let host = call
            .arg("host")
            .ok_or_else(|| AppError::Policy("missing host".into()))?;
        if !safe_host(host) {
            return Err(AppError::Policy("invalid CrowdStrike host".into()));
        }
        Ok(host)
    }

    async fn request_async(
        request: reqwest::RequestBuilder,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let mut response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            result = request.send() => result.map_err(|_| AppError::Storage("CrowdStrike request failed".into()))?,
        };
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "CrowdStrike returned status {}",
                response.status()
            )));
        }
        let mut raw = Vec::new();
        loop {
            let chunk = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(AppError::Cancelled),
                result = response.chunk() => result.map_err(|_| AppError::Storage("CrowdStrike response failed".into()))?,
            };
            let Some(chunk) = chunk else {
                break;
            };
            if raw.len().saturating_add(chunk.len()) > 5_000_000 {
                return Err(AppError::Policy("CrowdStrike response exceeds 5 MB".into()));
            }
            raw.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&raw)
            .map_err(|_| AppError::Storage("invalid CrowdStrike JSON".into()))
    }

    async fn token_async(&self, cancel: &CancellationToken) -> Result<SecretString, AppError> {
        let url = self.endpoint("/oauth2/token")?;
        let response = Self::request_async(
            self.async_client.post(url).form(&[
                ("client_id", self.client_id.expose_secret()),
                ("client_secret", self.client_secret.expose_secret()),
            ]),
            cancel,
        )
        .await?;
        let token = response["access_token"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Storage("CrowdStrike token response is invalid".into()))?;
        Ok(SecretString::from(token.to_owned()))
    }

    async fn host_async(
        &self,
        host: &str,
        token: &SecretString,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let url = self.endpoint("/devices/combined/devices/v1")?;
        let filter = format!("hostname:'{host}'");
        let response = Self::request_async(
            self.async_client
                .get(url)
                .bearer_auth(token.expose_secret())
                .query(&[("filter", filter.as_str()), ("limit", "2")]),
            cancel,
        )
        .await?;
        select_host(&response, host)
    }
}

#[async_trait]
impl EdrPort for CrowdStrike {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn supports(&self, tool: &Tool) -> bool {
        matches!(tool, Tool::EdrHostInfo | Tool::EdrDetections)
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        match call.tool() {
            Tool::EdrHostInfo => {
                let host = self.checked_call(call, &Tool::EdrHostInfo)?;
                let token = self.token_async(cancel).await?;
                encode(&self.host_async(host, &token, cancel).await?)
            }
            Tool::EdrDetections => self.detections_async(call, cancel).await,
            Tool::EdrProcessTree => Err(AppError::Policy(
                "CrowdStrike process tree unavailable".into(),
            )),
            _ => Err(AppError::Policy("invalid CrowdStrike tool".into())),
        }
    }
}

impl CrowdStrike {
    async fn detections_async(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let host = self.checked_call(call, &Tool::EdrDetections)?;
        let (from, to) = window(call)?;
        let token = self.token_async(cancel).await?;
        let device = self.host_async(host, &token, cancel).await?;
        let aid = device["device_id"]
            .as_str()
            .filter(|id| safe_id(id))
            .ok_or_else(|| AppError::Storage("CrowdStrike host has no valid device ID".into()))?;
        let filter =
            format!("agent_id:'{aid}'+created_timestamp:>='{from}'+created_timestamp:<='{to}'");
        let url = self.endpoint("/alerts/combined/alerts/v1")?;
        let response = Self::request_async(
            self.async_client
                .post(url)
                .bearer_auth(token.expose_secret())
                .json(&json!({"filter":filter,"limit":20})),
            cancel,
        )
        .await?;
        validate_alerts(&response, aid, from, to)?;
        encode(&response)
    }
}

fn resources(value: &Value) -> Result<&Vec<Value>, AppError> {
    value["resources"]
        .as_array()
        .ok_or_else(|| AppError::Storage("CrowdStrike response has no resources array".into()))
}
fn select_host(response: &Value, host: &str) -> Result<Value, AppError> {
    let rows = resources(response)?;
    if rows.len() != 1
        || rows[0]["hostname"]
            .as_str()
            .is_none_or(|actual| !actual.eq_ignore_ascii_case(host))
    {
        return Err(AppError::Policy(
            "CrowdStrike host is missing or ambiguous".into(),
        ));
    }
    Ok(rows[0].clone())
}
fn validate_alerts(response: &Value, aid: &str, from: &str, to: &str) -> Result<(), AppError> {
    for alert in resources(response)? {
        if alert["agent_id"].as_str() != Some(aid)
            || !within(alert["created_timestamp"].as_str(), from, to)
        {
            return Err(AppError::Policy(
                "CrowdStrike returned an alert outside the host or window".into(),
            ));
        }
    }
    Ok(())
}
fn encode(value: &Value) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(value)
        .map_err(|_| AppError::Storage("cannot encode CrowdStrike evidence".into()))
}
fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
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
            "CrowdStrike detection window must be at most 24 hours".into(),
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
                EdrScenario::OversizedResponse => responses.push(MockResponse { status: 200, body: vec![b'X'; 5_000_001], location: None }),
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
