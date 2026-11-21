use super::{
    AppError, AzureLogAnalytics, CancellationToken, CompiledSourceQueryV1, QueryResponsePage,
    SecretString, SourceQueryError, json,
};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use zeroize::Zeroizing;

const CONTROL_LIMIT: usize = 64 * 1024;
const ARM_SCOPE: &str = "https://management.azure.com/.default";
const LOGS_SCOPE: &str = "https://api.loganalytics.io/.default";

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(deserialize_with = "secret_field")]
    access_token: SecretString,
    token_type: String,
}

fn secret_field<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::from)
}

impl AzureLogAnalytics {
    async fn token(
        &self,
        audience: &str,
        cancel: &CancellationToken,
    ) -> Result<SecretString, AppError> {
        let request = self.client.post(self.identity.clone()).form(&[
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret()),
            ("scope", audience),
        ]);
        let response = send(request, cancel).await?;
        let bytes = Zeroizing::new(read(response, cancel).await?);
        let token: TokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| AppError::RemoteTool)?;
        if token.token_type != "Bearer"
            || token.access_token.expose_secret().is_empty()
            || token.access_token.expose_secret().len() > 8192
            || !token
                .access_token
                .expose_secret()
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(AppError::RemoteTool);
        }
        Ok(token.access_token)
    }

    pub(super) async fn analytics_plan(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let token = self.token(ARM_SCOPE, cancel).await?;
        let workspace_path = self
            .table_path
            .rsplit_once("/tables/")
            .ok_or(SourceQueryError::Invalid)?
            .0;
        let workspace = self.arm_get(workspace_path, &token, cancel).await?;
        if workspace["properties"]["customerId"] != self.source.owner()
            || workspace["location"]
                .as_str()
                .is_none_or(|region| !region.eq_ignore_ascii_case(self.source.location()))
        {
            return Err(SourceQueryError::Scope.into());
        }
        let table = self.arm_get(&self.table_path, &token, cancel).await?;
        let properties = &table["properties"];
        if table["name"] != self.source.table()
            || properties["plan"] != "Analytics"
            || properties["provisioningState"] != "Succeeded"
        {
            return Err(SourceQueryError::Unavailable.into());
        }
        let retention = properties["retentionInDays"]
            .as_u64()
            .filter(|days| (1..=730).contains(days))
            .ok_or(SourceQueryError::Invalid)?;
        Ok(json!({"plan":"Analytics","provisioning_state":"Succeeded",
            "interactive_retention_days":retention,"last_plan_modified_at":properties["lastPlanModifiedDate"]}))
    }

    async fn arm_get(
        &self,
        path: &str,
        token: &SecretString,
        cancel: &CancellationToken,
    ) -> Result<Value, AppError> {
        let url = self.arm.join(path).map_err(|_| SourceQueryError::Invalid)?;
        let request = self
            .client
            .get(url)
            .query(&[("api-version", "2025-07-01")])
            .bearer_auth(token.expose_secret());
        let response = send(request, cancel).await?;
        serde_json::from_slice(&read(response, cancel).await?).map_err(|_| AppError::RemoteTool)
    }

    pub(super) async fn query(
        &self,
        compiled: &CompiledSourceQueryV1,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, AppError> {
        let [from, to] = compiled.bindings() else {
            return Err(SourceQueryError::Invalid.into());
        };
        let from = from.value.as_str().ok_or(SourceQueryError::Invalid)?;
        let to = to.value.as_str().ok_or(SourceQueryError::Invalid)?;
        let timespan = format!("{from}/{to}");
        let token = self.token(LOGS_SCOPE, cancel).await?;
        let path = format!("workspaces/{}/query", self.source.owner());
        let url = self
            .logs
            .join(&path)
            .map_err(|_| SourceQueryError::Invalid)?;
        let raw = serde_json::to_vec(&json!({"query":compiled.text(),"timespan":timespan}))
            .map_err(|_| AppError::RemoteTool)?;
        let response = send(
            self.client
                .post(url)
                .bearer_auth(token.expose_secret())
                .header("content-type", "application/json")
                .header("prefer", format!("wait={}", self.limits.deadline_seconds))
                .body(raw),
            cancel,
        )
        .await?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|len| len > self.limits.retained_bytes)
        {
            return Err(AppError::RemoteTool);
        }
        Ok(response)
    }

    pub(super) fn single_page(
        &self,
        response: reqwest::Response,
        request_id: String,
        cancel: &CancellationToken,
    ) -> QueryResponsePage {
        let limit = self.limits.retained_bytes;
        let cancel = cancel.clone();
        let initial = Some((response, 0u64, cancel));
        let chunks = Box::pin(futures_util::stream::unfold(
            initial,
            move |state| async move {
                let (mut response, count, cancel) = state?;
                let chunk = tokio::select! { biased;
                    () = cancel.cancelled() => return Some((Err(AppError::Cancelled), None)),
                    chunk = response.chunk() => match chunk {
                        Ok(chunk) => chunk?,
                        Err(_) => return Some((Err(AppError::RemoteTool),None)),
                    },
                };
                let next = count.saturating_add(chunk.len() as u64);
                if next > limit {
                    return Some((Err(SourceQueryError::Limit.into()), None));
                }
                Some((Ok(chunk.to_vec()), Some((response, next, cancel))))
            },
        ));
        QueryResponsePage {
            request_id: Some(request_id),
            next_token: None,
            content_encoding: "identity".into(),
            chunks,
        }
    }
}

async fn send(
    request: reqwest::RequestBuilder,
    cancel: &CancellationToken,
) -> Result<reqwest::Response, AppError> {
    tokio::select! { biased;
        () = cancel.cancelled() => Err(AppError::Cancelled),
        response = request.send() => response.map_err(|_| AppError::RemoteTool),
    }
}

async fn read(
    response: reqwest::Response,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    if !response.status().is_success() {
        return Err(AppError::RemoteTool);
    }
    irmind_http::read_limited(response, CONTROL_LIMIT, cancel)
        .await
        .map_err(|error| match error {
            irmind_http::BodyError::Cancelled => AppError::Cancelled,
            _ => AppError::RemoteTool,
        })
}
