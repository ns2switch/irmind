#![forbid(unsafe_code)]
//! Read-only structured Elasticsearch queries; credentials are injected at composition.
mod config;
mod query;
mod response;
mod source;
pub use config::MANIFEST;
use irmind_app::{
    AppError, CancellationToken, SiemPort, async_trait,
    modules::{Module, ModuleConfig, ModuleManifest, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
pub use source::ElasticSourceDecoder;

pub struct Elastic {
    client: reqwest::Client,
    origin: reqwest::Url,
    key: SecretString,
    source_id: String,
    indices: String,
    alert_alias: String,
    account_field: String,
}
impl std::fmt::Debug for Elastic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elastic").finish_non_exhaustive()
    }
}
impl Module for Elastic {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(ElasticSourceDecoder))?;
        registry.add_siem(self)
    }
}
impl Elastic {
    async fn request(
        &self,
        endpoint: reqwest::Url,
        body: &Value,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            response = self.client.post(endpoint)
                .header(reqwest::header::AUTHORIZATION, format!("ApiKey {}", self.key.expose_secret()))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(body).map_err(|_| invalid_query())?).send() => response.map_err(|_| AppError::RemoteTool)?,
        };
        if !response.status().is_success() {
            return Err(AppError::RemoteTool);
        }
        irmind_http::read_limited(response, 5_000_000, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                _ => AppError::RemoteTool,
            })
    }
    fn endpoint(&self, alert: bool) -> Result<reqwest::Url, AppError> {
        let mut endpoint = self.origin.clone();
        endpoint
            .path_segments_mut()
            .map_err(|()| invalid_query())?
            .push(if alert {
                &self.alert_alias
            } else {
                &self.indices
            })
            .push("_search");
        Ok(endpoint)
    }
}
#[async_trait]
impl SiemPort for Elastic {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn dialect(&self) -> &'static str {
        "Elasticsearch Query DSL generated from structured fields"
    }
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if call.arg("source") != Some(self.source_id())
            || !matches!(call.tool(), Tool::SiemSearch | Tool::SiemGetAlert)
        {
            return Err(invalid_query());
        }
        let body = self.query(call)?;
        let raw = self
            .request(
                self.endpoint(call.tool() == &Tool::SiemGetAlert)?,
                &body,
                cancel,
            )
            .await?;
        response::validate(&raw, call)?;
        Ok(raw)
    }
}
fn invalid_query() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
        irmind_app::AdapterPolicyError::InvalidElasticQuery,
    ))
}
fn invalid_config() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
        irmind_app::AdapterPolicyError::InvalidElasticConfiguration,
    ))
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
