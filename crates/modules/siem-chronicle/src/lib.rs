#![forbid(unsafe_code)]
//! Experimental Google `SecOps` reads with explicit credentials and structured YARA-L.
mod auth;
mod config;
mod detections;
mod query;
mod response;
mod source;
pub use config::MANIFEST;
use irmind_app::{
    AppError, CancellationToken, SiemPort, async_trait,
    modules::{Module, ModuleConfig, ModuleManifest, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};
use secrecy::ExposeSecret as _;
pub use source::ChronicleSourceDecoder;

pub struct Chronicle {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    token_endpoint: reqwest::Url,
    credentials: auth::Credentials,
    source_id: String,
    resource: String,
    account_field: String,
    project: String,
    scope_mode: irmind_app::SiemScopeMode,
    rule_id: Option<String>,
}
impl std::fmt::Debug for Chronicle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chronicle").finish_non_exhaustive()
    }
}
impl Module for Chronicle {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_source_decoder(std::sync::Arc::new(ChronicleSourceDecoder))?;
        let scope = match self.scope_mode {
            irmind_app::SiemScopeMode::EventAccount => None,
            irmind_app::SiemScopeMode::Instance => {
                let parts = self.resource.split('/').collect::<Vec<_>>();
                Some(irmind_app::SiemSourceScope::instance(
                    &self.source_id,
                    MANIFEST.id,
                    &self.project,
                    parts[3],
                    parts[5],
                )?)
            }
        };
        registry.add_siem(self)?;
        if let Some(scope) = scope {
            registry.add_siem_scope(scope)?;
        }
        Ok(())
    }
}
#[async_trait]
impl SiemPort for Chronicle {
    fn source_id(&self) -> &str {
        &self.source_id
    }
    fn dialect(&self) -> &'static str {
        "Google SecOps v1alpha YARA-L generated from structured fields"
    }
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(45),
            self.execute_read(call, cancel),
        )
        .await
        .map_err(|_| AppError::RemoteTool)?
    }
}
fn invalid_config() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
        irmind_app::AdapterPolicyError::InvalidChronicleConfiguration,
    ))
}
fn invalid_query() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
        irmind_app::AdapterPolicyError::InvalidChronicleQuery,
    ))
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

impl Chronicle {
    async fn execute_read(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if call.arg("source") != Some(self.source_id()) {
            return Err(invalid_query());
        }
        self.check_scope(call)?;
        if call.tool() == &Tool::SiemGetAlert {
            return self.detections(call, cancel).await;
        }
        if call.tool() != &Tool::SiemSearch {
            return Err(invalid_query());
        }
        let endpoint = self.search_url(call)?;
        let token = self
            .credentials
            .token(&self.client, &self.token_endpoint, cancel)
            .await?;
        let raw = self
            .read(endpoint, token.expose_secret(), 5_000_000, cancel)
            .await?;
        response::validate(&raw, call)?;
        Ok(raw)
    }
    fn check_scope(&self, call: &AuthorizedCall) -> Result<(), AppError> {
        if self.scope_mode == irmind_app::SiemScopeMode::Instance
            && call.arg("account") != Some(self.project.as_str())
        {
            return Err(invalid_query());
        }
        Ok(())
    }
    async fn read(
        &self,
        endpoint: reqwest::Url,
        token: &str,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            response = self.client.get(endpoint).bearer_auth(token).send() => response.map_err(|_| AppError::RemoteTool)?,
        };
        if !response.status().is_success() {
            return Err(AppError::RemoteTool);
        }
        irmind_http::read_limited(response, limit, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                _ => AppError::RemoteTool,
            })
    }
}
