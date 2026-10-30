use super::{AppError, ModuleConfig, StorageObject, connector::SafeConnector};
use secrecy::ExposeSecret as _;
use std::sync::Arc;

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn require_identifier(config: &ModuleConfig, field: &str) -> Result<String, AppError> {
    let value = config.required_value(field)?;
    if !valid_identifier(value) {
        return Err(AppError::Policy("invalid object storage identifier".into()));
    }
    Ok(value.to_owned())
}

fn checked_endpoint(config: &ModuleConfig, field: &str) -> Result<Option<String>, AppError> {
    let Some(value) = config.value(field) else {
        return Ok(None);
    };
    let parsed = url::Url::parse(value)
        .map_err(|_| AppError::Policy("invalid object storage endpoint".into()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AppError::Policy(
            "object storage endpoint must use HTTPS".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

#[cfg(feature = "gcs")]
fn checked_service_account(config: &ModuleConfig) -> Result<&str, AppError> {
    let key = config
        .required_secret("GCP_SERVICE_ACCOUNT_JSON")?
        .expose_secret();
    if key.len() > 64 * 1024 {
        return Err(AppError::Policy(
            "GCS service account key is invalid".into(),
        ));
    }
    let document: serde_json::Value = serde_json::from_str(key)
        .map_err(|_| AppError::Policy("GCS service account key is invalid".into()))?;
    if document.get("type").and_then(serde_json::Value::as_str) != Some("service_account")
        || document
            .get("private_key")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        || document
            .get("client_email")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        || document
            .get("token_uri")
            .and_then(serde_json::Value::as_str)
            != Some("https://oauth2.googleapis.com/token")
    {
        return Err(AppError::Policy(
            "GCS service account key is invalid".into(),
        ));
    }
    Ok(key)
}

#[cfg(feature = "s3")]
impl StorageObject {
    pub fn from_s3_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let source_id = require_identifier(config, "IRMIND_STORAGE_S3_SOURCE_ID")?;
        let container = require_identifier(config, "IRMIND_STORAGE_S3_BUCKET")?;
        let region = require_identifier(config, "IRMIND_STORAGE_S3_REGION")?;
        let ca = irmind_http::load_optional_ca(
            config.value("IRMIND_STORAGE_S3_CA_PEM"),
            config.value("IRMIND_STORAGE_S3_CA_SHA256"),
        )
        .map_err(|error| AppError::Policy(error.to_string()))?;
        let mut builder = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(&container)
            .with_region(region)
            .with_access_key_id(config.required_secret("AWS_ACCESS_KEY_ID")?.expose_secret())
            .with_secret_access_key(
                config
                    .required_secret("AWS_SECRET_ACCESS_KEY")?
                    .expose_secret(),
            )
            .with_http_connector(SafeConnector { ca });
        if let Some(token) = config.secret("AWS_SESSION_TOKEN") {
            builder = builder.with_token(token.expose_secret());
        }
        if let Some(endpoint) = checked_endpoint(config, "IRMIND_STORAGE_S3_ENDPOINT")? {
            builder = builder.with_endpoint(endpoint);
        }
        let store = builder
            .build()
            .map_err(|_| AppError::Policy("S3 storage configuration is invalid".into()))?;
        Ok(Self {
            source_id,
            container,
            scheme: "s3",
            store: Arc::new(store),
            manifest: &super::S3_MANIFEST,
        })
    }
}

#[cfg(feature = "gcs")]
impl StorageObject {
    pub fn from_gcs_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let source_id = require_identifier(config, "IRMIND_STORAGE_GCS_SOURCE_ID")?;
        let container = require_identifier(config, "IRMIND_STORAGE_GCS_BUCKET")?;
        let mut builder = object_store::gcp::GoogleCloudStorageBuilder::new()
            .with_bucket_name(&container)
            .with_service_account_key(checked_service_account(config)?)
            .with_base_url("https://storage.googleapis.com")
            .with_http_connector(SafeConnector::default());
        if let Some(endpoint) = checked_endpoint(config, "IRMIND_STORAGE_GCS_ENDPOINT")? {
            builder = builder.with_base_url(&endpoint);
        }
        let store = builder
            .build()
            .map_err(|_| AppError::Policy("GCS storage configuration is invalid".into()))?;
        Ok(Self {
            source_id,
            container,
            scheme: "gs",
            store: Arc::new(store),
            manifest: &super::GCS_MANIFEST,
        })
    }
}

#[cfg(feature = "azure")]
impl StorageObject {
    pub fn from_azure_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let source_id = require_identifier(config, "IRMIND_STORAGE_AZURE_SOURCE_ID")?;
        let container = require_identifier(config, "IRMIND_STORAGE_AZURE_CONTAINER")?;
        let account = require_identifier(config, "IRMIND_STORAGE_AZURE_ACCOUNT")?;
        let client_id = require_identifier(config, "IRMIND_STORAGE_AZURE_CLIENT_ID")?;
        let tenant_id = require_identifier(config, "IRMIND_STORAGE_AZURE_TENANT_ID")?;
        let mut builder = object_store::azure::MicrosoftAzureBuilder::new()
            .with_account(account)
            .with_container_name(&container)
            .with_client_id(client_id)
            .with_tenant_id(tenant_id)
            .with_client_secret(
                config
                    .required_secret("AZURE_CLIENT_SECRET")?
                    .expose_secret(),
            )
            .with_http_connector(SafeConnector::default());
        if let Some(endpoint) = checked_endpoint(config, "IRMIND_STORAGE_AZURE_ENDPOINT")? {
            builder = builder.with_endpoint(endpoint);
        }
        let store = builder
            .build()
            .map_err(|_| AppError::Policy("Azure Blob storage configuration is invalid".into()))?;
        Ok(Self {
            source_id,
            container,
            scheme: "az",
            store: Arc::new(store),
            manifest: &super::AZURE_MANIFEST,
        })
    }
}

#[cfg(test)]
mod tests;
