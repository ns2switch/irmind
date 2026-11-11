use super::{AppError, Chronicle, ModuleConfig, ModuleManifest, Tool, auth, invalid_config};
use irmind_app::modules::{ConfigField, ModulePort};
use std::time::Duration;
const fn setting(name: &'static str, required: bool) -> ConfigField {
    ConfigField {
        name,
        required,
        secret: false,
    }
}
pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "siem-chronicle",
    version: "0.1.0",
    ports: &[ModulePort::Siem, ModulePort::SourceDecoder],
    tools: &[Tool::SiemSearch],
    config: &[
        setting("IRMIND_CHRONICLE_URL", true),
        setting("IRMIND_CHRONICLE_SOURCE_ID", true),
        setting("IRMIND_CHRONICLE_PROJECT", true),
        setting("IRMIND_CHRONICLE_LOCATION", true),
        setting("IRMIND_CHRONICLE_INSTANCE", true),
        setting("IRMIND_CHRONICLE_ACCOUNT_FIELD", true),
        setting("IRMIND_CHRONICLE_CA_PEM", false),
        setting("IRMIND_CHRONICLE_CA_SHA256", false),
        ConfigField {
            name: "IRMIND_CHRONICLE_SERVICE_ACCOUNT_JSON",
            required: true,
            secret: true,
        },
    ],
};
impl Chronicle {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let setting = |name| config.required_value(name).map_err(|_| invalid_config());
        let endpoint =
            reqwest::Url::parse(setting("IRMIND_CHRONICLE_URL")?).map_err(|_| invalid_config())?;
        if endpoint.scheme() != "https"
            || endpoint.path() != "/"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.port().is_some_and(|p| p != 443)
        {
            return Err(invalid_config());
        }
        let project = setting("IRMIND_CHRONICLE_PROJECT")?;
        let location = setting("IRMIND_CHRONICLE_LOCATION")?;
        let instance = setting("IRMIND_CHRONICLE_INSTANCE")?;
        let source_id = setting("IRMIND_CHRONICLE_SOURCE_ID")?;
        if ![project, location, instance, source_id]
            .iter()
            .all(|v| identifier(v))
            || endpoint.host_str() != Some(format!("{location}-chronicle.googleapis.com").as_str())
        {
            return Err(invalid_config());
        }
        let account_field = setting("IRMIND_CHRONICLE_ACCOUNT_FIELD")?;
        if account_field.len() > 128
            || account_field.split('.').count() < 2
            || !account_field.split('.').all(field_segment)
        {
            return Err(invalid_config());
        }
        let ca = irmind_http::load_optional_ca(
            config.value("IRMIND_CHRONICLE_CA_PEM"),
            config.value("IRMIND_CHRONICLE_CA_SHA256"),
        )
        .map_err(|_| invalid_config())?;
        let client =
            irmind_http::client_builder_with_ca(Duration::from_secs(45), false, ca.as_ref())
                .build()
                .map_err(|_| invalid_config())?;
        let credentials = auth::Credentials::new(
            config.required_secret("IRMIND_CHRONICLE_SERVICE_ACCOUNT_JSON")?,
        )?;
        Ok(Self {
            client,
            endpoint,
            token_endpoint: auth::token_endpoint()?,
            credentials,
            source_id: source_id.into(),
            resource: format!("projects/{project}/locations/{location}/instances/{instance}"),
            account_field: account_field.into(),
        })
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn field_segment(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
