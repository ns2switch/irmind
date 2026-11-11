use super::{AppError, Elastic, ModuleConfig, ModuleManifest, Tool, invalid_config};
use irmind_app::modules::{ConfigField, ModulePort};
use secrecy::ExposeSecret;
use std::time::Duration;
const fn public(name: &'static str, required: bool) -> ConfigField {
    ConfigField {
        name,
        required,
        secret: false,
    }
}
pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "siem-elastic",
    version: "0.1.0",
    ports: &[ModulePort::Siem, ModulePort::SourceDecoder],
    tools: &[Tool::SiemSearch, Tool::SiemGetAlert],
    config: &[
        public("IRMIND_ELASTIC_URL", true),
        public("IRMIND_ELASTIC_SOURCE_ID", true),
        public("IRMIND_ELASTIC_INDICES", true),
        public("IRMIND_ELASTIC_ALERT_SPACE", true),
        public("IRMIND_ELASTIC_ACCOUNT_FIELD", true),
        public("IRMIND_ELASTIC_CA_PEM", false),
        public("IRMIND_ELASTIC_CA_SHA256", false),
        ConfigField {
            name: "IRMIND_ELASTIC_API_KEY",
            required: true,
            secret: true,
        },
    ],
};
impl Elastic {
    pub fn from_config(config: &ModuleConfig) -> Result<Self, AppError> {
        let required = |name| config.required_value(name).map_err(|_| invalid_config());
        let origin =
            reqwest::Url::parse(required("IRMIND_ELASTIC_URL")?).map_err(|_| invalid_config())?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(invalid_config());
        }
        let source_id = required("IRMIND_ELASTIC_SOURCE_ID")?;
        let indices = required("IRMIND_ELASTIC_INDICES")?;
        let space = required("IRMIND_ELASTIC_ALERT_SPACE")?;
        let account_field = required("IRMIND_ELASTIC_ACCOUNT_FIELD")?;
        if !identifier(source_id)
            || !identifier(space)
            || !field(account_field)
            || !index_patterns(indices)
        {
            return Err(invalid_config());
        }
        let key = config.required_secret("IRMIND_ELASTIC_API_KEY")?;
        if key.expose_secret().is_empty()
            || key.expose_secret().len() > 8192
            || !key
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
        {
            return Err(invalid_config());
        }
        let ca = irmind_http::load_optional_ca(
            config.value("IRMIND_ELASTIC_CA_PEM"),
            config.value("IRMIND_ELASTIC_CA_SHA256"),
        )
        .map_err(|_| invalid_config())?;
        let client =
            irmind_http::client_builder_with_ca(Duration::from_secs(45), false, ca.as_ref())
                .build()
                .map_err(|_| invalid_config())?;
        Ok(Self {
            client,
            origin,
            key: key.clone(),
            source_id: source_id.into(),
            indices: indices.into(),
            alert_alias: format!(".alerts-security.alerts-{space}"),
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
fn field(value: &str) -> bool {
    value.len() <= 128 && value.split('.').all(identifier)
}
fn index_patterns(value: &str) -> bool {
    value.len() <= 1024
        && value.split(',').count() <= 16
        && value.split(',').all(|part| {
            let prefix = part.strip_suffix('*').unwrap_or(part);
            !prefix.is_empty()
                && prefix.len() <= 128
                && prefix.as_bytes()[0].is_ascii_lowercase()
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
}
