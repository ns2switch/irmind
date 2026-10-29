use super::*;
#[cfg(any(feature = "s3", feature = "gcs"))]
use secrecy::SecretString;

#[test]
fn endpoint_cannot_contain_credentials_or_query() {
    for endpoint in [
        "https://user:secret@example.invalid/",
        "https://example.invalid/?token=secret",
        "https://example.invalid/#secret",
    ] {
        let mut config = ModuleConfig::new();
        config.insert_value("ENDPOINT", endpoint.into());
        assert!(checked_endpoint(&config, "ENDPOINT").is_err());
    }
}

#[cfg(feature = "s3")]
fn s3_config() -> ModuleConfig {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_STORAGE_S3_SOURCE_ID", "storage-test".into());
    config.insert_value("IRMIND_STORAGE_S3_BUCKET", "test-bucket".into());
    config.insert_value("IRMIND_STORAGE_S3_REGION", "us-east-1".into());
    config.insert_secret(
        "AWS_ACCESS_KEY_ID",
        SecretString::from("synthetic-key".to_owned()),
    );
    config.insert_secret(
        "AWS_SECRET_ACCESS_KEY",
        SecretString::from("synthetic-secret".to_owned()),
    );
    config
}

#[cfg(feature = "s3")]
#[test]
fn s3_uses_only_explicit_credentials_and_rejects_plain_http() {
    let mut config = s3_config();
    assert!(StorageObject::from_s3_config(&config).is_ok());
    config.insert_value("IRMIND_STORAGE_S3_ENDPOINT", "http://127.0.0.1:9000".into());
    assert!(StorageObject::from_s3_config(&config).is_err());
}

#[cfg(feature = "gcs")]
#[test]
fn gcs_rejects_service_account_token_redirects() {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_STORAGE_GCS_SOURCE_ID", "storage-test".into());
    config.insert_value("IRMIND_STORAGE_GCS_BUCKET", "test-bucket".into());
    config.insert_secret(
        "GCP_SERVICE_ACCOUNT_JSON",
        SecretString::from(
            r#"{"type":"service_account","client_email":"test@example.invalid","private_key":"fake","token_uri":"https://example.invalid/token"}"#.to_owned(),
        ),
    );
    assert!(StorageObject::from_gcs_config(&config).is_err());
}
