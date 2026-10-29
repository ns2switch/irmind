use super::*;
#[cfg(any(feature = "s3", feature = "gcs"))]
use secrecy::SecretString;

#[allow(clippy::unwrap_used)]
async fn synthetic_object_contract(
    scheme: &'static str,
    manifest: &'static irmind_app::modules::ModuleManifest,
) {
    use object_store::{ObjectStoreExt as _, PutPayload, memory::InMemory, path::Path};
    let store = Arc::new(InMemory::new());
    let bytes = br#"{"Records":[{"eventName":"AssumeRole"}]}"#;
    store
        .put(
            &Path::from("AWSLogs/123/a.json"),
            PutPayload::from(bytes.to_vec()),
        )
        .await
        .unwrap();
    let module = StorageObject {
        source_id: "storage-test".into(),
        container: "synthetic-audit".into(),
        scheme,
        store,
        manifest,
    };
    irmind_testkit::run_object_source_contract(
        &module,
        scheme,
        "synthetic-audit",
        "AWSLogs/123/",
        "AWSLogs/123/a.json",
        bytes,
    )
    .await
    .unwrap();
}

#[cfg(feature = "s3")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn s3_passes_shared_object_contract() {
    synthetic_object_contract("s3", &crate::S3_MANIFEST).await;
}

#[cfg(feature = "gcs")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn gcs_passes_shared_object_contract() {
    synthetic_object_contract("gs", &crate::GCS_MANIFEST).await;
}

#[cfg(feature = "azure")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn azure_passes_shared_object_contract() {
    synthetic_object_contract("az", &crate::AZURE_MANIFEST).await;
}

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
