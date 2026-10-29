use super::*;
#[cfg(any(feature = "s3", feature = "gcs"))]
use secrecy::SecretString;

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
const RECORDED_S3_LIST: &str = r"<ListBucketResult><Contents><Key>AWSLogs/123/a.json</Key><LastModified>2026-10-23T12:00:00Z</LastModified><ETag>synthetic-etag</ETag><Size>7</Size></Contents></ListBucketResult>";

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
const RECORDED_AZURE_LIST: &str = r"<EnumerationResults><Blobs><Blob><Name>AWSLogs/123/a.json</Name><Properties><Last-Modified>Fri, 23 Oct 2026 12:00:00 GMT</Last-Modified><Etag>synthetic-etag</Etag><Content-Length>7</Content-Length><Content-Type>application/json</Content-Type></Properties></Blob></Blobs></EnumerationResults>";

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
fn recorded_object(scheme: &str) -> irmind_testkit::MockResponse {
    let response = irmind_testkit::MockResponse::json(r#"{"x":1}"#)
        .with_header("ETag", "synthetic-etag")
        .with_header("Last-Modified", "Fri, 23 Oct 2026 12:00:00 GMT");
    match scheme {
        "s3" => response.with_header("x-amz-version-id", "s3-v1"),
        "gs" => response.with_header("x-goog-generation", "12345"),
        "az" => response.with_header("x-ms-version-id", "azure-v1"),
        _ => response,
    }
}

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
fn assert_recorded_requests(requests: &[irmind_testkit::RecordedRequest]) {
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "GET");
    assert!(requests[0].target.contains("AWSLogs%2F123%2F"));
    assert!(requests[1].target.contains("AWSLogs"));
    // GCS percent-encodes path punctuation, including the dot in this fixture.
    assert!(requests[1].target.contains("json"));
    assert_eq!(
        requests[1].headers.get("if-match").map(String::as_str),
        Some("synthetic-etag")
    );
}

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
#[allow(clippy::unwrap_used)]
async fn recorded_provider_round_trip(
    scheme: &'static str,
    manifest: &'static irmind_app::modules::ModuleManifest,
    store: Arc<dyn object_store::ObjectStore>,
) {
    let module = StorageObject {
        source_id: "storage-test".into(),
        container: "synthetic-audit".into(),
        scheme,
        store,
        manifest,
    };
    let metadata = irmind_testkit::run_object_source_contract(
        &module,
        scheme,
        "synthetic-audit",
        "AWSLogs/123/",
        "AWSLogs/123/a.json",
        br#"{"x":1}"#,
    )
    .await
    .unwrap();
    let expected = match scheme {
        "s3" => "s3-v1",
        "gs" => "12345",
        "az" => "azure-v1",
        _ => unreachable!(),
    };
    assert_eq!(metadata.version.as_deref(), Some(expected));
}

#[cfg(feature = "s3")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn s3_reads_recorded_object_from_local_server() {
    use irmind_testkit::{MockResponse, MockServer};
    let server = MockServer::start(vec![
        MockResponse::json(RECORDED_S3_LIST),
        recorded_object("s3"),
    ])
    .unwrap();
    // Plain HTTP exists only in this synthetic protocol fixture. Production
    // configuration rejects it before a connector is constructed.
    let store = object_store::aws::AmazonS3Builder::new()
        .with_bucket_name("synthetic-audit")
        .with_region("us-east-1")
        .with_endpoint(server.origin())
        .with_allow_http(true)
        .with_skip_signature(true)
        .with_http_connector(SafeConnector)
        .build()
        .unwrap();
    recorded_provider_round_trip("s3", &crate::S3_MANIFEST, Arc::new(store)).await;
    assert_recorded_requests(&server.finish().unwrap());
}

#[cfg(feature = "gcs")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn gcs_reads_recorded_object_from_local_server() {
    use irmind_testkit::{MockResponse, MockServer};
    let server = MockServer::start(vec![
        MockResponse::json(RECORDED_S3_LIST),
        recorded_object("gs"),
    ])
    .unwrap();
    let store = object_store::gcp::GoogleCloudStorageBuilder::new()
        .with_bucket_name("synthetic-audit")
        .with_base_url(server.origin().trim_end_matches('/'))
        .with_skip_signature(true)
        .with_http_connector(SafeConnector)
        .build()
        .unwrap();
    recorded_provider_round_trip("gs", &crate::GCS_MANIFEST, Arc::new(store)).await;
    assert_recorded_requests(&server.finish().unwrap());
}

#[cfg(feature = "azure")]
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn azure_reads_recorded_object_from_local_server() {
    use irmind_testkit::{MockResponse, MockServer};
    let server = MockServer::start(vec![
        MockResponse::json(RECORDED_AZURE_LIST),
        recorded_object("az"),
    ])
    .unwrap();
    let store = object_store::azure::MicrosoftAzureBuilder::new()
        .with_account("syntheticaccount")
        .with_container_name("synthetic-audit")
        .with_endpoint(server.origin().into())
        .with_allow_http(true)
        .with_skip_signature(true)
        .with_http_connector(SafeConnector)
        .build()
        .unwrap();
    recorded_provider_round_trip("az", &crate::AZURE_MANIFEST, Arc::new(store)).await;
    assert_recorded_requests(&server.finish().unwrap());
}

#[cfg(feature = "azure")]
#[test]
fn azure_requires_an_explicit_service_principal_secret() {
    let mut config = ModuleConfig::new();
    config.insert_value("IRMIND_STORAGE_AZURE_SOURCE_ID", "storage-test".into());
    config.insert_value("IRMIND_STORAGE_AZURE_CONTAINER", "synthetic-audit".into());
    config.insert_value("IRMIND_STORAGE_AZURE_ACCOUNT", "syntheticaccount".into());
    config.insert_value("IRMIND_STORAGE_AZURE_CLIENT_ID", "syntheticclient".into());
    config.insert_value("IRMIND_STORAGE_AZURE_TENANT_ID", "synthetictenant".into());
    assert!(StorageObject::from_azure_config(&config).is_err());
    config.insert_secret(
        "AZURE_CLIENT_SECRET",
        secrecy::SecretString::from("synthetic-secret".to_owned()),
    );
    assert!(StorageObject::from_azure_config(&config).is_ok());
}

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
