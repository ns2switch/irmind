#![forbid(unsafe_code)]

use irmind_http::{CaError, client_builder_with_ca, load_ca_file, load_optional_ca};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CERT: &[u8] = include_bytes!("fixtures/server.der");
const KEY: &[u8] = include_bytes!("fixtures/server-key.der");

#[tokio::test]
async fn custom_ca_keeps_full_tls_verification() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("test-ca.pem");
    std::fs::write(&path, CA)?;
    let ca = load_ca_file(&path)?;
    assert!(
        load_optional_ca(
            Some(path.to_str().ok_or("invalid test path")?),
            Some(ca.fingerprint())
        )?
        .is_some()
    );
    assert_eq!(
        load_optional_ca(
            Some(path.to_str().ok_or("invalid test path")?),
            Some(&"0".repeat(64))
        )
        .err(),
        Some(CaError::FingerprintMismatch)
    );

    let (address, task) = test_server().await?;

    let plain = client_builder_with_ca(Duration::from_secs(3), true, None)
        .resolve("localhost", address)
        .build()?;
    assert!(
        plain
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .is_err()
    );
    let trusted = client_builder_with_ca(Duration::from_secs(3), true, Some(&ca))
        .resolve("localhost", address)
        .build()?;
    assert_eq!(
        trusted
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    let wrong_name = client_builder_with_ca(Duration::from_secs(3), true, Some(&ca))
        .resolve("wrong.example", address)
        .build()?;
    assert!(
        wrong_name
            .get(format!("https://wrong.example:{}/", address.port()))
            .send()
            .await
            .is_err()
    );
    task.await?;
    Ok(())
}

async fn test_server()
-> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let server = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(CERT.to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let task = tokio::spawn(async move {
        for _ in 0..3 {
            let Ok(Ok((socket, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
            else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut request = [0_u8; 1024];
                    if stream.read(&mut request).await.is_ok() {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await;
                    }
                }
            });
        }
    });

    Ok((address, task))
}
