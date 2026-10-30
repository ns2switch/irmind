#![forbid(unsafe_code)]

use std::time::Duration;
use tokio_util::sync::CancellationToken;

mod trust;
pub use trust::{CaBundle, CaError, load_ca_file, load_optional_ca};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyError {
    Cancelled,
    Transport,
    TooLarge,
}

/// All reqwest product clients share the same transport guardrails.
pub fn client_builder(timeout: Duration, no_proxy: bool) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if no_proxy {
        builder.no_proxy()
    } else {
        builder
    }
}

pub fn client_builder_with_ca(
    timeout: Duration,
    no_proxy: bool,
    ca: Option<&CaBundle>,
) -> reqwest::ClientBuilder {
    ca.map_or_else(
        || client_builder(timeout, no_proxy),
        |bundle| {
            bundle.certificates().iter().cloned().fold(
                client_builder(timeout, no_proxy),
                reqwest::ClientBuilder::add_root_certificate,
            )
        },
    )
}

pub async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, BodyError> {
    let mut raw = Vec::new();
    loop {
        let chunk = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(BodyError::Cancelled),
            result = response.chunk() => result.map_err(|_| BodyError::Transport)?,
        };
        let Some(chunk) = chunk else { break };
        if raw.len().saturating_add(chunk.len()) > limit {
            return Err(BodyError::TooLarge);
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(raw)
}
