//! Fresh credentialless TLS clients; all redirects are checked before sending.
use irmind_app::{AppError, CancellationToken};
use std::time::{Duration, Instant};
pub(super) async fn fetch(
    initial: &str,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    let client = irmind_http::client_builder(Duration::from_secs(30), true)
        .build()
        .map_err(|_| failed())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut target = initial.to_owned();
    for hop in 0..=3 {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(failed)?;
        let request = client
            .get(&target)
            .timeout(remaining)
            .header("User-Agent", "irmind-skills-catalog")
            .header(
                "Accept",
                if target.starts_with("https://api.github.com/") {
                    "application/vnd.github+json"
                } else {
                    "application/octet-stream"
                },
            )
            .header("X-GitHub-Api-Version", "2026-03-10")
            .build()
            .map_err(|_| failed())?;
        let url = request.url();
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some_and(|port| port != 443)
            || !destination(url.host_str().unwrap_or_default(), url.path())
        {
            return Err(failed());
        }
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            response = client.execute(request) => response.map_err(|_| failed())?,
        };
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if hop == 3 {
                return Err(failed());
            }
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .filter(|s| s.len() <= 4096)
                .ok_or_else(failed)?;
            target = response
                .url()
                .join(location)
                .map_err(|_| failed())?
                .to_string();
            continue;
        }
        if response.status().as_u16() != 200 {
            return Err(AppError::Policy(format!(
                "Catalog download returned HTTP {}; retry later or use an offline package.",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|size| size > limit as u64)
        {
            return Err(failed());
        }
        return irmind_http::read_limited(response, limit, cancel)
            .await
            .map_err(|error| match error {
                irmind_http::BodyError::Cancelled => AppError::Cancelled,
                _ => failed(),
            });
    }
    Err(failed())
}
fn destination(host: &str, path: &str) -> bool {
    if path.contains('%') || path.contains('\\') {
        return false;
    }
    match host {
        "api.github.com" => path.starts_with("/repos/ns2switch/irmind-skills/releases/"),
        "github.com" => path.starts_with("/ns2switch/irmind-skills/releases/download/"),
        "release-assets.githubusercontent.com" | "objects.githubusercontent.com" => true,
        _ => false,
    }
}
fn failed() -> AppError {
    AppError::Policy("Catalog download failed its TLS, destination, timeout or size checks; retry or use an offline package.".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_destinations_are_exact_public_release_hosts_and_repository_paths() {
        assert!(destination(
            "api.github.com",
            "/repos/ns2switch/irmind-skills/releases/latest"
        ));
        assert!(destination(
            "github.com",
            "/ns2switch/irmind-skills/releases/download/v1.0.0/index.json"
        ));
        assert!(destination(
            "release-assets.githubusercontent.com",
            "/asset"
        ));
        for (host, path) in [
            ("github.com.evil.invalid", "/"),
            ("api.github.com", "/repos/other/repo/releases/latest"),
            ("github.com", "/login"),
            ("localhost", "/"),
            ("169.254.169.254", "/latest/meta-data"),
            ("objects.githubusercontent.com.evil.invalid", "/"),
        ] {
            assert!(!destination(host, path));
        }
    }
}
