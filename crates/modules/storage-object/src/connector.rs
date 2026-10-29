use object_store::{
    ClientOptions,
    client::{HttpClient, HttpConnector},
};
use std::time::Duration;

/// Reuses the application's rustls/native-roots client and disables redirects, including
/// redirects that could forward a signed cloud request to another host.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SafeConnector;

impl HttpConnector for SafeConnector {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        let client = irmind_http::client_builder(Duration::from_mins(5), false)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| object_store::Error::Generic {
                store: "IRMind object transport",
                source: Box::new(std::io::Error::other("cannot create TLS client")),
            })?;
        Ok(HttpClient::new(client))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn object_transport_rejects_redirects_and_bounds_http() -> Result<(), String> {
        irmind_testkit::run_http_safety_contract()
    }
}
