//! Chronicle's fixed OAuth scope and public error mapping.
use crate::{AppError, CancellationToken, invalid_config};
use irmind_http::google_auth::{GoogleApi, GoogleAuthError, GoogleServiceAccount};
use secrecy::SecretString;

pub(super) struct Credentials(GoogleServiceAccount);

impl Credentials {
    pub(super) fn new(raw: &SecretString) -> Result<Self, AppError> {
        GoogleServiceAccount::new(raw, GoogleApi::Chronicle)
            .map(Self)
            .map_err(map_auth_error)
    }

    pub(super) async fn token(
        &self,
        client: &reqwest::Client,
        endpoint: &reqwest::Url,
        cancel: &CancellationToken,
    ) -> Result<SecretString, AppError> {
        self.0
            .token(client, endpoint, cancel)
            .await
            .map_err(map_auth_error)
    }

    #[cfg(test)]
    pub(super) fn assertion(&self, now: u64) -> Result<SecretString, AppError> {
        self.0.assertion(now).map_err(map_auth_error)
    }
}

pub(super) fn token_endpoint() -> Result<reqwest::Url, AppError> {
    irmind_http::google_auth::google_token_endpoint().map_err(map_auth_error)
}

fn map_auth_error(error: GoogleAuthError) -> AppError {
    match error {
        GoogleAuthError::InvalidConfiguration => invalid_config(),
        GoogleAuthError::Cancelled => AppError::Cancelled,
        GoogleAuthError::ExchangeFailed => AppError::RemoteTool,
    }
}
