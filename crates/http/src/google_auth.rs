//! Explicit service-account OAuth. No ambient credential discovery or configurable token destination.
use crate::{BodyError, read_limited, rs256::Rs256Key};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleApi {
    Chronicle,
    BigQuery,
}

impl GoogleApi {
    const fn oauth_scope(self) -> &'static str {
        match self {
            Self::Chronicle => "https://www.googleapis.com/auth/chronicle",
            Self::BigQuery => "https://www.googleapis.com/auth/bigquery",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleAuthError {
    InvalidConfiguration,
    Cancelled,
    ExchangeFailed,
}

pub struct GoogleServiceAccount {
    api: GoogleApi,
    email: String,
    key: SecretString,
    token: Mutex<Option<Token>>,
}
struct Token {
    access: GoogleAccessToken,
    expires: Instant,
}

/// A token may only authorize requests made for its original service.
#[derive(Clone)]
pub struct GoogleAccessToken {
    api: GoogleApi,
    secret: SecretString,
}

impl GoogleAccessToken {
    pub fn authorize(
        &self,
        api: GoogleApi,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, GoogleAuthError> {
        if self.api != api {
            return Err(GoogleAuthError::InvalidConfiguration);
        }
        Ok(request.bearer_auth(self.secret.expose_secret()))
    }
}

impl std::fmt::Debug for GoogleAccessToken {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("GoogleAccessToken")
            .field("api", &self.api)
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
struct ServiceAccount {
    r#type: String,
    client_email: String,
    #[serde(deserialize_with = "secret_field")]
    private_key: SecretString,
    token_uri: String,
}
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(deserialize_with = "secret_field")]
    access_token: SecretString,
    token_type: String,
    expires_in: u32,
}
fn secret_field<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::from)
}
impl GoogleServiceAccount {
    pub fn new(raw: &SecretString, api: GoogleApi) -> Result<Self, GoogleAuthError> {
        if raw.expose_secret().len() > 64 * 1024 {
            return Err(GoogleAuthError::InvalidConfiguration);
        }
        let account: ServiceAccount = serde_json::from_str(raw.expose_secret())
            .map_err(|_| GoogleAuthError::InvalidConfiguration)?;
        if account.r#type != "service_account"
            || account.token_uri != TOKEN_URL
            || account.client_email.len() > 254
            || !account.client_email.ends_with(".iam.gserviceaccount.com")
            || !account
                .client_email
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
        {
            return Err(GoogleAuthError::InvalidConfiguration);
        }
        let key = account.private_key;
        let _ = parse_key(&key)?;
        Ok(Self {
            api,
            email: account.client_email,
            key,
            token: Mutex::new(None),
        })
    }
    /// Exchange at the pinned Google endpoint. The endpoint argument also
    /// supports an HTTP loopback server for synthetic protocol tests.
    pub async fn token(
        &self,
        client: &reqwest::Client,
        endpoint: &reqwest::Url,
        cancel: &CancellationToken,
    ) -> Result<GoogleAccessToken, GoogleAuthError> {
        if cancel.is_cancelled() {
            return Err(GoogleAuthError::Cancelled);
        }
        if endpoint.as_str() != TOKEN_URL
            && !(cfg!(feature = "google-auth-test-support") && loopback_test_endpoint(endpoint))
        {
            return Err(GoogleAuthError::InvalidConfiguration);
        }
        {
            let cache = self
                .token
                .lock()
                .map_err(|_| GoogleAuthError::ExchangeFailed)?;
            if let Some(token) = cache.as_ref().filter(|t| t.expires > Instant::now()) {
                return Ok(token.access.clone());
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GoogleAuthError::ExchangeFailed)?
            .as_secs();
        let assertion = self.assertion(now)?;
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(GoogleAuthError::Cancelled),
            response = client.post(endpoint.clone()).form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.expose_secret()),
            ]).send() => response.map_err(|_| GoogleAuthError::ExchangeFailed)?,
        };
        if !response.status().is_success() {
            return Err(GoogleAuthError::ExchangeFailed);
        }
        let raw = Zeroizing::new(read_limited(response, 64 * 1024, cancel).await.map_err(
            |error| match error {
                BodyError::Cancelled => GoogleAuthError::Cancelled,
                _ => GoogleAuthError::ExchangeFailed,
            },
        )?);
        let token: TokenResponse =
            serde_json::from_slice(&raw).map_err(|_| GoogleAuthError::ExchangeFailed)?;
        if token.token_type != "Bearer"
            || !(60..=3600).contains(&token.expires_in)
            || token.access_token.expose_secret().is_empty()
            || token.access_token.expose_secret().len() > 8192
            || !token
                .access_token
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_graphic())
        {
            return Err(GoogleAuthError::ExchangeFailed);
        }
        let access = GoogleAccessToken {
            api: self.api,
            secret: token.access_token,
        };
        let expires = Instant::now()
            .checked_add(Duration::from_secs(u64::from(token.expires_in - 30)))
            .ok_or(GoogleAuthError::ExchangeFailed)?;
        *self
            .token
            .lock()
            .map_err(|_| GoogleAuthError::ExchangeFailed)? = Some(Token {
            access: access.clone(),
            expires,
        });
        Ok(access)
    }
    pub fn assertion(&self, now: u64) -> Result<SecretString, GoogleAuthError> {
        let expiry = now
            .checked_add(300)
            .ok_or(GoogleAuthError::ExchangeFailed)?;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::to_vec(&serde_json::json!({"iss":self.email,"scope":self.api.oauth_scope(),"aud":TOKEN_URL,"iat":now,"exp":expiry})).map_err(|_| GoogleAuthError::ExchangeFailed)?;
        let input = Zeroizing::new(format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims)));
        let key = parse_key(&self.key)?;
        let signature = key
            .sign(input.as_bytes())
            .map_err(|_| GoogleAuthError::ExchangeFailed)?;
        Ok(SecretString::from(format!(
            "{}.{signature}",
            input.as_str(),
            signature = URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}
fn parse_key(secret: &SecretString) -> Result<Rs256Key, GoogleAuthError> {
    let pem = secret.expose_secret().trim();
    let body = pem
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|v| v.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or(GoogleAuthError::InvalidConfiguration)?;
    let encoded = Zeroizing::new(
        body.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let der = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| GoogleAuthError::InvalidConfiguration)?,
    );
    Rs256Key::from_pkcs8(&der).map_err(|_| GoogleAuthError::InvalidConfiguration)
}
pub fn google_token_endpoint() -> Result<reqwest::Url, GoogleAuthError> {
    reqwest::Url::parse(TOKEN_URL).map_err(|_| GoogleAuthError::InvalidConfiguration)
}

fn loopback_test_endpoint(endpoint: &reqwest::Url) -> bool {
    endpoint.scheme() == "http"
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.fragment().is_none()
        && endpoint
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "[::1]"))
}
