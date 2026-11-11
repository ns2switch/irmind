//! Explicit service-account OAuth. No ambient credential discovery or configurable token destination.
use crate::{AppError, CancellationToken, invalid_config};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/chronicle";

pub(super) struct Credentials {
    email: String,
    key: SecretString,
    token: Mutex<Option<Token>>,
}
struct Token {
    secret: SecretString,
    expires: Instant,
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
impl Credentials {
    pub(super) fn new(raw: &SecretString) -> Result<Self, AppError> {
        if raw.expose_secret().len() > 64 * 1024 {
            return Err(invalid_config());
        }
        let account: ServiceAccount =
            serde_json::from_str(raw.expose_secret()).map_err(|_| invalid_config())?;
        if account.r#type != "service_account"
            || account.token_uri != TOKEN_URL
            || account.client_email.len() > 254
            || !account.client_email.ends_with(".iam.gserviceaccount.com")
            || !account
                .client_email
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
        {
            return Err(invalid_config());
        }
        let key = account.private_key;
        let _ = parse_key(&key)?;
        Ok(Self {
            email: account.client_email,
            key,
            token: Mutex::new(None),
        })
    }
    pub(super) async fn token(
        &self,
        client: &reqwest::Client,
        endpoint: &reqwest::Url,
        cancel: &CancellationToken,
    ) -> Result<SecretString, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        {
            let cache = self.token.lock().map_err(|_| AppError::RemoteTool)?;
            if let Some(token) = cache.as_ref().filter(|t| t.expires > Instant::now()) {
                return Ok(token.secret.clone());
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AppError::RemoteTool)?
            .as_secs();
        let assertion = self.assertion(now)?;
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            response = client.post(endpoint.clone()).form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.expose_secret()),
            ]).send() => response.map_err(|_| AppError::RemoteTool)?,
        };
        if !response.status().is_success() {
            return Err(AppError::RemoteTool);
        }
        let raw = Zeroizing::new(
            irmind_http::read_limited(response, 64 * 1024, cancel)
                .await
                .map_err(|error| match error {
                    irmind_http::BodyError::Cancelled => AppError::Cancelled,
                    _ => AppError::RemoteTool,
                })?,
        );
        let token: TokenResponse =
            serde_json::from_slice(&raw).map_err(|_| AppError::RemoteTool)?;
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
            return Err(AppError::RemoteTool);
        }
        let secret = token.access_token;
        let expires = Instant::now()
            .checked_add(Duration::from_secs(u64::from(token.expires_in - 30)))
            .ok_or(AppError::RemoteTool)?;
        *self.token.lock().map_err(|_| AppError::RemoteTool)? = Some(Token {
            secret: secret.clone(),
            expires,
        });
        Ok(secret)
    }
    pub(super) fn assertion(&self, now: u64) -> Result<SecretString, AppError> {
        let expiry = now.checked_add(300).ok_or(AppError::RemoteTool)?;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::to_vec(&serde_json::json!({"iss":self.email,"scope":SCOPE,"aud":TOKEN_URL,"iat":now,"exp":expiry})).map_err(|_| AppError::RemoteTool)?;
        let input = Zeroizing::new(format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims)));
        let key = parse_key(&self.key)?;
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .map_err(|_| AppError::RemoteTool)?;
        Ok(SecretString::from(format!(
            "{}.{signature}",
            input.as_str(),
            signature = URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}
fn parse_key(secret: &SecretString) -> Result<RsaKeyPair, AppError> {
    let pem = secret.expose_secret().trim();
    let body = pem
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|v| v.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or_else(invalid_config)?;
    let encoded = Zeroizing::new(
        body.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let der = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| invalid_config())?,
    );
    RsaKeyPair::from_pkcs8(&der).map_err(|_| invalid_config())
}
pub(super) fn token_endpoint() -> Result<reqwest::Url, AppError> {
    reqwest::Url::parse(TOKEN_URL).map_err(|_| invalid_config())
}
