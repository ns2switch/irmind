use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::path::Path;

const MAX_CA_BYTES: u64 = 1_048_576;

#[derive(Clone)]
pub struct CaBundle {
    certificates: Vec<reqwest::Certificate>,
    fingerprint: String,
}

impl std::fmt::Debug for CaBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaBundle")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl CaBundle {
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn certificates(&self) -> &[reqwest::Certificate] {
        &self.certificates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaError {
    Unavailable,
    TooLarge,
    InvalidPem,
    FingerprintMismatch,
    IncompleteConfiguration,
}

impl std::fmt::Display for CaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "the CA file cannot be read",
            Self::TooLarge => "the CA file exceeds the 1 MiB limit",
            Self::InvalidPem => "the CA file does not contain a valid PEM certificate chain",
            Self::FingerprintMismatch => {
                "the CA file has changed since its fingerprint was approved"
            }
            Self::IncompleteConfiguration => {
                "the CA path and approved fingerprint must be set together"
            }
        })
    }
}

impl std::error::Error for CaError {}

pub fn load_ca_file(path: &Path) -> Result<CaBundle, CaError> {
    let file = std::fs::File::open(path).map_err(|_| CaError::Unavailable)?;
    if !file.metadata().map_err(|_| CaError::Unavailable)?.is_file() {
        return Err(CaError::Unavailable);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CaError::Unavailable)?;
    if bytes.len() as u64 > MAX_CA_BYTES {
        return Err(CaError::TooLarge);
    }
    let certificates =
        reqwest::Certificate::from_pem_bundle(&bytes).map_err(|_| CaError::InvalidPem)?;
    if certificates.is_empty() {
        return Err(CaError::InvalidPem);
    }
    let mut fingerprint = String::with_capacity(64);
    let digits = b"0123456789abcdef";
    for byte in Sha256::digest(&bytes) {
        fingerprint.push(char::from(digits[usize::from(byte >> 4)]));
        fingerprint.push(char::from(digits[usize::from(byte & 15)]));
    }
    Ok(CaBundle {
        certificates,
        fingerprint,
    })
}

pub fn load_optional_ca(
    path: Option<&str>,
    expected_fingerprint: Option<&str>,
) -> Result<Option<CaBundle>, CaError> {
    match (path, expected_fingerprint) {
        (None, None) => Ok(None),
        (Some(path), Some(expected)) => {
            let bundle = load_ca_file(Path::new(path))?;
            if bundle.fingerprint() != expected {
                return Err(CaError::FingerprintMismatch);
            }
            Ok(Some(bundle))
        }
        _ => Err(CaError::IncompleteConfiguration),
    }
}
