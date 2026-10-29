use crate::{AppError, AuthorizedCall, CancellationToken, async_trait};
use futures_util::stream::BoxStream;

/// Metadata returned by a versioned object store. The URI never contains
/// credentials or query parameters and is validated before it is signed.
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObjectEntry {
    pub uri: String,
    pub key: String,
    pub size: u64,
    pub modified_unix_seconds: Option<u64>,
    pub version: Option<String>,
    pub provider_checksum: Option<String>,
}

pub type ObjectStream = BoxStream<'static, Result<Vec<u8>, AppError>>;

pub enum ObjectSourceOutput {
    Listing {
        objects: Vec<ObjectEntry>,
        total_bytes: u64,
        truncated: bool,
    },
    Object {
        metadata: ObjectEntry,
        chunks: ObjectStream,
    },
}

/// Every network operation requires the policy's unforgeable call token.
#[async_trait]
pub trait ObjectSource: Send + Sync {
    fn source_id(&self) -> &str;

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError>;
}
