use crate::{AppError, AuthorizedCall, CancellationToken, Tool, async_trait};
#[async_trait]
pub trait ThreatIntelPort: Send + Sync {
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait SiemPort: Send + Sync {
    fn source_id(&self) -> &str;
    fn dialect(&self) -> &'static str;
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait CloudAuditPort: Send + Sync {
    fn source_id(&self) -> &str;
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait EdrPort: Send + Sync {
    fn source_id(&self) -> &str;
    fn supports(&self, tool: &Tool) -> bool;
    fn process_tree_hint(&self) -> Option<&'static str> {
        None
    }
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}

#[async_trait]
pub trait InternalIntelPort: Send + Sync {
    fn source_id(&self) -> &str;
    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError>;
}
