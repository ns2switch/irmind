use crate::{AppError, AuthorizedCall, CancellationToken, Engine, ObjectSourceOutput, Tool};

impl Engine<'_> {
    pub(crate) async fn dispatch_object_source(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        let source = call.arg("source").ok_or(AppError::RemoteTool)?;
        let port = self
            .object_sources
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or(AppError::RemoteTool)?;
        port.execute(call, cancel).await
    }
    pub(crate) fn object_source_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| {
            self.object_sources
                .iter()
                .any(|port| port.source_id() == source)
        })
    }

    pub(crate) fn siem_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| self.siems.iter().any(|port| port.source_id() == source))
    }

    pub(crate) async fn dispatch_siem(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call.arg("source").ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyMissingSIEMSource,
        ))?;
        self.siems
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicySIEMSourceUnavailable,
            ))?
            .execute(call, cancel)
            .await
    }

    pub(crate) fn cloud_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| {
            self.cloud_audits
                .iter()
                .any(|port| port.source_id() == source)
        })
    }

    pub(crate) async fn dispatch_cloud(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call.arg("source").ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyMissingCloudAuditSource,
        ))?;
        self.cloud_audits
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyCloudAuditSourceUnavailable,
            ))?
            .execute(call, cancel)
            .await
    }

    pub(crate) fn internal_intel_available(&self, source: Option<&str>) -> bool {
        source.is_some_and(|source| {
            self.internal_intel
                .iter()
                .any(|port| port.source_id() == source)
        })
    }

    pub(crate) fn edr_available(&self, source: Option<&str>, tool: &Tool) -> bool {
        source.is_some_and(|source| {
            self.edrs
                .iter()
                .any(|port| port.source_id() == source && port.supports(tool))
        })
    }

    pub(crate) async fn dispatch_edr(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call.arg("source").ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyMissingEDRSource,
        ))?;
        let port = self
            .edrs
            .iter()
            .find(|port| port.source_id() == source && port.supports(call.tool()))
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyEDRSourceUnavailable,
            ))?;
        port.execute(call, cancel).await
    }

    pub(crate) async fn dispatch_internal_intel(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let source = call.arg("source").ok_or({
            AppError::Fixed(crate::FixedAppError::PolicyMissingInternalIntelligenceSource)
        })?;
        self.internal_intel
            .iter()
            .find(|port| port.source_id() == source)
            .ok_or({
                AppError::Fixed(crate::FixedAppError::PolicyInternalIntelligenceSourceUnavailable)
            })?
            .execute(call, cancel)
            .await
    }
}
