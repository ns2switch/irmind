use crate::DomainError;

/// Stable names are part of the signed audit format. Never rename a variant's wire value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuditEventKind {
    Allowed,
    ApprovalDenied,
    ApprovalGranted,
    BinaryResultOmitted,
    BudgetExceeded,
    Cancelled,
    CaseCreated,
    CaseScopeChanged,
    CaseSealed,
    Denied,
    EvidenceIngested,
    FindingConfirmed,
    FindingDismissed,
    FindingProposed,
    GraphIndexed,
    GuardActivated,
    InjectionDetected,
    ModelError,
    ModelReply,
    ModelRequest,
    ModelSelected,
    ModelUsage,
    ModulesActivated,
    NeedsApproval,
    PolicyActivated,
    Prompt,
    Proposal,
    SourceManifestV1,
    ParquetArtifactV1,
    TaintDeclassified,
    ToolDispatch,
    ToolError,
    ToolResult,
}

impl AuditEventKind {
    pub const ALL: [Self; 33] = [
        Self::Allowed,
        Self::ApprovalDenied,
        Self::ApprovalGranted,
        Self::BinaryResultOmitted,
        Self::BudgetExceeded,
        Self::Cancelled,
        Self::CaseCreated,
        Self::CaseScopeChanged,
        Self::CaseSealed,
        Self::Denied,
        Self::EvidenceIngested,
        Self::FindingConfirmed,
        Self::FindingDismissed,
        Self::FindingProposed,
        Self::GraphIndexed,
        Self::GuardActivated,
        Self::InjectionDetected,
        Self::ModelError,
        Self::ModelReply,
        Self::ModelRequest,
        Self::ModelSelected,
        Self::ModelUsage,
        Self::ModulesActivated,
        Self::NeedsApproval,
        Self::PolicyActivated,
        Self::Prompt,
        Self::Proposal,
        Self::SourceManifestV1,
        Self::ParquetArtifactV1,
        Self::TaintDeclassified,
        Self::ToolDispatch,
        Self::ToolError,
        Self::ToolResult,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::ApprovalDenied => "ApprovalDenied",
            Self::ApprovalGranted => "ApprovalGranted",
            Self::BinaryResultOmitted => "BinaryResultOmitted",
            Self::BudgetExceeded => "BudgetExceeded",
            Self::Cancelled => "Cancelled",
            Self::CaseCreated => "CaseCreated",
            Self::CaseScopeChanged => "CaseScopeChanged",
            Self::CaseSealed => "CaseSealed",
            Self::Denied => "Denied",
            Self::EvidenceIngested => "EvidenceIngested",
            Self::FindingConfirmed => "FindingConfirmed",
            Self::FindingDismissed => "FindingDismissed",
            Self::FindingProposed => "FindingProposed",
            Self::GraphIndexed => "GraphIndexed",
            Self::GuardActivated => "GuardActivated",
            Self::InjectionDetected => "InjectionDetected",
            Self::ModelError => "ModelError",
            Self::ModelReply => "ModelReply",
            Self::ModelRequest => "ModelRequest",
            Self::ModelSelected => "ModelSelected",
            Self::ModelUsage => "ModelUsage",
            Self::ModulesActivated => "ModulesActivated",
            Self::NeedsApproval => "NeedsApproval",
            Self::PolicyActivated => "PolicyActivated",
            Self::Prompt => "Prompt",
            Self::Proposal => "Proposal",
            Self::SourceManifestV1 => "SourceManifestV1",
            Self::ParquetArtifactV1 => "ParquetArtifactV1",
            Self::TaintDeclassified => "TaintDeclassified",
            Self::ToolDispatch => "ToolDispatch",
            Self::ToolError => "ToolError",
            Self::ToolResult => "ToolResult",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or(DomainError::UnknownAuditEvent)
    }
}

impl std::fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::AuditEventKind;

    #[test]
    fn wire_names_are_stable_and_unknown_names_fail() {
        const EXPECTED: [&str; 33] = [
            "Allowed",
            "ApprovalDenied",
            "ApprovalGranted",
            "BinaryResultOmitted",
            "BudgetExceeded",
            "Cancelled",
            "CaseCreated",
            "CaseScopeChanged",
            "CaseSealed",
            "Denied",
            "EvidenceIngested",
            "FindingConfirmed",
            "FindingDismissed",
            "FindingProposed",
            "GraphIndexed",
            "GuardActivated",
            "InjectionDetected",
            "ModelError",
            "ModelReply",
            "ModelRequest",
            "ModelSelected",
            "ModelUsage",
            "ModulesActivated",
            "NeedsApproval",
            "PolicyActivated",
            "Prompt",
            "Proposal",
            "SourceManifestV1",
            "ParquetArtifactV1",
            "TaintDeclassified",
            "ToolDispatch",
            "ToolError",
            "ToolResult",
        ];
        for (kind, expected) in AuditEventKind::ALL.into_iter().zip(EXPECTED) {
            assert_eq!(kind.as_str(), expected);
            assert_eq!(AuditEventKind::parse(expected), Ok(kind));
        }
        assert!(AuditEventKind::parse("UnknownEvent").is_err());
    }
}
