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
    CaseBudgetChanged,
    SourceQueryBudgetV1,
    SourceQueryPlanV1,
    SourceQueryApprovalV1,
    SourceQueryReservationV1,
    SourceQueryExecutionV1,
    SourceQueryResultV1,
    SourceQuerySettlementV1,
    SourceQueryRecoveryV1,
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
    FinalAnswer,
    ConversationSummary,
    ModelRequest,
    ModelSelected,
    ModelUsage,
    ModulesActivated,
    NeedsApproval,
    PolicyActivated,
    Prompt,
    Proposal,
    SourceManifestV1,
    SourceManifestV2,
    ParquetArtifactV1,
    ParquetArtifactV2,
    ParquetArtifactsMigrated,
    ParserSelectionRequired,
    TaintDeclassified,
    ToolDispatch,
    ToolError,
    ToolResult,
    SourceRecordSetV1,
    MappingProfileV1,
    MappingRunV1,
    ParquetArtifactV3,
    ParquetLayoutV1,
    SkillSnapshotV2,
    SkillLoadV1,
    /// Recognized only to reject a retired case without interpreting its body.
    RetiredSkillSnapshot,
    SubagentSourcePageV1,
    SubagentSourceSetV1,
    SubagentTypeSnapshotV1,
    SubagentPlanV1,
    SubagentPlanApprovalV1,
    SubagentReservationV1,
    SubagentCheckpointV1,
    SubagentResultV1,
    SigmaCaseRunAdmissionV1,
    SigmaRunV2,
    ReportPublishedV1,
    IngestFileOutcomeV1,
}

impl AuditEventKind {
    pub const ALL: [Self; 68] = [
        Self::Allowed,
        Self::ApprovalDenied,
        Self::ApprovalGranted,
        Self::BinaryResultOmitted,
        Self::BudgetExceeded,
        Self::Cancelled,
        Self::CaseCreated,
        Self::CaseBudgetChanged,
        Self::SourceQueryBudgetV1,
        Self::SourceQueryPlanV1,
        Self::SourceQueryApprovalV1,
        Self::SourceQueryReservationV1,
        Self::SourceQueryExecutionV1,
        Self::SourceQueryResultV1,
        Self::SourceQuerySettlementV1,
        Self::SourceQueryRecoveryV1,
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
        Self::FinalAnswer,
        Self::ConversationSummary,
        Self::ModelRequest,
        Self::ModelSelected,
        Self::ModelUsage,
        Self::ModulesActivated,
        Self::NeedsApproval,
        Self::PolicyActivated,
        Self::Prompt,
        Self::Proposal,
        Self::SourceManifestV1,
        Self::SourceManifestV2,
        Self::ParquetArtifactV1,
        Self::ParquetArtifactV2,
        Self::ParquetArtifactsMigrated,
        Self::ParserSelectionRequired,
        Self::TaintDeclassified,
        Self::ToolDispatch,
        Self::ToolError,
        Self::ToolResult,
        Self::SourceRecordSetV1,
        Self::MappingProfileV1,
        Self::MappingRunV1,
        Self::ParquetArtifactV3,
        Self::ParquetLayoutV1,
        Self::SkillSnapshotV2,
        Self::SkillLoadV1,
        Self::RetiredSkillSnapshot,
        Self::SubagentSourcePageV1,
        Self::SubagentSourceSetV1,
        Self::SubagentTypeSnapshotV1,
        Self::SubagentPlanV1,
        Self::SubagentPlanApprovalV1,
        Self::SubagentReservationV1,
        Self::SubagentCheckpointV1,
        Self::SubagentResultV1,
        Self::SigmaCaseRunAdmissionV1,
        Self::SigmaRunV2,
        Self::ReportPublishedV1,
        Self::IngestFileOutcomeV1,
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
            Self::CaseBudgetChanged => "CaseBudgetChanged",
            Self::SourceQueryBudgetV1 => "SourceQueryBudgetV1",
            Self::SourceQueryPlanV1 => "SourceQueryPlanV1",
            Self::SourceQueryApprovalV1 => "SourceQueryApprovalV1",
            Self::SourceQueryReservationV1 => "SourceQueryReservationV1",
            Self::SourceQueryExecutionV1 => "SourceQueryExecutionV1",
            Self::SourceQueryResultV1 => "SourceQueryResultV1",
            Self::SourceQuerySettlementV1 => "SourceQuerySettlementV1",
            Self::SourceQueryRecoveryV1 => "SourceQueryRecoveryV1",
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
            Self::FinalAnswer => "FinalAnswer",
            Self::ConversationSummary => "ConversationSummary",
            Self::ModelRequest => "ModelRequest",
            Self::ModelSelected => "ModelSelected",
            Self::ModelUsage => "ModelUsage",
            Self::ModulesActivated => "ModulesActivated",
            Self::NeedsApproval => "NeedsApproval",
            Self::PolicyActivated => "PolicyActivated",
            Self::Prompt => "Prompt",
            Self::Proposal => "Proposal",
            Self::SourceManifestV1 => "SourceManifestV1",
            Self::SourceManifestV2 => "SourceManifestV2",
            Self::ParquetArtifactV1 => "ParquetArtifactV1",
            Self::ParquetArtifactV2 => "ParquetArtifactV2",
            Self::ParquetArtifactsMigrated => "ParquetArtifactsMigrated",
            Self::ParserSelectionRequired => "ParserSelectionRequired",
            Self::TaintDeclassified => "TaintDeclassified",
            Self::ToolDispatch => "ToolDispatch",
            Self::ToolError => "ToolError",
            Self::ToolResult => "ToolResult",
            Self::SourceRecordSetV1 => "SourceRecordSetV1",
            Self::MappingProfileV1 => "MappingProfileV1",
            Self::MappingRunV1 => "MappingRunV1",
            Self::ParquetArtifactV3 => "ParquetArtifactV3",
            Self::ParquetLayoutV1 => "ParquetLayoutV1",
            Self::SkillSnapshotV2 => "skill-snapshot-v2",
            Self::RetiredSkillSnapshot => "skill-snapshot-v1",
            Self::SkillLoadV1 => "skill-load-v1",
            Self::SubagentSourcePageV1 => "subagent-source-page-v1",
            Self::SubagentSourceSetV1 => "subagent-source-set-v1",
            Self::SubagentTypeSnapshotV1 => "subagent-type-v1",
            Self::SubagentPlanV1 => "subagent-plan-v1",
            Self::SubagentPlanApprovalV1 => "subagent-plan-approval-v1",
            Self::SubagentReservationV1 => "subagent-reservation-v1",
            Self::SubagentCheckpointV1 => "subagent-checkpoint-v1",
            Self::SubagentResultV1 => "subagent-result-v1",
            Self::SigmaCaseRunAdmissionV1 => "sigma-case-run-admission-v1",
            Self::SigmaRunV2 => "sigma-run-v2",
            Self::ReportPublishedV1 => "report-published-v1",
            Self::IngestFileOutcomeV1 => "ingest-file-outcome-v1",
        }
    }

    /// Recognize obsolete layouts for a fail-closed, actionable format message.
    pub const fn is_retired_case_format(self) -> bool {
        matches!(
            self,
            Self::SourceManifestV1
                | Self::ParquetArtifactV1
                | Self::ParquetArtifactV2
                | Self::ParquetArtifactsMigrated
                | Self::GraphIndexed
        )
    }

    pub const fn is_mapped_custody(self) -> bool {
        matches!(
            self,
            Self::SourceRecordSetV1
                | Self::MappingProfileV1
                | Self::MappingRunV1
                | Self::ParquetArtifactV3
                | Self::ParquetLayoutV1
        )
    }

    pub const fn is_source_query_lifecycle(self) -> bool {
        matches!(
            self,
            Self::SourceQueryPlanV1
                | Self::SourceQueryApprovalV1
                | Self::SourceQueryReservationV1
                | Self::SourceQueryExecutionV1
                | Self::SourceQueryResultV1
                | Self::SourceQuerySettlementV1
                | Self::SourceQueryRecoveryV1
        )
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
        const EXPECTED: [&str; 68] = [
            "Allowed",
            "ApprovalDenied",
            "ApprovalGranted",
            "BinaryResultOmitted",
            "BudgetExceeded",
            "Cancelled",
            "CaseCreated",
            "CaseBudgetChanged",
            "SourceQueryBudgetV1",
            "SourceQueryPlanV1",
            "SourceQueryApprovalV1",
            "SourceQueryReservationV1",
            "SourceQueryExecutionV1",
            "SourceQueryResultV1",
            "SourceQuerySettlementV1",
            "SourceQueryRecoveryV1",
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
            "FinalAnswer",
            "ConversationSummary",
            "ModelRequest",
            "ModelSelected",
            "ModelUsage",
            "ModulesActivated",
            "NeedsApproval",
            "PolicyActivated",
            "Prompt",
            "Proposal",
            "SourceManifestV1",
            "SourceManifestV2",
            "ParquetArtifactV1",
            "ParquetArtifactV2",
            "ParquetArtifactsMigrated",
            "ParserSelectionRequired",
            "TaintDeclassified",
            "ToolDispatch",
            "ToolError",
            "ToolResult",
            "SourceRecordSetV1",
            "MappingProfileV1",
            "MappingRunV1",
            "ParquetArtifactV3",
            "ParquetLayoutV1",
            "skill-snapshot-v2",
            "skill-load-v1",
            "skill-snapshot-v1",
            "subagent-source-page-v1",
            "subagent-source-set-v1",
            "subagent-type-v1",
            "subagent-plan-v1",
            "subagent-plan-approval-v1",
            "subagent-reservation-v1",
            "subagent-checkpoint-v1",
            "subagent-result-v1",
            "sigma-case-run-admission-v1",
            "sigma-run-v2",
            "report-published-v1",
            "ingest-file-outcome-v1",
        ];
        assert_eq!(AuditEventKind::ALL.len(), EXPECTED.len());
        for (kind, expected) in AuditEventKind::ALL.into_iter().zip(EXPECTED) {
            assert_eq!(kind.as_str(), expected);
            assert_eq!(AuditEventKind::parse(expected), Ok(kind));
        }
        assert!(AuditEventKind::parse("UnknownEvent").is_err());
    }
}
