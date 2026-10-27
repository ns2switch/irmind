use crate::AdapterGuardError;
use crate::AdapterModelError;
use crate::AdapterPolicyError;
use crate::AdapterSignatureError;
use crate::AdapterStorageError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FixedAppError {
    #[error("model: LLM module is not registered")]
    ModelLLMModuleIsNotRegistered,
    #[error("model: provider stream ended without completion")]
    ModelProviderStreamEndedWithoutCompletion,
    #[error("policy denied: EDR source unavailable")]
    PolicyEDRSourceUnavailable,
    #[error("policy denied: SIEM source unavailable")]
    PolicySIEMSourceUnavailable,
    #[error("policy denied: agent cannot run in attended mode")]
    PolicyAgentCannotRunInAttendedMode,
    #[error("policy denied: alert exceeds 20 KB")]
    PolicyAlertExceeds20KB,
    #[error("policy denied: case model token quota reached")]
    PolicyCaseModelTokenQuotaReached,
    #[error("policy denied: cloud audit source unavailable")]
    PolicyCloudAuditSourceUnavailable,
    #[error("policy denied: duplicate EDR source")]
    PolicyDuplicateEDRSource,
    #[error("policy denied: duplicate LLM module")]
    PolicyDuplicateLLMModule,
    #[error("policy denied: duplicate SIEM source")]
    PolicyDuplicateSIEMSource,
    #[error("policy denied: duplicate cloud audit source")]
    PolicyDuplicateCloudAuditSource,
    #[error("policy denied: duplicate event parser")]
    PolicyDuplicateEventParser,
    #[error("policy denied: duplicate module ID")]
    PolicyDuplicateModuleID,
    #[error("policy denied: edited request id mismatch")]
    PolicyEditedRequestIdMismatch,
    #[error("policy denied: event parser is not registered")]
    PolicyEventParserIsNotRegistered,
    #[error("policy denied: evidence exceeds 50 MB")]
    PolicyEvidenceExceeds50MB,
    #[error("policy denied: external intel unavailable")]
    PolicyExternalIntelUnavailable,
    #[error("policy denied: global operational audit sequence exhausted")]
    PolicyGlobalOperationalAuditSequenceExhausted,
    #[error("policy denied: internal intelligence source unavailable")]
    PolicyInternalIntelligenceSourceUnavailable,
    #[error("policy denied: invalid case scope")]
    PolicyInvalidCaseScope,
    #[error("policy denied: invalid dismissal reason")]
    PolicyInvalidDismissalReason,
    #[error("policy denied: invalid finding type")]
    PolicyInvalidFindingType,
    #[error("policy denied: invalid finding value")]
    PolicyInvalidFindingValue,
    #[error("policy denied: invalid keystore migration")]
    PolicyInvalidKeystoreMigration,
    #[error("policy denied: invalid public configuration")]
    PolicyInvalidPublicConfiguration,
    #[error(
        "configuration does not match the signed operational record; restore the last approved config.toml"
    )]
    PolicyConfigurationAuditMismatch,
    #[error("policy denied: configuration change requires explicit analyst confirmation")]
    PolicyConfigurationConfirmationRequired,
    #[error("policy denied: invalid local tool")]
    PolicyInvalidLocalTool,
    #[error("policy denied: invalid module fingerprint")]
    PolicyInvalidModuleFingerprint,
    #[error("policy denied: invalid module manifest")]
    PolicyInvalidModuleManifest,
    #[error("policy denied: invalid policy fingerprint")]
    PolicyInvalidPolicyFingerprint,
    #[error("policy denied: invalid policy limits")]
    PolicyInvalidPolicyLimits,
    #[error("policy denied: invalid remote tool")]
    PolicyInvalidRemoteTool,
    #[error("policy denied: invalid secret backend migration")]
    PolicyInvalidSecretBackendMigration,
    #[error("policy denied: invalid signing backend migration")]
    PolicyInvalidSigningBackendMigration,
    #[error("policy denied: invalid structured scope")]
    PolicyInvalidStructuredScope,
    #[error("policy denied: missing EDR source")]
    PolicyMissingEDRSource,
    #[error("policy denied: missing SIEM source")]
    PolicyMissingSIEMSource,
    #[error("policy denied: missing cloud audit source")]
    PolicyMissingCloudAuditSource,
    #[error("policy denied: missing finding evidence")]
    PolicyMissingFindingEvidence,
    #[error("policy denied: missing finding kind")]
    PolicyMissingFindingKind,
    #[error("policy denied: missing finding value")]
    PolicyMissingFindingValue,
    #[error("policy denied: missing from_kind")]
    PolicyMissingFromKind,
    #[error("policy denied: missing from_value")]
    PolicyMissingFromValue,
    #[error("policy denied: missing hash")]
    PolicyMissingHash,
    #[error("policy denied: missing index")]
    PolicyMissingIndex,
    #[error("policy denied: missing internal intelligence source")]
    PolicyMissingInternalIntelligenceSource,
    #[error("policy denied: missing kind")]
    PolicyMissingKind,
    #[error("policy denied: missing query")]
    PolicyMissingQuery,
    #[error("policy denied: missing to_kind")]
    PolicyMissingToKind,
    #[error("policy denied: missing to_value")]
    PolicyMissingToValue,
    #[error("policy denied: missing value")]
    PolicyMissingValue,
    #[error("policy denied: model cost overflow")]
    PolicyModelCostOverflow,
    #[error("policy denied: model exceeded tool round limit")]
    PolicyModelExceededToolRoundLimit,
    #[error("policy denied: model token count overflow")]
    PolicyModelTokenCountOverflow,
    #[error("policy denied: open finding not found")]
    PolicyOpenFindingNotFound,
    #[error("policy denied: operational audit sequence exhausted")]
    PolicyOperationalAuditSequenceExhausted,
    #[error("policy denied: pending approval not found")]
    PolicyPendingApprovalNotFound,
    #[error("policy denied: seal preview is stale")]
    PolicySealPreviewIsStale,
    #[error("policy denied: seal the case before export")]
    PolicySealTheCaseBeforeExport,
    #[error("policy denied: stored approval challenge is invalid")]
    PolicyStoredApprovalChallengeIsInvalid,
    #[error("policy denied: title or scope is invalid")]
    PolicyTitleOrScopeIsInvalid,
    #[error("policy denied: tool result exceeds 5 MB")]
    PolicyToolResultExceeds5MB,
    #[error("policy denied: unconfirmed finding not found")]
    PolicyUnconfirmedFindingNotFound,
    #[error("signature: analyst approval signature is invalid")]
    SignatureAnalystApprovalSignatureIsInvalid,
    #[error("signature: analyst declassification approval required")]
    SignatureAnalystDeclassificationApprovalRequired,
    #[error("signature: analyst denial signature is invalid")]
    SignatureAnalystDenialSignatureIsInvalid,
    #[error("storage: audit sequence overflow")]
    StorageAuditSequenceOverflow,
    #[error("model: provider emitted data after completion")]
    ModelProviderEmittedDataAfterCompletion,
    #[error("policy denied: EDR manifest and capabilities differ")]
    PolicyEDRManifestAndCapabilitiesDiffer,
    #[error("policy denied: LLM registered under a different module ID")]
    PolicyLLMRegisteredUnderADifferentModuleID,
    #[error("policy denied: denial reason must be 1..500 bytes")]
    PolicyDenialReasonMustBe1500Bytes,
    #[error("policy denied: duplicate external intelligence module")]
    PolicyDuplicateExternalIntelligenceModule,
    #[error("policy denied: duplicate internal intelligence source")]
    PolicyDuplicateInternalIntelligenceSource,
    #[error("policy denied: edited arguments do not produce a pending approval")]
    PolicyEditedArgumentsDoNotProduceAPendingApproval,
    #[error("policy denied: finding evidence is absent from case")]
    PolicyFindingEvidenceIsAbsentFromCase,
    #[error("policy denied: module registered undeclared ports")]
    PolicyModuleRegisteredUndeclaredPorts,
    #[error("policy denied: module source or port is already registered")]
    PolicyModuleSourceOrPortIsAlreadyRegistered,
    #[error("policy denied: resolve pending approvals before sealing")]
    PolicyResolvePendingApprovalsBeforeSealing,
    #[error("policy denied: source must be a relative, slash-separated path")]
    PolicySourceMustBeARelativeSlashSeparatedPath,
    #[error("signature: destination has a different signing key")]
    SignatureDestinationHasADifferentSigningKey,
    #[error("signature: migrated signing fingerprint differs")]
    SignatureMigratedSigningFingerprintDiffers,
    #[error("storage: SECRET from hostile provider URL")]
    StorageSECRETFromHostileProviderURL,
    #[error("storage: migrated credential verification failed")]
    StorageMigratedCredentialVerificationFailed,
    #[error(transparent)]
    AdapterStorage(AdapterStorageError),
    #[error(transparent)]
    AdapterSignature(AdapterSignatureError),
    #[error(transparent)]
    AdapterGuard(AdapterGuardError),
    #[error(transparent)]
    AdapterModel(AdapterModelError),
    #[error(transparent)]
    AdapterPolicy(AdapterPolicyError),
}
