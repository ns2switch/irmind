use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterStorageError {
    #[error("storage: AWS IAM GetRole failed")]
    AWSIAMGetRoleFailed,
    #[error("storage: AWS IAM GetUser failed")]
    AWSIAMGetUserFailed,
    #[error("storage: AWS IAM role missing")]
    AWSIAMRoleMissing,
    #[error("storage: AWS IAM user missing")]
    AWSIAMUserMissing,
    #[error("storage: AWS STS identity lookup failed")]
    AWSSTSIdentityLookupFailed,
    #[error("storage: CloudTrail LookupEvents failed")]
    CloudTrailLookupEventsFailed,
    #[error("storage: CrowdStrike host has no valid device ID")]
    CrowdStrikeHostHasNoValidDeviceID,
    #[error("storage: CrowdStrike request failed")]
    CrowdStrikeRequestFailed,
    #[error("storage: CrowdStrike response failed")]
    CrowdStrikeResponseFailed,
    #[error("storage: CrowdStrike response has no resources array")]
    CrowdStrikeResponseHasNoResourcesArray,
    #[error("storage: CrowdStrike token response is invalid")]
    CrowdStrikeTokenResponseIsInvalid,
    #[error("storage: DuckDB graph operation failed")]
    DuckDBGraphOperationFailed,
    #[error("storage: MISP HTTP client unavailable")]
    MISPHTTPClientUnavailable,
    #[error("storage: MISP request failed")]
    MISPRequestFailed,
    #[error("storage: MISP response failed")]
    MISPResponseFailed,
    #[error("storage: SentinelOne agent has no valid ID")]
    SentinelOneAgentHasNoValidID,
    #[error("storage: SentinelOne request failed")]
    SentinelOneRequestFailed,
    #[error("storage: SentinelOne response failed")]
    SentinelOneResponseFailed,
    #[error("storage: SentinelOne response has no data array")]
    SentinelOneResponseHasNoDataArray,
    #[error("storage: Splunk HTTP client unavailable")]
    SplunkHTTPClientUnavailable,
    #[error("storage: Splunk request failed")]
    SplunkRequestFailed,
    #[error("storage: Splunk response failed")]
    SplunkResponseFailed,
    #[error("storage: VirusTotal HTTP client unavailable")]
    VirusTotalHTTPClientUnavailable,
    #[error("storage: VirusTotal request failed")]
    VirusTotalRequestFailed,
    #[error("storage: VirusTotal response failed")]
    VirusTotalResponseFailed,
    #[error("storage: cannot create CrowdStrike HTTP client")]
    CannotCreateCrowdStrikeHTTPClient,
    #[error("storage: cannot create SentinelOne HTTP client")]
    CannotCreateSentinelOneHTTPClient,
    #[error("storage: cannot encode CrowdStrike evidence")]
    CannotEncodeCrowdStrikeEvidence,
    #[error("storage: cannot encode SentinelOne evidence")]
    CannotEncodeSentinelOneEvidence,
    #[error("storage: cannot list selected evidence")]
    CannotListSelectedEvidence,
    #[error("storage: cannot read selected evidence")]
    CannotReadSelectedEvidence,
    #[error("storage: cannot unlock encrypted keystore")]
    CannotUnlockEncryptedKeystore,
    #[error("storage: encrypted keystore is open in another process")]
    EncryptedKeystoreIsOpenInAnotherProcess,
    #[error("storage: encrypted keystore not found")]
    EncryptedKeystoreNotFound,
    #[error("storage: encrypted keystore operation failed")]
    EncryptedKeystoreOperationFailed,
    #[error("storage: encrypted keystore parameters are unsafe")]
    EncryptedKeystoreParametersAreUnsafe,
    #[error("storage: evidence save failed")]
    EvidenceSaveFailed,
    #[error("storage: fake EDR counter poisoned")]
    FakeEDRCounterPoisoned,
    #[error("storage: invalid CrowdStrike JSON")]
    InvalidCrowdStrikeJSON,
    #[error("storage: invalid SentinelOne JSON")]
    InvalidSentinelOneJSON,
    #[error("storage: invalid fixed VirusTotal endpoint")]
    InvalidFixedVirusTotalEndpoint,
    #[error("storage: invalid selected evidence path")]
    InvalidSelectedEvidencePath,
    #[error("storage: local storage operation failed")]
    LocalStorageOperationFailed,
    #[error("storage: module secret is empty")]
    ModuleSecretIsEmpty,
    #[error("storage: seal preview UI unavailable")]
    SealPreviewUIUnavailable,
    #[error("storage: system clock is before the Unix epoch")]
    SystemClockIsBeforeTheUnixEpoch,
    #[error("storage: system keyring unavailable")]
    SystemKeyringUnavailable,
    #[error("storage: unknown encrypted keystore version")]
    UnknownEncryptedKeystoreVersion,
}
