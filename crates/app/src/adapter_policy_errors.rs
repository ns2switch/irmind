use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterPolicyError {
    #[error("policy denied: AWS credential account differs from case scope")]
    AWSCredentialAccountDiffersFromCaseScope,
    #[error("policy denied: AWS credentials do not use the dedicated role")]
    AWSCredentialsDoNotUseTheDedicatedRole,
    #[error("policy denied: CloudTrail requires UTC second precision")]
    CloudTrailRequiresUTCSecondPrecision,
    #[error("policy denied: CloudTrail response exceeds 5 MB")]
    CloudTrailResponseExceeds5MB,
    #[error("policy denied: CrowdStrike URL must be an HTTPS origin")]
    CrowdStrikeURLMustBeAnHTTPSOrigin,
    #[error("policy denied: CrowdStrike detection window must be at most 24 hours")]
    CrowdStrikeDetectionWindowMustBeAtMost24Hours,
    #[error("policy denied: CrowdStrike host is missing or ambiguous")]
    CrowdStrikeHostIsMissingOrAmbiguous,
    #[error("policy denied: CrowdStrike process tree unavailable")]
    CrowdStrikeProcessTreeUnavailable,
    #[error("policy denied: CrowdStrike response exceeds 5 MB")]
    CrowdStrikeResponseExceeds5MB,
    #[error("policy denied: CrowdStrike returned an alert outside the host or window")]
    CrowdStrikeReturnedAnAlertOutsideTheHostOrWindow,
    #[error("policy denied: JSON input exceeds 50 MB")]
    JSONInputExceeds50MB,
    #[error("policy denied: MISP URL must be an HTTPS base path")]
    MISPURLMustBeAnHTTPSBasePath,
    #[error("policy denied: MISP response exceeds 5 MB")]
    MISPResponseExceeds5MB,
    #[error("policy denied: SentinelOne URL must be an HTTPS origin")]
    SentinelOneURLMustBeAnHTTPSOrigin,
    #[error("policy denied: SentinelOne detection window must be at most 24 hours")]
    SentinelOneDetectionWindowMustBeAtMost24Hours,
    #[error("policy denied: SentinelOne host is missing or ambiguous")]
    SentinelOneHostIsMissingOrAmbiguous,
    #[error("policy denied: SentinelOne process ID must be threat_id:event_id")]
    SentinelOneProcessIDMustBeThreatIdEventId,
    #[error("policy denied: SentinelOne process tree exceeds limit")]
    SentinelOneProcessTreeExceedsLimit,
    #[error("policy denied: SentinelOne response exceeds 5 MB")]
    SentinelOneResponseExceeds5MB,
    #[error("policy denied: SentinelOne returned a threat outside the host or window")]
    SentinelOneReturnedAThreatOutsideTheHostOrWindow,
    #[error("policy denied: SentinelOne threat is outside the selected host")]
    SentinelOneThreatIsOutsideTheSelectedHost,
    #[error("policy denied: Splunk URL must be an HTTPS origin")]
    SplunkURLMustBeAnHTTPSOrigin,
    #[error("policy denied: Splunk query window must be at most 24 hours")]
    SplunkQueryWindowMustBeAtMost24Hours,
    #[error("policy denied: Splunk response exceeds 5 MB")]
    SplunkResponseExceeds5MB,
    #[error("policy denied: VirusTotal response exceeds 5 MB")]
    VirusTotalResponseExceeds5MB,
    #[error("policy denied: case state is not sealed")]
    CaseStateIsNotSealed,
    #[error("policy denied: destination signing key already exists")]
    DestinationSigningKeyAlreadyExists,
    #[error("policy denied: destination signing key already exists or is unavailable")]
    DestinationSigningKeyAlreadyExistsOrIsUnavailable,
    #[error("policy denied: empty AWS credential")]
    EmptyAWSCredential,
    #[error("policy denied: empty CrowdStrike credential")]
    EmptyCrowdStrikeCredential,
    #[error("policy denied: empty MISP API key")]
    EmptyMISPAPIKey,
    #[error("policy denied: empty SentinelOne API token")]
    EmptySentinelOneAPIToken,
    #[error("policy denied: empty Splunk token")]
    EmptySplunkToken,
    #[error("policy denied: empty VirusTotal key")]
    EmptyVirusTotalKey,
    #[error("policy denied: empty module secret")]
    EmptyModuleSecret,
    #[error("policy denied: fake EDR source, host or tool mismatch")]
    FakeEDRSourceHostOrToolMismatch,
    #[error("policy denied: invalid AWS identity request")]
    InvalidAWSIdentityRequest,
    #[error("policy denied: invalid AWS role name")]
    InvalidAWSRoleName,
    #[error("policy denied: invalid AWS source ID or region")]
    InvalidAWSSourceIDOrRegion,
    #[error("policy denied: invalid CloudTrail event name")]
    InvalidCloudTrailEventName,
    #[error("policy denied: invalid CloudTrail time")]
    InvalidCloudTrailTime,
    #[error("policy denied: invalid CrowdStrike URL")]
    InvalidCrowdStrikeURL,
    #[error("policy denied: invalid CrowdStrike endpoint")]
    InvalidCrowdStrikeEndpoint,
    #[error("policy denied: invalid CrowdStrike host")]
    InvalidCrowdStrikeHost,
    #[error("policy denied: invalid CrowdStrike source ID")]
    InvalidCrowdStrikeSourceID,
    #[error("policy denied: invalid CrowdStrike tool")]
    InvalidCrowdStrikeTool,
    #[error("policy denied: invalid MISP IOC")]
    InvalidMISPIOC,
    #[error("policy denied: invalid MISP URL")]
    InvalidMISPURL,
    #[error("policy denied: invalid MISP endpoint")]
    InvalidMISPEndpoint,
    #[error("policy denied: invalid MISP source ID")]
    InvalidMISPSourceID,
    #[error("policy denied: invalid SentinelOne URL")]
    InvalidSentinelOneURL,
    #[error("policy denied: invalid SentinelOne endpoint")]
    InvalidSentinelOneEndpoint,
    #[error("policy denied: invalid SentinelOne host")]
    InvalidSentinelOneHost,
    #[error("policy denied: invalid SentinelOne process ID")]
    InvalidSentinelOneProcessID,
    #[error("policy denied: invalid SentinelOne site ID")]
    InvalidSentinelOneSiteID,
    #[error("policy denied: invalid SentinelOne source ID")]
    InvalidSentinelOneSourceID,
    #[error("policy denied: invalid SentinelOne tool")]
    InvalidSentinelOneTool,
    #[error("policy denied: invalid Splunk URL")]
    InvalidSplunkURL,
    #[error("policy denied: invalid Splunk end time")]
    InvalidSplunkEndTime,
    #[error("policy denied: invalid Splunk endpoint")]
    InvalidSplunkEndpoint,
    #[error("policy denied: invalid Splunk search term")]
    InvalidSplunkSearchTerm,
    #[error("policy denied: invalid Splunk source, index or account field")]
    InvalidSplunkSourceIndexOrAccountField,
    #[error("policy denied: invalid Splunk start time")]
    InvalidSplunkStartTime,
    #[error("policy denied: invalid VirusTotal path")]
    InvalidVirusTotalPath,
    #[error("policy denied: invalid bounded CloudTrail request")]
    InvalidBoundedCloudTrailRequest,
    #[error("policy denied: invalid case creation transaction")]
    InvalidCaseCreationTransaction,
    #[error("policy denied: invalid case scope transaction")]
    InvalidCaseScopeTransaction,
    #[error("policy denied: invalid case seal transaction")]
    InvalidCaseSealTransaction,
    #[error("policy denied: invalid cloud tool")]
    InvalidCloudTool,
    #[error("policy denied: invalid end time")]
    InvalidEndTime,
    #[error("policy denied: invalid graph query arguments")]
    InvalidGraphQueryArguments,
    #[error("policy denied: invalid module secret length")]
    InvalidModuleSecretLength,
    #[error("policy denied: invalid module secret name")]
    InvalidModuleSecretName,
    #[error("policy denied: invalid raw record pointer")]
    InvalidRawRecordPointer,
    #[error("policy denied: invalid start time")]
    InvalidStartTime,
    #[error("policy denied: invalid text search arguments")]
    InvalidTextSearchArguments,
    #[error("policy denied: missing AWS account")]
    MissingAWSAccount,
    #[error("policy denied: missing CloudTrail event name")]
    MissingCloudTrailEventName,
    #[error("policy denied: missing CloudTrail time")]
    MissingCloudTrailTime,
    #[error("policy denied: missing IAM identity kind")]
    MissingIAMIdentityKind,
    #[error("policy denied: missing IAM identity name")]
    MissingIAMIdentityName,
    #[error("policy denied: missing IOC")]
    MissingIOC,
    #[error("policy denied: missing end time")]
    MissingEndTime,
    #[error("policy denied: missing host")]
    MissingHost,
    #[error("policy denied: missing process ID")]
    MissingProcessID,
    #[error("policy denied: missing start time")]
    MissingStartTime,
    #[error("policy denied: no LLM selected")]
    NoLLMSelected,
    #[error("policy denied: non-EDR tool in contract")]
    NonEDRToolInContract,
    #[error("policy denied: non-public IP cannot be sent externally")]
    NonPublicIPCannotBeSentExternally,
    #[error("policy denied: record pointer is not indexed in this case")]
    RecordPointerIsNotIndexedInThisCase,
    #[error("policy denied: seal the case before export")]
    SealTheCaseBeforeExport,
    #[error("policy denied: signing key already exists")]
    SigningKeyAlreadyExists,
    #[error("policy denied: too many JSON records")]
    TooManyJSONRecords,
    #[error("policy denied: graph record exceeds 2048 distinct search terms")]
    TooManyGraphSearchTerms,
    #[error("policy denied: tool argument must be string or number")]
    ToolArgumentMustBeStringOrNumber,
    #[error("policy denied: tool arguments must be an object")]
    ToolArgumentsMustBeAnObject,
    #[error("policy denied: tool input must be an object")]
    ToolInputMustBeAnObject,
    #[error("policy denied: unknown provider tool")]
    UnknownProviderTool,
    #[error("policy denied: unsupported IAM identity kind")]
    UnsupportedIAMIdentityKind,
    #[error("policy denied: unsupported or private IOC")]
    UnsupportedOrPrivateIOC,
    #[error("policy denied: wrong AWS identity source or tool")]
    WrongAWSIdentitySourceOrTool,
    #[error("policy denied: wrong CloudTrail source or tool")]
    WrongCloudTrailSourceOrTool,
    #[error("policy denied: wrong CrowdStrike source or tool")]
    WrongCrowdStrikeSourceOrTool,
    #[error("policy denied: wrong MISP source or tool")]
    WrongMISPSourceOrTool,
    #[error("policy denied: wrong SentinelOne source or tool")]
    WrongSentinelOneSourceOrTool,
    #[error("policy denied: wrong Splunk source or tool")]
    WrongSplunkSourceOrTool,
    #[error("policy denied: wrong tool for VirusTotal")]
    WrongToolForVirusTotal,
}
