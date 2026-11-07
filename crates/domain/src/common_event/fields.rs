use super::{CommonFieldType, CommonValue, EventSchemaError};

macro_rules! fields {
    ($(($variant:ident, $label:literal, $code:literal, $kind:ident)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub enum CommonField { $($variant),+ }
        impl CommonField {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn code(self) -> u16 { match self { $(Self::$variant => $code),+ } }
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
            pub fn all() -> impl Iterator<Item = Self> { Self::ALL.iter().copied() }
            pub fn from_code(code: u16) -> Result<Self, EventSchemaError> {
                match code { $($code => Ok(Self::$variant)),+, _ => Err(EventSchemaError::UnknownCode) }
            }
            pub fn parse(label: &str) -> Result<Self, EventSchemaError> {
                match label { $($label => Ok(Self::$variant)),+, _ => Err(EventSchemaError::UnknownCode) }
            }
            pub const fn value_type(self) -> CommonFieldType {
                match self { $(Self::$variant => CommonFieldType::$kind),+ }
            }
            pub(super) fn validates(self, value: &CommonValue) -> bool {
                let kind = match self { $(Self::$variant => CommonFieldType::$kind),+ };
                kind.accepts(value)
            }
        }
    };
}

fields!(
    (CloudAccountId, "cloud.account.id", 1, Text),
    (CloudProjectId, "cloud.project.id", 2, Text),
    (CloudProvider, "cloud.provider", 3, Text),
    (CloudRegion, "cloud.region", 4, Text),
    (CloudServiceName, "cloud.service.name", 5, Text),
    (DestinationDomain, "destination.domain", 6, Text),
    (DestinationIp, "destination.ip", 7, Ip),
    (DestinationPort, "destination.port", 8, Port),
    (DestinationUserDomain, "destination.user.domain", 9, Text),
    (DestinationUserId, "destination.user.id", 10, Text),
    (DestinationUserName, "destination.user.name", 11, Text),
    (DnsAnswers, "dns.answers", 12, DnsAnswers),
    (DnsQuestionClass, "dns.question.class", 13, Text),
    (DnsQuestionName, "dns.question.name", 14, Text),
    (DnsQuestionType, "dns.question.type", 15, Text),
    (DnsResponseCode, "dns.response_code", 16, Text),
    (FileAccessed, "file.accessed", 17, Time),
    (FileCreated, "file.created", 18, Time),
    (FileExtension, "file.extension", 19, Text),
    (FileHashMd5, "file.hash.md5", 20, Md5),
    (FileHashSha1, "file.hash.sha1", 21, Sha1),
    (FileHashSha256, "file.hash.sha256", 22, Sha256),
    (FileModified, "file.modified", 23, Time),
    (FileName, "file.name", 24, Text),
    (FilePath, "file.path", 25, LongText),
    (FileSize, "file.size", 26, Unsigned),
    (HostDomain, "host.domain", 27, Text),
    (HostHostname, "host.hostname", 28, Text),
    (HostId, "host.id", 29, Text),
    (HostName, "host.name", 30, Text),
    (HostOsType, "host.os.type", 31, Text),
    (HttpRequestBytes, "http.request.bytes", 32, Unsigned),
    (HttpRequestMethod, "http.request.method", 33, Text),
    (HttpResponseBytes, "http.response.bytes", 34, Unsigned),
    (
        HttpResponseStatusCode,
        "http.response.status_code",
        35,
        HttpStatus
    ),
    (HttpVersion, "http.version", 36, Text),
    (IrmindDetectionId, "irmind.detection.id", 37, Text),
    (
        IrmindDetectionSourceSeverity,
        "irmind.detection.source_severity",
        38,
        Text
    ),
    (NetworkBytes, "network.bytes", 39, Unsigned),
    (NetworkCommunityId, "network.community_id", 40, Text),
    (NetworkDirection, "network.direction", 41, Direction),
    (NetworkPackets, "network.packets", 42, Unsigned),
    (NetworkProtocol, "network.protocol", 43, Text),
    (NetworkTransport, "network.transport", 44, Text),
    (ProcessCommandLine, "process.command_line", 45, LongText),
    (ProcessEntityId, "process.entity_id", 46, Text),
    (ProcessExecutable, "process.executable", 47, LongText),
    (ProcessHashMd5, "process.hash.md5", 48, Md5),
    (ProcessHashSha1, "process.hash.sha1", 49, Sha1),
    (ProcessHashSha256, "process.hash.sha256", 50, Sha256),
    (ProcessName, "process.name", 51, Text),
    (
        ProcessParentCommandLine,
        "process.parent.command_line",
        52,
        LongText
    ),
    (ProcessParentEntityId, "process.parent.entity_id", 53, Text),
    (
        ProcessParentExecutable,
        "process.parent.executable",
        54,
        LongText
    ),
    (ProcessParentHashMd5, "process.parent.hash.md5", 55, Md5),
    (ProcessParentHashSha1, "process.parent.hash.sha1", 56, Sha1),
    (
        ProcessParentHashSha256,
        "process.parent.hash.sha256",
        57,
        Sha256
    ),
    (ProcessParentName, "process.parent.name", 58, Text),
    (ProcessParentPid, "process.parent.pid", 59, Pid),
    (ProcessPid, "process.pid", 60, Pid),
    (RegistryDataStrings, "registry.data.strings", 61, TextList),
    (RegistryDataType, "registry.data.type", 62, Text),
    (RegistryHive, "registry.hive", 63, Text),
    (RegistryKey, "registry.key", 64, LongText),
    (RegistryPath, "registry.path", 65, LongText),
    (RegistryValue, "registry.value", 66, Text),
    (RuleId, "rule.id", 67, Text),
    (RuleName, "rule.name", 68, Text),
    (SourceDomain, "source.domain", 69, Text),
    (SourceIp, "source.ip", 70, Ip),
    (SourcePort, "source.port", 71, Port),
    (SourceUserDomain, "source.user.domain", 72, Text),
    (SourceUserId, "source.user.id", 73, Text),
    (SourceUserName, "source.user.name", 74, Text),
    (UrlDomain, "url.domain", 75, Text),
    (UrlFull, "url.full", 76, LongText),
    (UrlOriginal, "url.original", 77, LongText),
    (UrlPath, "url.path", 78, LongText),
    (UrlPort, "url.port", 79, Port),
    (UrlQuery, "url.query", 80, LongText),
    (UrlScheme, "url.scheme", 81, Text),
    (UserDomain, "user.domain", 82, Text),
    (UserEffectiveDomain, "user.effective.domain", 83, Text),
    (UserEffectiveId, "user.effective.id", 84, Text),
    (UserEffectiveName, "user.effective.name", 85, Text),
    (UserId, "user.id", 86, Text),
    (UserName, "user.name", 87, Text),
    (UserTargetDomain, "user.target.domain", 88, Text),
    (UserTargetId, "user.target.id", 89, Text),
    (UserTargetName, "user.target.name", 90, Text),
    (UserAgentOriginal, "user_agent.original", 91, LongText),
    (IrmindResourceId, "irmind.resource.id", 92, Text),
    (IrmindIamRoleId, "irmind.iam_role.id", 93, Text),
    (IrmindKeyId, "irmind.key.id", 94, Text),
    (IrmindSessionId, "irmind.session.id", 95, Text),
    (IrmindFlowRef, "irmind.flow.ref", 96, Text),
    (IrmindSourceEventId, "irmind.source_event.id", 97, Text),
    (
        IrmindCollectorArtifact,
        "irmind.collector.artifact",
        98,
        Text
    ),
);
