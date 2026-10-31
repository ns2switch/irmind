use crate::{AuditEventKind, DomainError, EvidenceHash, canonical::put};

const SOURCE_TAG: &[u8] = b"irmind-source-manifest-v1\0";
const SOURCE_V2_TAG: &[u8] = b"irmind-source-manifest-v2\0";
const ARTIFACT_TAG: &[u8] = b"irmind-parquet-artifact-v1\0";
const MAX_PAYLOAD_BYTES: usize = 16_384;
pub(super) const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Metadata signed with the case chain. `source` is a relative slash-separated
/// path or a credential-free object URI; it is never an authority to read it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceManifestV1 {
    pub source: String,
    pub size: u64,
    pub modified_unix_seconds: Option<u64>,
    pub version: Option<String>,
    pub provider_checksum: Option<String>,
    pub sha256: EvidenceHash,
    pub copied: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserSelectionMode {
    Automatic,
    Analyst,
    Forced,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SourceManifestV2 {
    pub source: SourceManifestV1,
    pub parser_id: String,
    pub parser_version: String,
    pub confidence: u8,
    pub selection: ParserSelectionMode,
    pub timestamp_context: Option<String>,
    pub rejected_records: u64,
    pub rejected_sample: Vec<String>,
}

impl std::fmt::Debug for SourceManifestV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceManifestV2")
            .field("source_hash", &self.source.sha256)
            .field("parser_id", &self.parser_id)
            .field("parser_version", &self.parser_version)
            .field("confidence", &self.confidence)
            .field("selection", &self.selection)
            .field("rejected_records", &self.rejected_records)
            .field("rejected_sample", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SourceManifestV2 {
    pub fn encode(&self) -> Result<String, DomainError> {
        self.validate()?;
        let mut bytes = SOURCE_V2_TAG.to_vec();
        put(&mut bytes, self.source.encode()?.as_bytes());
        put(&mut bytes, self.parser_id.as_bytes());
        put(&mut bytes, self.parser_version.as_bytes());
        bytes.push(self.confidence);
        bytes.push(match self.selection {
            ParserSelectionMode::Automatic => 0,
            ParserSelectionMode::Analyst => 1,
            ParserSelectionMode::Forced => 2,
        });
        put_optional(&mut bytes, self.timestamp_context.as_deref());
        bytes.extend_from_slice(&self.rejected_records.to_be_bytes());
        bytes.push(
            u8::try_from(self.rejected_sample.len()).map_err(|_| DomainError::InvalidManifest)?,
        );
        for sample in &self.rejected_sample {
            put(&mut bytes, sample.as_bytes());
        }
        encode_payload(&bytes)
    }

    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = decode_payload(payload, SOURCE_V2_TAG)?;
        let mut reader = Reader::new(&bytes[SOURCE_V2_TAG.len()..]);
        let source = SourceManifestV1::decode(&reader.string_limit(8192)?)?;
        let parser_id = reader.string()?;
        let parser_version = reader.string()?;
        let confidence = reader.byte()?;
        let selection = match reader.byte()? {
            0 => ParserSelectionMode::Automatic,
            1 => ParserSelectionMode::Analyst,
            2 => ParserSelectionMode::Forced,
            _ => return Err(DomainError::InvalidManifest),
        };
        let timestamp_context = reader.optional_string()?;
        let rejected_records = reader.u64()?;
        let count = usize::from(reader.byte()?);
        if count > 3 {
            return Err(DomainError::InvalidManifest);
        }
        let mut rejected_sample = Vec::with_capacity(count);
        for _ in 0..count {
            rejected_sample.push(reader.string()?);
        }
        reader.end()?;
        let result = Self {
            source,
            parser_id,
            parser_version,
            confidence,
            selection,
            timestamp_context,
            rejected_records,
            rejected_sample,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.source.validate()?;
        if self.parser_id.is_empty()
            || self.parser_id.len() > 64
            || !self
                .parser_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || self.parser_version.is_empty()
            || self.parser_version.len() > 128
            || self.confidence > 100
            || self
                .timestamp_context
                .as_ref()
                .is_some_and(|value| value.len() > 128)
            || self.rejected_sample.len() > 3
            || self.rejected_sample.iter().any(|value| value.len() > 256)
        {
            return Err(DomainError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParquetArtifactV1 {
    pub path: String,
    pub size: u64,
    pub sha256: EvidenceHash,
    pub parser_version: String,
    pub schema_version: String,
    pub partition_date: String,
    pub partition_account: String,
    pub partition_region: String,
    pub source_hashes: Vec<EvidenceHash>,
}

impl SourceManifestV1 {
    pub fn decode_signed(kind: AuditEventKind, payload: &str) -> Result<Option<Self>, DomainError> {
        match kind {
            AuditEventKind::SourceManifestV1 => Self::decode(payload).map(Some),
            AuditEventKind::SourceManifestV2 => {
                SourceManifestV2::decode(payload).map(|manifest| Some(manifest.source))
            }
            _ => Ok(None),
        }
    }

    pub fn encode(&self) -> Result<String, DomainError> {
        self.validate()?;
        let mut bytes = SOURCE_TAG.to_vec();
        put(&mut bytes, self.source.as_bytes());
        bytes.extend_from_slice(&self.size.to_be_bytes());
        put_optional_u64(&mut bytes, self.modified_unix_seconds);
        put_optional(&mut bytes, self.version.as_deref());
        put_optional(&mut bytes, self.provider_checksum.as_deref());
        put(&mut bytes, self.sha256.as_str().as_bytes());
        bytes.push(u8::from(self.copied));
        encode_payload(&bytes)
    }

    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = decode_payload(payload, SOURCE_TAG)?;
        let mut reader = Reader::new(&bytes[SOURCE_TAG.len()..]);
        let value = Self {
            source: reader.string()?,
            size: reader.u64()?,
            modified_unix_seconds: reader.optional_u64()?,
            version: reader.optional_string()?,
            provider_checksum: reader.optional_string()?,
            sha256: EvidenceHash::parse(&reader.string()?)?,
            copied: reader.bool()?,
        };
        reader.end()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if !valid_source(&self.source)
            || self.version.as_ref().is_some_and(|v| v.len() > 256)
            || self
                .provider_checksum
                .as_ref()
                .is_some_and(|v| v.len() > 256)
        {
            return Err(DomainError::InvalidManifest);
        }
        Ok(())
    }
}

impl ParquetArtifactV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        self.validate()?;
        let mut bytes = ARTIFACT_TAG.to_vec();
        put(&mut bytes, self.path.as_bytes());
        bytes.extend_from_slice(&self.size.to_be_bytes());
        put(&mut bytes, self.sha256.as_str().as_bytes());
        for value in [
            &self.parser_version,
            &self.schema_version,
            &self.partition_date,
            &self.partition_account,
            &self.partition_region,
        ] {
            put(&mut bytes, value.as_bytes());
        }
        bytes.extend_from_slice(&(self.source_hashes.len() as u64).to_be_bytes());
        for hash in &self.source_hashes {
            put(&mut bytes, hash.as_str().as_bytes());
        }
        encode_payload(&bytes)
    }

    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = decode_payload(payload, ARTIFACT_TAG)?;
        let mut reader = Reader::new(&bytes[ARTIFACT_TAG.len()..]);
        let path = reader.string()?;
        let size = reader.u64()?;
        let sha256 = EvidenceHash::parse(&reader.string()?)?;
        let parser_version = reader.string()?;
        let schema_version = reader.string()?;
        let partition_date = reader.string()?;
        let partition_account = reader.string()?;
        let partition_region = reader.string()?;
        let count = usize::try_from(reader.u64()?).map_err(|_| DomainError::InvalidManifest)?;
        if count == 0 || count > 128 {
            return Err(DomainError::InvalidManifest);
        }
        let mut source_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            source_hashes.push(EvidenceHash::parse(&reader.string()?)?);
        }
        reader.end()?;
        let value = Self {
            path,
            size,
            sha256,
            parser_version,
            schema_version,
            partition_date,
            partition_account,
            partition_region,
            source_hashes,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        let hashes_sorted = self.source_hashes.windows(2).all(|pair| pair[0] < pair[1]);
        let partition_path = format!(
            "date={}/account={}/region={}/",
            self.partition_date, self.partition_account, self.partition_region
        );
        if !valid_relative_path(&self.path)
            || !self.path.starts_with(&partition_path)
            || !self.path.ends_with(".parquet")
            || self.parser_version.is_empty()
            || self.parser_version.len() > 128
            || self.schema_version.is_empty()
            || self.schema_version.len() > 128
            || !valid_partition(&self.partition_date)
            || !valid_partition(&self.partition_account)
            || !valid_partition(&self.partition_region)
            || self.source_hashes.is_empty()
            || self.source_hashes.len() > 128
            || !hashes_sorted
        {
            return Err(DomainError::InvalidManifest);
        }
        Ok(())
    }
}

fn valid_partition(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn valid_source(source: &str) -> bool {
    if source.len() > 1024 || source.contains(['?', '#', '\\', '\0']) {
        return false;
    }
    if let Some(rest) = source.strip_prefix("s3://") {
        return valid_object_path(rest);
    }
    if let Some(rest) = source.strip_prefix("gs://") {
        return valid_object_path(rest);
    }
    if let Some(rest) = source.strip_prefix("az://") {
        return valid_object_path(rest);
    }
    valid_relative_path(source)
}

fn valid_object_path(value: &str) -> bool {
    !value.contains('@') && valid_relative_path(value)
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains(['\\', ':', '\0'])
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
}

fn put_optional(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            put(out, value.as_bytes());
        }
        None => out.push(0),
    }
}

fn put_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
        None => out.push(0),
    }
}

fn encode_payload(bytes: &[u8]) -> Result<String, DomainError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(DomainError::InvalidManifest);
    }
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(HEX_DIGITS[usize::from(byte & 15)]));
    }
    Ok(output)
}

fn decode_payload(value: &str, tag: &[u8]) -> Result<Vec<u8>, DomainError> {
    if value.len() > MAX_PAYLOAD_BYTES * 2 || !value.len().is_multiple_of(2) {
        return Err(DomainError::InvalidManifest);
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    if !bytes.starts_with(tag) {
        return Err(DomainError::InvalidManifest);
    }
    Ok(bytes)
}

pub(super) fn hex_digit(value: u8) -> Result<u8, DomainError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DomainError::InvalidManifest),
    }
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    fn u64(&mut self) -> Result<u64, DomainError> {
        let bytes = self.rest.get(..8).ok_or(DomainError::InvalidManifest)?;
        self.rest = &self.rest[8..];
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| DomainError::InvalidManifest)?,
        ))
    }

    fn string(&mut self) -> Result<String, DomainError> {
        self.string_limit(2048)
    }

    fn string_limit(&mut self, limit: usize) -> Result<String, DomainError> {
        let length = usize::try_from(self.u64()?).map_err(|_| DomainError::InvalidManifest)?;
        if length > limit {
            return Err(DomainError::InvalidManifest);
        }
        let bytes = self
            .rest
            .get(..length)
            .ok_or(DomainError::InvalidManifest)?;
        self.rest = &self.rest[length..];
        String::from_utf8(bytes.to_vec()).map_err(|_| DomainError::InvalidManifest)
    }

    fn byte(&mut self) -> Result<u8, DomainError> {
        let value = *self.rest.first().ok_or(DomainError::InvalidManifest)?;
        self.rest = &self.rest[1..];
        Ok(value)
    }

    fn marker(&mut self) -> Result<u8, DomainError> {
        let marker = *self.rest.first().ok_or(DomainError::InvalidManifest)?;
        self.rest = &self.rest[1..];
        if marker > 1 {
            return Err(DomainError::InvalidManifest);
        }
        Ok(marker)
    }

    fn bool(&mut self) -> Result<bool, DomainError> {
        Ok(self.marker()? == 1)
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, DomainError> {
        if self.bool()? {
            self.u64().map(Some)
        } else {
            Ok(None)
        }
    }

    fn optional_string(&mut self) -> Result<Option<String>, DomainError> {
        if self.bool()? {
            self.string().map(Some)
        } else {
            Ok(None)
        }
    }

    fn end(&self) -> Result<(), DomainError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DomainError::InvalidManifest)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn versioned_parser_manifest_round_trips_without_changing_v1() {
        let source = SourceManifestV1 {
            source: "logs/auth.log".into(),
            size: 42,
            modified_unix_seconds: Some(1_794_000_000),
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"a".repeat(64)).unwrap(),
            copied: false,
        };
        let original_v1 = source.encode().unwrap();
        let versioned = SourceManifestV2 {
            source: source.clone(),
            parser_id: "parser-linux".into(),
            parser_version: "linux-v1".into(),
            confidence: 92,
            selection: ParserSelectionMode::Automatic,
            timestamp_context: Some("year=2026;offset=0".into()),
            rejected_records: 1,
            rejected_sample: vec!["bad synthetic line".into()],
        };
        assert_eq!(
            SourceManifestV2::decode(&versioned.encode().unwrap()),
            Ok(versioned.clone())
        );
        assert_eq!(source.encode().unwrap(), original_v1);
        assert!(SourceManifestV1::decode(&versioned.encode().unwrap()).is_err());
    }

    #[test]
    fn source_round_trip_and_rejects_unsafe_uri() {
        let source = SourceManifestV1 {
            source: "logs/cloudtrail.json".into(),
            size: 17,
            modified_unix_seconds: Some(1_700_000_000),
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"a".repeat(64)).unwrap(),
            copied: false,
        };
        assert_eq!(
            SourceManifestV1::decode(&source.encode().unwrap()),
            Ok(source.clone())
        );
        for path in [
            "../secret",
            "/absolute",
            "s3://bucket/key?token=secret",
            "gs://user@bucket/key",
        ] {
            let mut unsafe_source = source.clone();
            unsafe_source.source = path.into();
            assert!(unsafe_source.encode().is_err());
        }
    }

    #[test]
    fn artifact_round_trip_rejects_noncanonical_sources() {
        let source = EvidenceHash::parse(&"a".repeat(64)).unwrap();
        let artifact = ParquetArtifactV1 {
            path: "date=2026-10-28/account=demo/region=eu-west-1/part.parquet".into(),
            size: 123,
            sha256: source.clone(),
            parser_version: "json-cloudtrail-v5".into(),
            schema_version: "irmind-parquet-v1".into(),
            partition_date: "2026-10-28".into(),
            partition_account: "demo".into(),
            partition_region: "eu-west-1".into(),
            source_hashes: vec![source.clone()],
        };
        assert_eq!(
            ParquetArtifactV1::decode(&artifact.encode().unwrap()),
            Ok(artifact.clone())
        );
        let mut invalid = artifact;
        invalid.path = "date=2026-10-28/account=other/region=eu-west-1/part.parquet".into();
        assert!(invalid.encode().is_err());
        invalid.path = "date=2026-10-28/account=demo/region=eu-west-1/part.parquet".into();
        invalid.source_hashes.push(source);
        assert!(invalid.encode().is_err());
    }
}
