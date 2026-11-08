use super::{DomainError, EvidenceHash, hash_payload, invalid, wire};
use crate::custody_manifest::{Reader, put};
use crate::{SOURCE_RECORD_V1, SourceKind, SourceReferenceV1};

const TAG: &[u8] = b"irmind-source-record-set-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceDecoderIdentityV1 {
    id: String,
    version: String,
}
impl SourceDecoderIdentityV1 {
    pub fn try_new(id: &str, version: &str) -> Result<Self, DomainError> {
        if !wire::id(id, 64) || id.contains(['.', '_']) || !wire::version(version) {
            return Err(invalid());
        }
        Ok(Self {
            id: id.into(),
            version: version.into(),
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceFormatIdentityV1 {
    id: String,
    version: String,
}
impl SourceFormatIdentityV1 {
    pub fn try_new(id: &str, version: &str) -> Result<Self, DomainError> {
        crate::SourceFormatV1::try_new(id, version, std::collections::BTreeMap::new())
            .map_err(|_| invalid())?;
        Ok(Self {
            id: id.into(),
            version: version.into(),
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// The final count precedes ordered tuple bytes in the records commitment.
/// No decoded cache or mapping/output reference is part of this input set.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceRecordSetV1 {
    source: EvidenceHash,
    manifest: EvidenceHash,
    rejected: u64,
    reference: SourceReferenceV1,
    decoder: SourceDecoderIdentityV1,
    time_context: Option<super::SourceTimeContextV1>,
    formats: Vec<SourceFormatIdentityV1>,
    records: u64,
    commitment: EvidenceHash,
}
impl std::fmt::Debug for SourceRecordSetV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(crate::AuditEventKind::SourceRecordSetV1.as_str())
            .field("source", &self.source)
            .field("decoder", &self.decoder)
            .field("records", &self.records)
            .finish_non_exhaustive()
    }
}
impl SourceRecordSetV1 {
    pub fn from_manifest(
        manifest: &crate::SourceManifestV2,
        reference: SourceReferenceV1,
        formats: Vec<SourceFormatIdentityV1>,
        records: u64,
        commitment: EvidenceHash,
    ) -> Result<Self, DomainError> {
        Self::from_manifest_with_time(manifest, reference, formats, records, commitment, None)
    }
    pub fn from_manifest_with_time(
        manifest: &crate::SourceManifestV2,
        reference: SourceReferenceV1,
        formats: Vec<SourceFormatIdentityV1>,
        records: u64,
        commitment: EvidenceHash,
        time_context: Option<super::SourceTimeContextV1>,
    ) -> Result<Self, DomainError> {
        manifest.validate()?;
        if reference.reference() != manifest.source.source
            || !context_matches(time_context, manifest.timestamp_context.as_deref())
        {
            return Err(invalid());
        }
        Self::checked(Self {
            source: manifest.source.sha256.clone(),
            manifest: manifest_identity(manifest)?,
            rejected: manifest.rejected_records,
            time_context,
            reference,
            decoder: SourceDecoderIdentityV1::try_new(
                &manifest.parser_id,
                &manifest.parser_version,
            )?,
            formats,
            records,
            commitment,
        })
    }
    fn checked(value: Self) -> Result<Self, DomainError> {
        if value.records == 0
            || value.records > 10_000_000
            || value.formats.is_empty()
            || value.formats.len() > 128
            || !value.formats.windows(2).all(|f| f[0] < f[1])
        {
            return Err(invalid());
        }
        value.encode()?;
        Ok(value)
    }
    pub fn validate_manifest(&self, manifest: &crate::SourceManifestV2) -> Result<(), DomainError> {
        if self.source != manifest.source.sha256
            || self.reference.reference() != manifest.source.source
            || self.decoder.id() != manifest.parser_id
            || self.decoder.version() != manifest.parser_version
            || self.rejected != manifest.rejected_records
            || self.manifest != manifest_identity(manifest)?
            || !context_matches(self.time_context, manifest.timestamp_context.as_deref())
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub const fn manifest_identity(&self) -> &EvidenceHash {
        &self.manifest
    }
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }
    pub const fn time_context(&self) -> Option<super::SourceTimeContextV1> {
        self.time_context
    }
    pub const fn source(&self) -> &EvidenceHash {
        &self.source
    }
    pub const fn reference(&self) -> &SourceReferenceV1 {
        &self.reference
    }
    pub const fn decoder(&self) -> &SourceDecoderIdentityV1 {
        &self.decoder
    }
    pub fn formats(&self) -> &[SourceFormatIdentityV1] {
        &self.formats
    }
    pub const fn records(&self) -> u64 {
        self.records
    }
    pub const fn records_commitment(&self) -> &EvidenceHash {
        &self.commitment
    }
    pub fn identity(&self) -> Result<EvidenceHash, DomainError> {
        hash_payload(&self.encode()?, TAG)
    }

    pub fn encode(&self) -> Result<String, DomainError> {
        let mut bytes = TAG.to_vec();
        put(&mut bytes, self.source.as_str().as_bytes());
        put(&mut bytes, self.manifest.as_str().as_bytes());
        put(&mut bytes, self.reference.reference().as_bytes());
        bytes.push(match self.reference.kind() {
            SourceKind::File => 0,
            SourceKind::ToolResult => 1,
            _ => return Err(invalid()),
        });
        bytes.push(u8::from(self.reference.acquisition().is_some()));
        if let Some(hash) = self.reference.acquisition() {
            put(&mut bytes, hash.as_str().as_bytes());
        }
        put(&mut bytes, self.decoder.id.as_bytes());
        put(&mut bytes, self.decoder.version.as_bytes());
        bytes.push(u8::from(self.time_context.is_some()));
        if let Some(context) = self.time_context {
            context.write(&mut bytes);
        }
        put(&mut bytes, SOURCE_RECORD_V1.as_bytes());
        put(
            &mut bytes,
            super::source_record_contract_digest().as_str().as_bytes(),
        );
        bytes.extend_from_slice(&(self.formats.len() as u64).to_be_bytes());
        for format in &self.formats {
            put(&mut bytes, format.id.as_bytes());
            put(&mut bytes, format.version.as_bytes());
        }
        bytes.extend_from_slice(&self.records.to_be_bytes());
        bytes.extend_from_slice(&self.rejected.to_be_bytes());
        put(&mut bytes, self.commitment.as_str().as_bytes());
        wire::encode(&bytes, wire::MAX_SMALL)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = wire::decode(payload, TAG, wire::MAX_SMALL)?;
        let mut r = Reader::new(&bytes[TAG.len()..]);
        let source = EvidenceHash::parse(&r.string_limit(64)?)?;
        let manifest = EvidenceHash::parse(&r.string_limit(64)?)?;
        let location = r.string_limit(1024)?;
        let kind = match r.byte()? {
            0 => SourceKind::File,
            1 => SourceKind::ToolResult,
            _ => return Err(invalid()),
        };
        let acquisition = if r.bool()? {
            Some(EvidenceHash::parse(&r.string_limit(64)?)?)
        } else {
            None
        };
        let reference =
            SourceReferenceV1::try_new(&location, kind, acquisition).map_err(|_| invalid())?;
        let decoder =
            SourceDecoderIdentityV1::try_new(&r.string_limit(64)?, &r.string_limit(128)?)?;
        let time_context = if r.bool()? {
            Some(super::SourceTimeContextV1::read(&mut r)?)
        } else {
            None
        };
        if r.string_limit(128)? != SOURCE_RECORD_V1 {
            return Err(invalid());
        }
        if r.string_limit(64)? != super::source_record_contract_digest().as_str() {
            return Err(invalid());
        }
        let count = r.u64()?;
        if count == 0 || count > 128 {
            return Err(invalid());
        }
        let mut formats = Vec::with_capacity(usize::try_from(count).map_err(|_| invalid())?);
        for _ in 0..count {
            formats.push(SourceFormatIdentityV1::try_new(
                &r.string_limit(64)?,
                &r.string_limit(128)?,
            )?);
        }
        let records = r.u64()?;
        let rejected = r.u64()?;
        let commitment = EvidenceHash::parse(&r.string_limit(64)?)?;
        r.end()?;
        Self::checked(Self {
            source,
            manifest,
            rejected,
            reference,
            decoder,
            time_context,
            formats,
            records,
            commitment,
        })
    }
}

pub(super) fn manifest_identity(
    manifest: &crate::SourceManifestV2,
) -> Result<EvidenceHash, DomainError> {
    hash_payload(&manifest.encode()?, b"irmind-source-manifest-v2\0")
}

fn context_matches(context: Option<super::SourceTimeContextV1>, snapshot: Option<&str>) -> bool {
    match context {
        Some(context) => snapshot.is_some_and(|s| s == context.snapshot()),
        None => matches!(snapshot, None | Some("normalized-utc")),
    }
}
