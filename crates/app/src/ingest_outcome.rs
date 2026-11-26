//! Canonical audit bodies for local file dispositions and unsigned checksum comparisons.
use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, CaseId, Engine, SignedEntry,
};
use irmind_domain::{Actor, SourceReferenceV1};
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"irmind-ingest-file-outcome-v1\0";
const MAX_PATH: usize = 1024;
const MAX_BODY: usize = DOMAIN.len() + 1 + 2 * (4 + MAX_PATH + 8 + 32) + 34;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileFingerprint {
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdentity {
    Complete(FileFingerprint),
    SizeOnly(u64),
    Unavailable,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileReason {
    AnalystSkipped = 0,
    ChecksumCompanion = 1,
    SignatureCompanion = 2,
    CollectorLog = 3,
    IntegrityDigest = 4,
    NoParserSelected = 5,
    PipelineUnavailable = 6,
    InvalidFormat = 7,
    SourceLimit = 8,
    SourceChanged = 9,
    Unavailable = 10,
}
impl FileReason {
    const ALL: [Self; 11] = [
        Self::AnalystSkipped,
        Self::ChecksumCompanion,
        Self::SignatureCompanion,
        Self::CollectorLog,
        Self::IntegrityDigest,
        Self::NoParserSelected,
        Self::PipelineUnavailable,
        Self::InvalidFormat,
        Self::SourceLimit,
        Self::SourceChanged,
        Self::Unavailable,
    ];

    pub const fn failed(self) -> bool {
        self as u8 >= Self::PipelineUnavailable as u8
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::AnalystSkipped => "skipped by the analyst",
            Self::ChecksumCompanion => "checksum companion",
            Self::SignatureCompanion => "signature companion",
            Self::CollectorLog => "collector execution log",
            Self::IntegrityDigest => "integrity digest",
            Self::NoParserSelected => "no parser selected",
            Self::PipelineUnavailable => "parser pipeline unavailable",
            Self::InvalidFormat => "invalid source format",
            Self::SourceLimit => "source limit exceeded",
            Self::SourceChanged => "source changed",
            Self::Unavailable => "source unavailable for safe read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestFileOutcome {
    Disposition {
        path: String,
        identity: FileIdentity,
        reason: FileReason,
    },
    Integrity {
        path: String,
        observed: FileFingerprint,
        companion: String,
        companion_identity: FileFingerprint,
        declared: [u8; 32],
    },
}

fn invalid() -> AppError {
    AppError::Policy("invalid signed file ingestion outcome".into())
}

pub fn validate_local_reference(path: &str) -> Result<(), AppError> {
    if path.len() > MAX_PATH
        || path.contains([':', '\\'])
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        || SourceReferenceV1::file(path).is_err()
    {
        return Err(invalid());
    }
    Ok(())
}

impl IngestFileOutcome {
    pub fn encode(&self) -> Result<String, AppError> {
        let mut bytes = DOMAIN.to_vec();
        match self {
            Self::Disposition {
                path,
                identity,
                reason,
            } => {
                bytes.push(0);
                put_path(&mut bytes, path)?;
                match identity {
                    FileIdentity::Complete(identity) => {
                        bytes.push(0);
                        put_fingerprint(&mut bytes, identity);
                    }
                    FileIdentity::SizeOnly(size) if *reason as u8 >= 8 => {
                        bytes.push(1);
                        bytes.extend(size.to_be_bytes());
                    }
                    FileIdentity::Unavailable if *reason as u8 >= 8 => bytes.push(2),
                    _ => return Err(invalid()),
                }
                bytes.extend([u8::from(reason.failed()), *reason as u8]);
            }
            Self::Integrity {
                path,
                observed,
                companion,
                companion_identity,
                declared,
            } => {
                if path == companion {
                    return Err(invalid());
                }
                bytes.push(1);
                put_path(&mut bytes, path)?;
                bytes.push(0);
                put_fingerprint(&mut bytes, observed);
                put_path(&mut bytes, companion)?;
                put_fingerprint(&mut bytes, companion_identity);
                bytes.extend(declared);
                bytes.push(u8::from(&observed.sha256 != declared));
            }
        }
        Ok(hex::encode(bytes))
    }

    pub fn decode(payload: &str) -> Result<Self, AppError> {
        if payload.len() > 2 * MAX_BODY
            || !payload
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(invalid());
        }
        let bytes = hex::decode(payload).map_err(|_| invalid())?;
        let mut input = Wire(bytes.strip_prefix(DOMAIN).ok_or_else(invalid)?);
        let variant = input.byte()?;
        let path = input.path()?;
        let state = input.byte()?;
        let outcome = match variant {
            0 => {
                let identity = match state {
                    0 => FileIdentity::Complete(input.fingerprint()?),
                    1 => FileIdentity::SizeOnly(u64::from_be_bytes(input.array()?)),
                    2 => FileIdentity::Unavailable,
                    _ => return Err(invalid()),
                };
                let disposition = input.byte()?;
                let reason = *FileReason::ALL
                    .get(usize::from(input.byte()?))
                    .ok_or_else(invalid)?;
                if disposition != u8::from(reason.failed()) || (state != 0 && (reason as u8) < 8) {
                    return Err(invalid());
                }
                Self::Disposition {
                    path,
                    identity,
                    reason,
                }
            }
            1 if state == 0 => {
                let observed = input.fingerprint()?;
                let companion = input.path()?;
                let companion_identity = input.fingerprint()?;
                let declared = input.array()?;
                if path == companion || input.byte()? != u8::from(observed.sha256 != declared) {
                    return Err(invalid());
                }
                Self::Integrity {
                    path,
                    observed,
                    companion,
                    companion_identity,
                    declared,
                }
            }
            _ => return Err(invalid()),
        };
        if !input.0.is_empty() {
            return Err(invalid());
        }
        Ok(outcome)
    }

    pub fn from_audit(entry: &SignedEntry) -> Result<Option<Self>, AppError> {
        if entry.kind != AuditEventKind::IngestFileOutcomeV1 {
            return Ok(None);
        }
        if entry.actor != Actor::Analyst
            || entry.origin != AuditOrigin::Analyst.as_str()
            || entry.evidence.is_some()
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        Self::decode(&entry.payload)
            .map(Some)
            .map_err(|_| AppError::InvalidChain(entry.seq))
    }
}

impl Engine<'_> {
    pub fn record_ingest_outcomes(
        &self,
        id: &CaseId,
        outcomes: &[IngestFileOutcome],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if outcomes.is_empty() {
            return Ok(());
        }
        self.require_attended_analyst("record file ingestion outcomes")?;
        let _lock = self.repo.lock_case(id)?;
        self.verify_ingest_checkpoint(id, cancel)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Policy("case is sealed".into()));
        }
        for chunk in outcomes.chunks(1024) {
            let events = chunk
                .iter()
                .map(|outcome| {
                    Ok((
                        AuditOrigin::Analyst,
                        AuditEventKind::IngestFileOutcomeV1,
                        outcome.encode()?,
                    ))
                })
                .collect::<Result<Vec<_>, AppError>>()?;
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            self.audit_batch(id, &events)?;
        }
        Ok(())
    }
}

fn put_path(bytes: &mut Vec<u8>, path: &str) -> Result<(), AppError> {
    validate_local_reference(path)?;
    bytes.extend(
        u32::try_from(path.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    bytes.extend(path.as_bytes());
    Ok(())
}

fn put_fingerprint(bytes: &mut Vec<u8>, fingerprint: &FileFingerprint) {
    bytes.extend(fingerprint.size.to_be_bytes());
    bytes.extend(fingerprint.sha256);
}

struct Wire<'a>(&'a [u8]);
impl<'a> Wire<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AppError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or_else(invalid)?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AppError> {
        self.take(N)?.try_into().map_err(|_| invalid())
    }
    fn byte(&mut self) -> Result<u8, AppError> {
        Ok(u8::from_be_bytes(self.array()?))
    }
    fn path(&mut self) -> Result<String, AppError> {
        let len = usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| invalid())?;
        if len > MAX_PATH {
            return Err(invalid());
        }
        let path = std::str::from_utf8(self.take(len)?).map_err(|_| invalid())?;
        validate_local_reference(path)?;
        Ok(path.to_owned())
    }
    fn fingerprint(&mut self) -> Result<FileFingerprint, AppError> {
        Ok(FileFingerprint {
            size: u64::from_be_bytes(self.array()?),
            sha256: self.array()?,
        })
    }
}

/// Same streaming raw-byte digest used for original verification, with an
/// optional read limit for a folder member that has no manifest.
pub fn fingerprint_file(
    reader: &mut impl std::io::Read,
    limit: u64,
    chunk_size: usize,
    cancel: &CancellationToken,
) -> Result<FileFingerprint, AppError> {
    use sha2::{Digest as _, Sha256};
    let mut sha = Sha256::new();
    let mut size = 0u64;
    let mut chunk = vec![0u8; chunk_size.clamp(1, 1024 * 1024)];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let n = reader
            .read(&mut chunk)
            .map_err(|error| AppError::Storage(error.to_string()))?;
        if n == 0 {
            return Ok(FileFingerprint {
                size,
                sha256: sha.finalize().into(),
            });
        }
        size = size
            .checked_add(n as u64)
            .filter(|n| *n <= limit)
            .ok_or_else(|| AppError::Policy("file exceeds the raw fingerprint limit".into()))?;
        sha.update(&chunk[..n]);
    }
}

#[derive(Default)]
pub struct FileOutcomeReview {
    pub skipped: usize,
    pub failed: usize,
    pub matched: usize,
    pub mismatched: usize,
    pub limitations: Vec<FileOutcomeNotice>,
}

pub struct FileOutcomeNotice {
    pub sequence: u64,
    pub hash: irmind_domain::EvidenceHash,
    pub outcome: IngestFileOutcome,
}

impl FileOutcomeReview {
    /// Derive coverage from the authenticated case prefix. Receipts stay in
    /// the audit even when a later manifest resolves the same original bytes.
    pub fn read(entries: &[SignedEntry]) -> Result<Self, AppError> {
        if !entries
            .iter()
            .any(|entry| entry.kind == AuditEventKind::IngestFileOutcomeV1)
        {
            return Ok(Self::default());
        }
        let mut originals = BTreeMap::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        {
            let manifest = irmind_domain::SourceManifestV2::decode(&entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            originals.insert(manifest.source.source.clone(), (entry.seq, manifest.source));
        }
        let mut review = Self::default();
        let mut active_originals = BTreeMap::new();
        for entry in entries {
            if entry.kind == AuditEventKind::SourceManifestV2 {
                let manifest = irmind_domain::SourceManifestV2::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?
                    .source;
                active_originals.insert(manifest.source, (manifest.size, manifest.sha256));
                continue;
            }
            let Some(outcome) = IngestFileOutcome::from_audit(entry)? else {
                continue;
            };
            let include = match &outcome {
                IngestFileOutcome::Disposition {
                    path,
                    identity,
                    reason,
                } => {
                    if reason.failed() {
                        review.failed += 1;
                    } else {
                        review.skipped += 1;
                    }
                    !matches!(reason, FileReason::ChecksumCompanion | FileReason::SignatureCompanion
                        | FileReason::CollectorLog | FileReason::IntegrityDigest)
                        && !originals.get(path).is_some_and(|(seq, manifest)| {
                            *seq > entry.seq && matches!(identity, FileIdentity::Complete(known)
                                if known.size == manifest.size
                                    && irmind_domain::EvidenceHash::from_bytes(known.sha256) == manifest.sha256)
                        })
                }
                IngestFileOutcome::Integrity {
                    path,
                    observed,
                    declared,
                    ..
                } => {
                    if active_originals.get(path).is_some_and(|(size, hash)| {
                        observed.size != *size
                            || irmind_domain::EvidenceHash::from_bytes(observed.sha256) != *hash
                    }) {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                    if observed.sha256 == *declared {
                        review.matched += 1;
                        false
                    } else {
                        review.mismatched += 1;
                        true
                    }
                }
            };
            if include {
                review.limitations.push(FileOutcomeNotice {
                    sequence: entry.seq,
                    hash: irmind_domain::EvidenceHash::from_bytes(entry.hash),
                    outcome,
                });
            }
        }
        Ok(review)
    }

    pub fn summary(&self) -> String {
        format!(
            "{} skipped · {} failed · {} SHA-256 matches · {} SHA-256 mismatches",
            self.skipped, self.failed, self.matched, self.mismatched
        )
    }
}

impl FileOutcomeNotice {
    pub fn fingerprint_display(&self) -> String {
        match &self.outcome {
            IngestFileOutcome::Disposition { identity, .. } => match identity {
                FileIdentity::Complete(fingerprint) => format!(
                    "{} bytes · SHA-256 {}",
                    fingerprint.size,
                    hex::encode(fingerprint.sha256)
                ),
                FileIdentity::SizeOnly(size) => format!("{size} bytes · SHA-256 unavailable"),
                FileIdentity::Unavailable => "complete fingerprint unavailable".into(),
            },
            IngestFileOutcome::Integrity { observed, .. } => {
                format!(
                    "{} bytes · SHA-256 {}",
                    observed.size,
                    hex::encode(observed.sha256)
                )
            }
        }
    }

    pub fn description(&self) -> (&str, &'static str) {
        match &self.outcome {
            IngestFileOutcome::Disposition { path, reason, .. } => (path, reason.description()),
            IngestFileOutcome::Integrity { path, .. } => (path, "SHA-256 MISMATCH"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    #[test]
    fn approved_wire_vectors() {
        let values: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/development/folder-ingest-outcomes-vectors/wire.json"
        ))
        .unwrap();
        for (name, vector) in values.as_object().unwrap() {
            let payload = vector["bytes_hex"].as_str().unwrap();
            if name.starts_with("reject_") {
                assert!(IngestFileOutcome::decode(payload).is_err(), "{name}");
            } else if !name.starts_with("signed_") {
                let decoded = IngestFileOutcome::decode(payload).unwrap();
                assert_eq!(decoded.encode().unwrap(), payload, "{name}");
            }
        }
        let signed: SignedEntry = serde_json::from_slice(
            &hex::decode(values["signed_skip"]["bytes_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(signed.canonical()),
            values["signed_skip_challenge"]["bytes_hex"]
        );
        assert_eq!(
            IngestFileOutcome::from_audit(&signed)
                .unwrap()
                .unwrap()
                .encode()
                .unwrap(),
            signed.payload
        );
    }

    #[test]
    fn only_a_later_manifest_with_the_same_bytes_resolves_a_disposition() {
        use irmind_domain::{
            EvidenceHash, ParserSelectionMode, SourceManifestV1, SourceManifestV2,
        };

        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/development/folder-ingest-outcomes-vectors/wire.json"
        ))
        .unwrap();
        let skip: SignedEntry = serde_json::from_slice(
            &hex::decode(cases["signed_skip"]["bytes_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let Some(IngestFileOutcome::Disposition {
            path,
            identity: FileIdentity::Complete(fingerprint),
            ..
        }) = IngestFileOutcome::from_audit(&skip).unwrap()
        else {
            panic!("expected an authenticated disposition fixture");
        };
        let mut manifest = SourceManifestV2 {
            source: SourceManifestV1 {
                source: path,
                size: fingerprint.size,
                modified_unix_seconds: None,
                version: None,
                provider_checksum: None,
                sha256: EvidenceHash::from_bytes(fingerprint.sha256),
                copied: false,
            },
            parser_id: "parser-json".into(),
            parser_version: "1".into(),
            confidence: 100,
            selection: ParserSelectionMode::Analyst,
            timestamp_context: None,
            cluster_context: None,
            rejected_records: 0,
            rejected_sample: Vec::new(),
        };
        let mut retry = skip.clone();
        retry.kind = AuditEventKind::SourceManifestV2;
        retry.seq += 1;
        retry.payload = manifest.encode().unwrap();
        let recovered = FileOutcomeReview::read(&[skip.clone(), retry.clone()]).unwrap();
        assert_eq!(recovered.skipped, 1);
        assert!(recovered.limitations.is_empty());
        manifest.source.sha256 = EvidenceHash::from_bytes([99; 32]);
        retry.payload = manifest.encode().unwrap();
        assert_eq!(
            FileOutcomeReview::read(&[skip, retry])
                .unwrap()
                .limitations
                .len(),
            1
        );
    }
}
