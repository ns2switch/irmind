use super::export_v4::{HeaderV4, MAGIC_V4, MAX_FRAME_BYTES, v4_result};
use super::{
    AppError, CaseId, LocalVerifier, Path, Severity, hex, seal_challenge, sha256, storage,
    storage_reason, verify_case_metadata,
};
use irmind_app::{ExportVerification, SignedEntry, SignedOperation, Verifier};
use irmind_domain::{
    Actor, AuditEventKind, ParquetArtifactV1, SealedParquetMigrationV1, SourceManifestV1,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;

const MAX_AUDIT_ENTRIES: u64 = 5_000_000;
const MAX_SOURCE_MANIFESTS: usize = 1_000_000;
const MAX_V4_FILE_BYTES: u64 = 2_000_000_000_000;

pub(super) fn verify_export_v4(
    path: &Path,
    expected_key: Option<&str>,
) -> Result<ExportVerification, AppError> {
    let mut input = File::open(path).map_err(storage)?;
    if input.metadata().map_err(storage)?.len() > MAX_V4_FILE_BYTES {
        return Err(storage_reason("export package exceeds size limit"));
    }
    let mut magic = [0u8; MAGIC_V4.len()];
    input.read_exact(&mut magic).map_err(storage)?;
    if magic != MAGIC_V4 {
        return Err(storage_reason("unsupported export version"));
    }
    let header: HeaderV4 = serde_json::from_slice(&read_frame(&mut input)?).map_err(storage)?;
    if header.version != 4 {
        return Err(storage_reason("unsupported export version"));
    }
    let id =
        CaseId::parse(&header.case_id).map_err(|_| storage_reason("invalid case id in export"))?;
    let count = read_u64(&mut input)?;
    if count == 0 || count > MAX_AUDIT_ENTRIES {
        return Err(storage_reason("invalid audit entry count"));
    }
    let mut chain = ChainState::new();
    for index in 0..count {
        let entry: SignedEntry =
            serde_json::from_slice(&read_frame(&mut input)?).map_err(storage)?;
        chain.accept(&id, index, entry)?;
    }
    chain.verify_seal(&id, &header)?;
    let fingerprint = hex(&sha256(&header.seal.public_key));
    if expected_key.is_some_and(|key| !key.eq_ignore_ascii_case(&fingerprint)) {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::AdapterSignature(
                irmind_app::AdapterSignatureError::ExportKeyDoesNotMatchExpectedFingerprint,
            ),
        ));
    }
    verify_legacy_blobs(&mut input, &chain)?;
    let provided_count = verify_source_frames(&mut input, &mut chain)?;
    verify_operation_frames(&mut input, &mut chain, &header)?;
    let mut trailer = [0u8; 1];
    if input.read(&mut trailer).map_err(storage)? != 0 {
        return Err(storage_reason("export has trailing bytes"));
    }
    Ok(v4_result(
        fingerprint,
        usize::try_from(count).map_err(storage)?,
        chain.source_count,
        provided_count,
    ))
}

fn verify_operation_frames(
    input: &mut File,
    chain: &mut ChainState,
    header: &HeaderV4,
) -> Result<(), AppError> {
    let count = read_u64(input)?;
    if count > MAX_AUDIT_ENTRIES {
        return Err(storage_reason("too many operational entries"));
    }
    let mut previous = [0; 32];
    for index in 0..count {
        let operation: SignedOperation =
            serde_json::from_slice(&read_frame(input)?).map_err(storage)?;
        if operation.case_id != header.case_id
            || operation.seq != index + 1
            || operation.prev != previous
            || sha256(&operation.canonical()) != operation.hash
            || chain.verifier.trusted_public_key(&operation.actor)? != operation.public_key
        {
            return Err(AppError::InvalidChain(operation.seq));
        }
        chain
            .verifier
            .verify(&operation.public_key, &operation.hash, &operation.sig)
            .map_err(|_| AppError::InvalidChain(operation.seq))?;
        if let Some(record) = SealedParquetMigrationV1::decode(&operation.operation)
            .map_err(|_| AppError::InvalidChain(operation.seq))?
        {
            if operation.actor != Actor::Analyst
                || record.seal_hash != header.seal.hash
                || record.artifact.source_hashes.len() != 1
                || !chain
                    .source_hashes
                    .contains(record.artifact.source_hashes[0].as_str())
                || !chain.artifact_paths.insert(record.artifact.path.clone())
            {
                return Err(AppError::InvalidChain(operation.seq));
            }
            chain.artifact_sources.extend(
                record
                    .artifact
                    .source_hashes
                    .into_iter()
                    .map(|hash| hash.as_str().to_owned()),
            );
        }
        previous = operation.hash;
    }
    if !chain.source_hashes.is_subset(&chain.artifact_sources) {
        return Err(AppError::InvalidChain(header.seal.seq));
    }
    Ok(())
}

fn verify_legacy_blobs(input: &mut File, chain: &ChainState) -> Result<(), AppError> {
    let evidence_count = read_u64(input)?;
    if evidence_count > MAX_SOURCE_MANIFESTS as u64 {
        return Err(storage_reason("too many copied evidence blobs"));
    }
    let mut evidence_hashes = BTreeSet::new();
    for _ in 0..evidence_count {
        let hash = read_hash(input)?;
        let size = read_u64(input)?;
        if size > 50_000_000 || !evidence_hashes.insert(hash.clone()) {
            return Err(storage_reason("invalid copied evidence frame"));
        }
        verify_raw(input, size, &hash)?;
    }
    let last = chain.last.as_ref().ok_or(AppError::InvalidChain(0))?;
    if evidence_hashes
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",")
        != last.payload
        || chain.referenced_evidence.iter().any(|hash| {
            !evidence_hashes.contains(hash)
                && !chain.sources.keys().any(|(source, _)| source == hash)
        })
    {
        return Err(AppError::InvalidChain(last.seq));
    }
    Ok(())
}

fn verify_source_frames(input: &mut File, chain: &mut ChainState) -> Result<usize, AppError> {
    let provided = read_u64(input)?;
    let provided_count = usize::try_from(provided).map_err(storage)?;
    if provided > MAX_SOURCE_MANIFESTS as u64
        || (provided != 0 && provided_count != chain.source_count)
    {
        return Err(storage_reason(
            "source frame count differs from signed manifest",
        ));
    }
    for _ in 0..provided {
        let hash = read_hash(input)?;
        let size = read_u64(input)?;
        let key = (hash.clone(), size);
        let remaining = chain
            .sources
            .get_mut(&key)
            .ok_or_else(|| storage_reason("source frame is not in signed manifest"))?;
        if *remaining == 0 {
            return Err(storage_reason("duplicate source frame"));
        }
        *remaining -= 1;
        verify_raw(input, size, &hash)?;
    }
    if provided != 0 && chain.sources.values().any(|remaining| *remaining != 0) {
        return Err(storage_reason("missing original source frame"));
    }
    Ok(provided_count)
}

struct ChainState {
    previous: [u8; 32],
    verifier: LocalVerifier,
    metadata_entries: Vec<SignedEntry>,
    last: Option<SignedEntry>,
    referenced_evidence: BTreeSet<String>,
    sources: BTreeMap<(String, u64), usize>,
    source_hashes: BTreeSet<String>,
    artifact_paths: BTreeSet<String>,
    artifact_sources: BTreeSet<String>,
    source_count: usize,
}

impl ChainState {
    fn new() -> Self {
        Self {
            previous: [0; 32],
            verifier: LocalVerifier {
                trusted: BTreeMap::new(),
            },
            metadata_entries: Vec::new(),
            last: None,
            referenced_evidence: BTreeSet::new(),
            sources: BTreeMap::new(),
            source_hashes: BTreeSet::new(),
            artifact_paths: BTreeSet::new(),
            artifact_sources: BTreeSet::new(),
            source_count: 0,
        }
    }

    fn accept(&mut self, id: &CaseId, index: u64, entry: SignedEntry) -> Result<(), AppError> {
        if entry.case_id != id.as_str()
            || entry.seq != index + 1
            || entry.prev != self.previous
            || sha256(&entry.canonical()) != entry.hash
            || (index == 0 && entry.kind != AuditEventKind::CaseCreated)
            || (index > 0 && entry.kind == AuditEventKind::CaseCreated)
            || self
                .last
                .as_ref()
                .is_some_and(|last| last.kind == AuditEventKind::CaseSealed)
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        self.verifier
            .verify(&entry.public_key, &entry.hash, &entry.sig)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        self.verifier = self
            .verifier
            .clone()
            .with_trusted_key(&entry.actor, &entry.public_key)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        match entry.kind {
            AuditEventKind::CaseCreated | AuditEventKind::CaseScopeChanged => {
                self.metadata_entries.push(entry.clone());
            }
            AuditEventKind::EvidenceIngested | AuditEventKind::GraphIndexed => {
                let hash = entry
                    .evidence
                    .as_deref()
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                irmind_domain::EvidenceHash::parse(hash)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                self.source_hashes.insert(hash.to_owned());
            }
            AuditEventKind::SourceManifestV1 | AuditEventKind::SourceManifestV2 => {
                let source = SourceManifestV1::decode_signed(entry.kind, &entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                let source = source.ok_or(AppError::InvalidChain(entry.seq))?;
                if entry.evidence.is_some() || self.source_count >= MAX_SOURCE_MANIFESTS {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                self.source_count += 1;
                self.source_hashes.insert(source.sha256.as_str().into());
                *self
                    .sources
                    .entry((source.sha256.as_str().into(), source.size))
                    .or_default() += 1;
            }
            AuditEventKind::ParquetArtifactV1 => {
                let artifact = ParquetArtifactV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if entry.evidence.is_some()
                    || !self.artifact_paths.insert(artifact.path)
                    || artifact
                        .source_hashes
                        .iter()
                        .any(|hash| !self.source_hashes.contains(hash.as_str()))
                {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                self.artifact_sources.extend(
                    artifact
                        .source_hashes
                        .into_iter()
                        .map(|hash| hash.as_str().to_owned()),
                );
            }
            _ => {}
        }
        if let Some(hash) = &entry.evidence {
            self.referenced_evidence.insert(hash.clone());
        }
        self.previous = entry.hash;
        self.last = Some(entry);
        Ok(())
    }

    fn verify_seal(&self, id: &CaseId, header: &HeaderV4) -> Result<(), AppError> {
        let severity = Severity::parse(&header.severity).map_err(|_| AppError::InvalidChain(1))?;
        verify_case_metadata(
            &header.title,
            severity,
            &header.scope,
            &self.metadata_entries,
        )?;
        let last = self.last.as_ref().ok_or(AppError::InvalidChain(0))?;
        if last.kind != AuditEventKind::CaseSealed
            || last.actor != Actor::Analyst
            || last.seq != header.seal.seq
            || last.hash != header.seal.hash
            || last.public_key != header.seal.public_key
            || header.seal.analyst_key_fingerprint != hex(&sha256(&header.seal.public_key))
        {
            return Err(AppError::InvalidChain(last.seq));
        }
        self.verifier
            .verify(
                &header.seal.public_key,
                &seal_challenge(id, last.seq, &last.hash, &last.payload),
                &header.seal.sig,
            )
            .map_err(|_| AppError::InvalidChain(last.seq))
    }
}

fn read_frame(input: &mut File) -> Result<Vec<u8>, AppError> {
    let length = read_u64(input)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(storage_reason("invalid export metadata frame length"));
    }
    let mut bytes = vec![0u8; usize::try_from(length).map_err(storage)?];
    input.read_exact(&mut bytes).map_err(storage)?;
    Ok(bytes)
}

fn read_u64(input: &mut File) -> Result<u64, AppError> {
    let mut bytes = [0u8; 8];
    input.read_exact(&mut bytes).map_err(storage)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_hash(input: &mut File) -> Result<String, AppError> {
    let mut bytes = [0u8; 64];
    input.read_exact(&mut bytes).map_err(storage)?;
    let hash = std::str::from_utf8(&bytes).map_err(storage)?;
    irmind_domain::EvidenceHash::parse(hash).map_err(|_| storage_reason("invalid export hash"))?;
    Ok(hash.into())
}

fn verify_raw(input: &mut File, size: u64, expected: &str) -> Result<(), AppError> {
    let mut left = size;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    while left > 0 {
        let count = usize::try_from(left.min(chunk.len() as u64)).map_err(storage)?;
        input.read_exact(&mut chunk[..count]).map_err(storage)?;
        hasher.update(&chunk[..count]);
        left -= count as u64;
    }
    if hex(&hasher.finalize()) != expected {
        return Err(AppError::EvidenceMismatch(expected.into()));
    }
    Ok(())
}
