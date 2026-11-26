use super::export_current::{EXPORT_VERSION, HeaderV10, MAGIC_V10, v10_result};
use super::frames::{read_frame, read_hash, read_u64, verify_raw};
use super::{
    AppError, CaseId, LocalVerifier, Path, Severity, hex, seal_challenge, sha256, storage,
    storage_reason, verify_case_metadata,
};
use irmind_app::{ExportVerification, SignedEntry, SignedOperation, Verifier};
use irmind_domain::{Actor, AuditEventKind, SourceManifestV2};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek as _, SeekFrom};

const MAX_AUDIT_ENTRIES: u64 = 5_000_000;
const MAX_SOURCE_MANIFESTS: usize = 1_000_000;
const MAX_PACKAGE_FILE_BYTES: u64 = 2_000_000_000_000;

pub(super) fn verify_export_v10(
    path: &Path,
    expected_key: Option<&str>,
) -> Result<ExportVerification, AppError> {
    let input = File::open(path).map_err(storage)?;
    let size = input.metadata().map_err(storage)?.len();
    verify_open_export(input, size, expected_key)
}

// Production always obtains size from this same opened file. Keeping the
// metadata gate here allows boundary tests without allocating huge fixtures.
fn verify_open_export(
    input: File,
    size: u64,
    expected_key: Option<&str>,
) -> Result<ExportVerification, AppError> {
    let catalog = crate::Ed25519CatalogIndexVerifier::production()?;
    verify_open_export_with_catalog(input, size, expected_key, &catalog)
}

fn verify_open_export_with_catalog(
    mut input: File,
    size: u64,
    expected_key: Option<&str>,
    catalog: &dyn irmind_app::catalog::CatalogIndexVerifier,
) -> Result<ExportVerification, AppError> {
    if size > MAX_PACKAGE_FILE_BYTES {
        return Err(storage_reason("export package exceeds size limit"));
    }
    let (header, id) = read_header(&mut input)?;
    let count = read_u64(&mut input)?;
    if count == 0 || count > MAX_AUDIT_ENTRIES {
        return Err(storage_reason("invalid audit entry count"));
    }
    let audit_start = input.stream_position().map_err(storage)?;
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
    verify_evidence_blobs(&mut input, &mut chain)?;
    let provided_count = verify_source_frames(&mut input, &mut chain)?;
    let operations = verify_operation_frames(&mut input, &chain, &header)?;
    let cancel = irmind_app::CancellationToken::new();
    {
        super::mapping_proofs::read(
            &mut input,
            &chain.mapping_installations,
            &chain.verifier,
            &header.seal.public_key,
        )?;
    }
    let offsets = super::artifact_frames::verify_artifact_frames(&mut input, &chain.artifacts)?;
    verify_methodology_tail(&mut input, &mut chain, &header, catalog)?;
    let journal = irmind_app::source_queries::SourceQueryJournal::replay(
        &chain.metadata_entries,
        &operations.query_adoptions,
        &chain.verifier,
        &cancel,
    )?;
    if journal.adoptions().len() != operations.query_adoptions.len() {
        return Err(AppError::InvalidChain(header.seal.seq));
    }
    journal.verify_source_links(&chain.metadata_entries)?;
    let captures = journal.captures().collect::<Vec<_>>();
    irmind_app::source_queries::read_query_capture_section(&mut input, &captures, &cancel)?;
    let proof_entries = chain.read_proof_history(&mut input, &id, audit_start, count, &cancel)?;
    super::extensions::verify(
        &mut input,
        &super::extensions::ReportVerification {
            title: &header.title,
            entries: &proof_entries,
            sigma_admissions: &operations.sigma_admissions,
            evidence: &chain.copied_evidence,
            skills: &chain.skills,
            offsets: &offsets,
        },
        &cancel,
    )?;
    let mut result = v10_result(
        fingerprint,
        usize::try_from(count).map_err(storage)?,
        chain.source_count,
        provided_count + captures.len(),
    );
    result.source_query_limits = captures
        .iter()
        .filter_map(|receipt| receipt.limit_notice())
        .collect();
    Ok(result)
}

fn read_header(input: &mut File) -> Result<(HeaderV10, CaseId), AppError> {
    let mut magic = [0u8; MAGIC_V10.len()];
    if input.read_exact(&mut magic).is_err() || magic != MAGIC_V10 {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredExportFormat,
        ));
    }
    let encoded_header = read_frame(input)?;
    let header: HeaderV10 = serde_json::from_slice(&encoded_header).map_err(storage)?;
    if header.version != EXPORT_VERSION {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredExportFormat,
        ));
    }
    if serde_json::to_vec(&header).map_err(storage)? != encoded_header {
        return Err(storage_reason("noncanonical export header"));
    }
    let id = CaseId::parse(&header.case_id)
        .ok()
        .filter(|id| {
            id.as_str().bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
                }
            })
        })
        .ok_or_else(|| storage_reason("invalid case id in export"))?;
    Ok((header, id))
}

fn verify_methodology_tail(
    input: &mut File,
    chain: &mut ChainState,
    header: &HeaderV10,
    catalog: &dyn irmind_app::catalog::CatalogIndexVerifier,
) -> Result<(), AppError> {
    let proofs = super::skill_proofs::read(
        input,
        &chain.skills,
        &chain.verifier,
        &header.seal.public_key,
    )?;
    super::catalog_proofs::read(
        input,
        &mut chain.skills,
        &proofs,
        &chain.verifier,
        &header.seal.public_key,
        catalog,
    )?;
    super::subagent_branches::read(
        input,
        chain.subagents.as_ref().ok_or(AppError::InvalidChain(0))?,
        &chain.verifier,
        &mut chain.skills,
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn verify_export_with_catalog(
    path: &Path,
    expected_key: Option<&str>,
    catalog: &dyn irmind_app::catalog::CatalogIndexVerifier,
) -> Result<ExportVerification, AppError> {
    let input = File::open(path).map_err(storage)?;
    let size = input.metadata().map_err(storage)?.len();
    verify_open_export_with_catalog(input, size, expected_key, catalog)
}

struct ScopedOperations {
    query_adoptions: Vec<SignedOperation>,
    sigma_admissions: BTreeMap<[u8; 32], SignedOperation>,
}

fn verify_operation_frames(
    input: &mut File,
    chain: &ChainState,
    header: &HeaderV10,
) -> Result<ScopedOperations, AppError> {
    let count = read_u64(input)?;
    if count > MAX_AUDIT_ENTRIES {
        return Err(storage_reason("too many operational entries"));
    }
    let mut previous = [0; 32];
    let mut previous_global = None;
    let mut operations = ScopedOperations {
        query_adoptions: Vec::new(),
        sigma_admissions: BTreeMap::new(),
    };
    for index in 0..count {
        let operation: SignedOperation =
            serde_json::from_slice(&read_frame(input)?).map_err(storage)?;
        if operation.case_id == irmind_app::GLOBAL_OPERATION_SCOPE {
            if previous_global.is_some_and(|prior| prior >= operation.hash) {
                return Err(AppError::InvalidChain(operation.seq));
            }
            previous_global = Some(operation.hash);
            if irmind_app::v10_proofs::sigma_pack_operation(&operation)?.is_some() {
                irmind_app::v10_proofs::verify_sigma_pack_operation(&operation, &chain.verifier)?;
                operations
                    .sigma_admissions
                    .insert(operation.hash, operation);
            } else {
                // The query journal authenticates its proofs and requires references.
                operations.query_adoptions.push(operation);
            }
            continue;
        }
        if previous_global.is_some()
            || operation.case_id != header.case_id
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
        previous = operation.hash;
    }
    if !chain.source_hashes.is_subset(&chain.artifact_sources) {
        return Err(AppError::InvalidChain(header.seal.seq));
    }
    Ok(operations)
}

fn verify_evidence_blobs(input: &mut File, chain: &mut ChainState) -> Result<(), AppError> {
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
    let matches = if chain.inventory.has_mapped_artifacts() {
        for hash in &evidence_hashes {
            chain.inventory.add_evidence(hash)?;
        }
        chain.inventory.verify(&last.payload).is_ok()
    } else {
        evidence_hashes
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",")
            == last.payload
    };
    if !matches
        || chain.referenced_evidence.iter().any(|hash| {
            !evidence_hashes.contains(hash)
                && !chain.sources.keys().any(|(source, _)| source == hash)
                && !chain.query_hashes.contains(hash)
        })
    {
        return Err(AppError::InvalidChain(last.seq));
    }
    chain.copied_evidence = evidence_hashes;
    Ok(())
}

fn verify_source_frames(input: &mut File, chain: &mut ChainState) -> Result<usize, AppError> {
    let provided = read_u64(input)?;
    let provided_count = usize::try_from(provided).map_err(storage)?;
    let originals = chain
        .source_count
        .checked_sub(chain.query_hashes.len())
        .ok_or_else(|| storage_reason("capture count differs from signed manifest"))?;
    if provided > MAX_SOURCE_MANIFESTS as u64 || (provided != 0 && provided_count != originals) {
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
    skills: irmind_app::SkillReceiptVerifier,
    subagents: Option<irmind_app::subagents::SubagentJournal>,
    mapping_installations:
        BTreeMap<irmind_domain::EvidenceHash, irmind_app::source_mapping::MappingManifest>,
    catalog: irmind_app::ArtifactCatalogBuilder,
    inventory: irmind_app::SealInventoryBuilder,
    artifacts: BTreeMap<String, super::artifact_frames::ArtifactFrame>,
    previous: [u8; 32],
    verifier: LocalVerifier,
    metadata_entries: Vec<SignedEntry>,
    query_hashes: BTreeSet<String>,
    last: Option<SignedEntry>,
    referenced_evidence: BTreeSet<String>,
    copied_evidence: BTreeSet<String>,
    proof_checkpoints: BTreeSet<u64>,
    sources: BTreeMap<(String, u64), usize>,
    source_hashes: BTreeSet<String>,
    artifact_paths: BTreeSet<String>,
    artifact_sources: BTreeSet<String>,
    source_count: usize,
}

impl ChainState {
    fn new() -> Self {
        let mut skills = irmind_app::SkillReceiptVerifier::default();
        skills.track_report_loads();
        Self {
            skills,
            subagents: None,
            mapping_installations: BTreeMap::new(),
            catalog: irmind_app::ArtifactCatalogBuilder::default(),
            inventory: irmind_app::SealInventoryBuilder::default(),
            artifacts: BTreeMap::new(),
            previous: [0; 32],
            verifier: LocalVerifier {
                trusted: BTreeMap::new(),
            },
            metadata_entries: Vec::new(),
            query_hashes: BTreeSet::new(),
            last: None,
            referenced_evidence: BTreeSet::new(),
            copied_evidence: BTreeSet::new(),
            proof_checkpoints: BTreeSet::new(),
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
        if index == 0 {
            irmind_app::budget_status(
                std::slice::from_ref(&entry),
                &irmind_domain::PolicyRules::default(),
            )?;
        }
        {
            self.catalog.accept(&entry)?;
            self.inventory.accept(&entry)?;
        }
        if self.subagents.is_none() {
            self.subagents = Some(
                irmind_app::subagents::SubagentJournal::for_verification(id.clone())
                    .map_err(|_| AppError::InvalidChain(entry.seq))?,
            );
        }
        self.subagents
            .as_mut()
            .ok_or(AppError::InvalidChain(entry.seq))?
            .accept(&entry, &self.verifier)?;
        super::mapping_proofs::collect(&entry, &mut self.mapping_installations)?;
        self.skills.accept(&entry, &crate::TomlSkillCompiler)?;
        self.accept_metadata(&entry)?;
        if entry.kind == AuditEventKind::SigmaRunV1 {
            self.proof_checkpoints.insert(
                irmind_app::v10_proofs::sigma_execution(&entry)?
                    .checkpoint
                    .sequence,
            );
        }
        if entry.kind == AuditEventKind::ReportPublishedV1 {
            self.proof_checkpoints
                .insert(irmind_app::report_publication(&entry)?.checkpoint.sequence);
        }
        if let Some(hash) = &entry.evidence {
            self.referenced_evidence.insert(hash.clone());
        }
        self.previous = entry.hash;
        self.last = Some(entry);
        Ok(())
    }

    fn read_proof_history(
        &self,
        input: &mut File,
        case: &CaseId,
        start: u64,
        count: u64,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<Vec<SignedEntry>, AppError> {
        if self.proof_checkpoints.is_empty() {
            return Ok(Vec::new());
        }
        let resume = input.stream_position().map_err(storage)?;
        input.seek(SeekFrom::Start(start)).map_err(storage)?;
        let mut history = Vec::new();
        let mut previous = [0; 32];
        // Reauthenticate the streamed ledger against the sealed tip. Keep only
        // provenance and claims needed to resolve report checkpoints.
        for index in 0..count {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let entry: SignedEntry =
                serde_json::from_slice(&read_frame(input)?).map_err(storage)?;
            if entry.case_id != case.as_str()
                || entry.seq != index + 1
                || entry.prev != previous
                || sha256(&entry.canonical()) != entry.hash
                || self.verifier.trusted_public_key(&entry.actor)? != entry.public_key
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
            self.verifier
                .verify(&entry.public_key, &entry.hash, &entry.sig)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            previous = entry.hash;
            if self.proof_checkpoints.contains(&entry.seq)
                || entry.kind.is_mapped_custody()
                || matches!(
                    entry.kind,
                    AuditEventKind::ReportPublishedV1
                        | AuditEventKind::SigmaRunV1
                        | AuditEventKind::SigmaCaseRunAdmissionV1
                        | AuditEventKind::SourceManifestV2
                        | AuditEventKind::SourceQueryResultV1
                        | AuditEventKind::FindingProposed
                        | AuditEventKind::FindingConfirmed
                        | AuditEventKind::FindingDismissed
                )
            {
                history.push(entry);
            }
        }
        if self
            .last
            .as_ref()
            .is_none_or(|entry| entry.hash != previous)
        {
            return Err(AppError::InvalidChain(count));
        }
        input.seek(SeekFrom::Start(resume)).map_err(storage)?;
        Ok(history)
    }

    fn accept_metadata(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        if entry.kind.is_source_query_lifecycle() {
            if entry.kind == AuditEventKind::SourceQueryResultV1 {
                let result = irmind_app::source_queries::SourceQueryResultV1::decode(
                    entry.payload.as_bytes(),
                )?;
                if !self.query_hashes.insert(result.capture_identity().0.into()) {
                    return Err(AppError::InvalidChain(entry.seq));
                }
            }
            self.metadata_entries.push(entry.clone());
            return Ok(());
        }
        match entry.kind {
            AuditEventKind::CaseCreated
            | AuditEventKind::CaseScopeChanged
            | AuditEventKind::SourceQueryBudgetV1 => {
                self.metadata_entries.push(entry.clone());
            }
            AuditEventKind::EvidenceIngested => {
                let hash = entry
                    .evidence
                    .as_deref()
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                irmind_domain::EvidenceHash::parse(hash)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                self.source_hashes.insert(hash.to_owned());
            }
            AuditEventKind::SourceManifestV2 => {
                let source = SourceManifestV2::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?
                    .source;
                if entry.evidence.is_some() || self.source_count >= MAX_SOURCE_MANIFESTS {
                    return Err(AppError::InvalidChain(entry.seq));
                }
                self.source_count += 1;
                self.source_hashes.insert(source.sha256.as_str().into());
                if self.query_hashes.contains(source.sha256.as_str()) {
                    self.metadata_entries.push(entry.clone());
                } else {
                    *self
                        .sources
                        .entry((source.sha256.as_str().into(), source.size))
                        .or_default() += 1;
                }
            }
            AuditEventKind::SourceRecordSetV1 => {
                let source = irmind_domain::SourceRecordSetV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if self.query_hashes.contains(source.source().as_str())
                    || source.reference().kind() == irmind_domain::SourceKind::ToolResult
                {
                    self.metadata_entries.push(entry.clone());
                }
            }
            AuditEventKind::ParquetArtifactV3 => self.accept_artifact(entry)?,
            _ => {}
        }
        Ok(())
    }

    fn accept_artifact(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        let artifact = irmind_domain::ParquetArtifact::decode(entry.kind, &entry.payload)
            .map_err(|_| invalid())?;
        if artifact
            .source_hashes()
            .iter()
            .any(|hash| self.query_hashes.contains(hash.as_str()))
        {
            self.metadata_entries.push(entry.clone());
        }
        if entry.evidence.is_some()
            || !self.artifact_paths.insert(artifact.path().into())
            || artifact
                .source_hashes()
                .iter()
                .any(|hash| !self.source_hashes.contains(hash.as_str()))
        {
            return Err(invalid());
        }
        self.artifacts.insert(
            artifact.path().into(),
            super::artifact_frames::ArtifactFrame::from_artifact(&artifact),
        );
        self.artifact_sources.extend(
            artifact
                .source_hashes()
                .iter()
                .map(|hash| hash.as_str().to_owned()),
        );
        Ok(())
    }

    fn verify_seal(&self, id: &CaseId, header: &HeaderV10) -> Result<(), AppError> {
        {
            self.catalog.validate()?;
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn oversized_export_is_rejected_before_parsing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("synthetic-invalid-export");
        std::fs::write(&path, b"not an export").unwrap();
        let input = File::open(&path).unwrap();
        let mut observer = input.try_clone().unwrap();
        let error = verify_open_export(input, MAX_PACKAGE_FILE_BYTES + 1, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("export package exceeds size limit")
        );
        assert_eq!(observer.stream_position().unwrap(), 0);

        // The exact limit remains inclusive: reaching the parser is observable
        // through both its distinct error and the shared file cursor.
        let input = File::open(&path).unwrap();
        let mut observer = input.try_clone().unwrap();
        assert!(matches!(
            verify_open_export(input, MAX_PACKAGE_FILE_BYTES, None),
            Err(AppError::Fixed(
                irmind_app::FixedAppError::RetiredExportFormat
            ))
        ));
        assert!(observer.stream_position().unwrap() > 0);
        assert!(super::super::verify_export(&path).is_err());
    }
}
