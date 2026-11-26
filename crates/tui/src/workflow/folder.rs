use crate::{WorkspaceIo, case::escape_display};
use irmind_app::{
    AppError, CancellationToken, CaseId, Engine, FixedAppError, LargeCaseUseCases,
    ParserTimeContext, SourceClusterContext, StreamingEventParser,
    ingest_outcome::{
        FileFingerprint, FileIdentity, FileReason, IngestFileOutcome, fingerprint_file,
        validate_local_reference,
    },
    modules::{ParserCatalog, ParserSelectionRequest, ResolvedParserSelection},
};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fmt::Write as _,
    io::Read as _,
    path::Path,
};

const SAMPLE_BYTES: usize = 64 * 1024;
const CHECKSUM_BYTES: u64 = 1024 * 1024;
const CHECKSUM_LINES: usize = 4096;
const RAW_BYTES: u64 = 500_000_000_000;
const DISPLAYED_FAILURES: usize = 50;

pub struct FolderImport<'a> {
    pub id: &'a CaseId,
    pub root: &'a Path,
    pub io: &'a dyn WorkspaceIo,
    pub catalog: &'a ParserCatalog,
    pub copy_original: bool,
    pub forced_parser: Option<&'a str>,
    pub default_time: Option<ParserTimeContext>,
    pub default_cluster: Option<&'a SourceClusterContext>,
    pub analyst_choices: &'a BTreeMap<String, String>,
    pub times: &'a BTreeMap<String, ParserTimeContext>,
    pub clusters: &'a BTreeMap<String, SourceClusterContext>,
    pub cancel: &'a CancellationToken,
    pub interactive: bool,
    /// On subsequent passes, only reconsider the explicitly selected members.
    pub members: Option<&'a BTreeSet<String>>,
    pub skipped: &'a BTreeSet<String>,
}

pub(crate) struct PendingFile {
    pub path: String,
    pub prompt: AppError,
}

#[derive(Default)]
pub struct FolderPass {
    pub ingested: usize,
    pub skipped: usize,
    pub failed: usize,
    pub matches: usize,
    pub mismatches: usize,
    pub warnings: usize,
    invalid_paths: usize,
    pub(crate) pending: Vec<PendingFile>,
    details: Vec<String>,
}

impl FolderPass {
    pub fn summary(&self) -> String {
        let mut result = format!(
            "Ingested {} files · {} skipped · {} failed · {} SHA-256 matches · {} SHA-256 mismatches",
            self.ingested, self.skipped, self.failed, self.matches, self.mismatches
        );
        if self.mismatches != 0 {
            result.push_str("\nWARNING: SHA-256 MISMATCH");
        }
        if self.warnings != 0 {
            let _ = write!(
                result,
                "\n{} checksum companion warning(s). Invalid, conflicting and out-of-inventory declarations establish no integrity.",
                self.warnings
            );
        }
        if self.invalid_paths != 0 {
            let _ = write!(
                result,
                "\n{} path(s) could not be represented in the signed inventory.",
                self.invalid_paths
            );
        }
        for detail in &self.details {
            result.push('\n');
            result.push_str(detail);
        }
        if self.failed > self.details.len() {
            result.push_str("\nSee /evidence and /verify for additional signed dispositions.");
        }
        result
    }

    pub(crate) fn accumulate(&mut self, pass: Self) {
        self.ingested += pass.ingested;
        self.skipped += pass.skipped;
        self.failed += pass.failed;
        self.matches += pass.matches;
        self.mismatches += pass.mismatches;
        self.warnings += pass.warnings;
        self.invalid_paths += pass.invalid_paths;
        self.details.extend(
            pass.details
                .into_iter()
                .take(DISPLAYED_FAILURES.saturating_sub(self.details.len())),
        );
    }

    fn add(&mut self, outcome: &IngestFileOutcome) {
        match outcome {
            IngestFileOutcome::Disposition {
                path,
                reason,
                identity,
            } if reason.failed() => {
                self.failed += 1;
                if self.details.len() < DISPLAYED_FAILURES {
                    let missing = if matches!(identity, FileIdentity::Complete(_)) {
                        ""
                    } else {
                        " (complete fingerprint unavailable)"
                    };
                    self.details.push(format!(
                        "Failed {}: {}{missing}",
                        escape_display(path),
                        reason.description()
                    ));
                }
            }
            IngestFileOutcome::Disposition { .. } => self.skipped += 1,
            IngestFileOutcome::Integrity {
                observed,
                declared,
                path,
                ..
            } => {
                if observed.sha256 == *declared {
                    self.matches += 1;
                } else {
                    self.mismatches += 1;
                    if self.details.len() < DISPLAYED_FAILURES {
                        self.details
                            .push(format!("SHA-256 MISMATCH: {}", escape_display(path)));
                    }
                }
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "Read-only inventory and planning precede the commit and accounting phases."
)]
pub fn import_folder(
    engine: &Engine<'_>,
    req: &FolderImport<'_>,
    mut progress: impl FnMut(usize, usize, &str, &str),
) -> Result<FolderPass, AppError> {
    let (inventory, invalid_paths) = inventory(req)?;
    let store = req
        .io
        .large_case_store()
        .ok_or_else(|| AppError::Policy("signed Parquet ingestion is unavailable".into()))?;
    let entries = engine.audit_log.entries(req.id)?;
    let first_seq = entries.last().map_or(0, |entry| entry.seq);
    let known = manifests(&entries)?;
    let mut plan = Vec::new();
    let mut outcomes = Vec::new();
    let mut result = FolderPass {
        invalid_paths,
        ..FolderPass::default()
    };
    let mut checksums = BTreeMap::new();

    for source in &inventory {
        cancelled(req.cancel)?;
        if req.skipped.contains(source) {
            outcomes.push(disposition(req, source, FileReason::AnalystSkipped)?);
            continue;
        }
        if let Some(manifest) = known.get(source) {
            match store.verify_local_source(req.root, manifest, req.cancel) {
                Ok(()) => {}
                Err(AppError::EvidenceMismatch(_)) => {
                    outcomes.push(disposition(req, source, FileReason::SourceChanged)?);
                }
                Err(AppError::Storage(_) | AppError::Fixed(FixedAppError::AdapterStorage(_))) => {
                    outcomes.push(disposition(req, source, FileReason::Unavailable)?);
                }
                Err(error) => return Err(error),
            }
            continue;
        }
        let Ok(sample) = req
            .io
            .open_folder_member(req.root, Path::new(source))
            .and_then(|file| {
                let mut bytes = Vec::new();
                file.take(SAMPLE_BYTES as u64).read_to_end(&mut bytes)?;
                Ok(bytes)
            })
        else {
            outcomes.push(disposition(req, source, FileReason::Unavailable)?);
            continue;
        };
        if let Some(reason) = companion_reason(source, &sample) {
            if reason == FileReason::ChecksumCompanion && is_sha256(source) {
                match checksum_companion(req, source)? {
                    Some((identity, bytes)) => {
                        collect_declarations(
                            source,
                            identity,
                            &bytes,
                            &inventory,
                            &mut checksums,
                            &mut result.warnings,
                        );
                        outcomes.push(IngestFileOutcome::Disposition {
                            path: source.clone(),
                            identity: FileIdentity::Complete(identity),
                            reason,
                        });
                        continue;
                    }
                    None => result.warnings += 1,
                }
            }
            outcomes.push(disposition(req, source, reason)?);
            continue;
        }
        let choice = req.catalog.select_source(ParserSelectionRequest {
            source,
            sample: &sample,
            parser_override: req
                .forced_parser
                .or_else(|| req.analyst_choices.get(source).map(String::as_str)),
            forced: req.forced_parser.is_some(),
            time_context: req.times.get(source).copied().or(req.default_time),
            cluster_context: req.clusters.get(source).or(req.default_cluster),
        });
        match choice {
            Ok(selection) if req.catalog.can_ingest(&selection.selection.parser_id) => {
                plan.push((source.clone(), selection));
            }
            Ok(_) => outcomes.push(disposition(req, source, FileReason::PipelineUnavailable)?),
            Err(AppError::NonEventSource { .. }) => {
                outcomes.push(disposition(req, source, FileReason::IntegrityDigest)?);
            }
            Err(AppError::ParserUnavailable { .. }) => {
                outcomes.push(disposition(req, source, FileReason::PipelineUnavailable)?);
            }
            Err(
                error @ (AppError::ParserSelection { .. }
                | AppError::ParserTimeContextRequired { .. }
                | AppError::ParserClusterContextRequired { .. }
                | AppError::UnsupportedCompressedSource { .. }),
            ) => {
                if req.interactive {
                    result.pending.push(PendingFile {
                        path: source.clone(),
                        prompt: error,
                    });
                } else {
                    outcomes.push(disposition(req, source, FileReason::NoParserSelected)?);
                }
            }
            Err(AppError::SourceFailure(failure)) => {
                outcomes.push(disposition(req, source, failure_reason(failure.reason())?)?);
            }
            Err(error) => return Err(error),
        }
    }
    commit_plan(
        engine,
        req,
        store,
        &plan,
        &mut result,
        &mut outcomes,
        &mut progress,
        inventory.len(),
    )?;
    let entries = engine.audit_log.entries(req.id)?;
    for entry in entries.iter().filter(|entry| entry.seq > first_seq) {
        if let Some(rejected) = irmind_app::RejectedSource::from_audit(entry)? {
            outcomes.push(disposition(
                req,
                rejected.source(),
                failure_reason(rejected.reason())?,
            )?);
        }
    }
    compare_checksums(
        req,
        &entries,
        checksums,
        &mut outcomes,
        &mut result.warnings,
    )?;
    engine.record_ingest_outcomes(req.id, &outcomes, req.cancel)?;
    for outcome in &outcomes {
        result.add(outcome);
    }
    Ok(result)
}

fn compare_checksums(
    req: &FolderImport<'_>,
    entries: &[irmind_app::SignedEntry],
    checksums: BTreeMap<String, Option<Declaration>>,
    outcomes: &mut Vec<IngestFileOutcome>,
    warnings: &mut usize,
) -> Result<(), AppError> {
    let signed = manifests(entries)?;
    for (target, checksum) in checksums {
        let Some(checksum) = checksum else { continue };
        let identity = if let Some(manifest) = signed.get(&target) {
            let hash = parse_digest(manifest.sha256.as_str()).ok_or(AppError::InvalidChain(
                entries.last().map_or(0, |entry| entry.seq),
            ))?;
            FileIdentity::Complete(FileFingerprint {
                size: manifest.size,
                sha256: hash,
            })
        } else {
            read_identity(req, &target)?
        };
        if let FileIdentity::Complete(observed) = identity {
            outcomes.push(IngestFileOutcome::Integrity {
                path: target,
                observed,
                companion: checksum.companion,
                companion_identity: checksum.identity,
                declared: checksum.digest,
            });
        } else {
            *warnings += 1;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "Folder-wide accounting and progress stay with the caller."
)]
#[allow(
    clippy::too_many_lines,
    reason = "Keep the bounded group retry and its accounting together."
)]
fn commit_plan(
    engine: &Engine<'_>,
    req: &FolderImport<'_>,
    store: &dyn irmind_app::LargeCaseStore,
    plan: &[(String, ResolvedParserSelection)],
    result: &mut FolderPass,
    outcomes: &mut Vec<IngestFileOutcome>,
    progress: &mut impl FnMut(usize, usize, &str, &str),
    total: usize,
) -> Result<(), AppError> {
    let mut remaining = plan;
    while let Some((_, first)) = remaining.first() {
        cancelled(req.cancel)?;
        let end = remaining
            .iter()
            .take_while(|(_, resolved)| {
                let selection = &resolved.selection;
                selection.parser_id == first.selection.parser_id
                    && selection.parser_version == first.selection.parser_version
                    && selection.timestamp_context == first.selection.timestamp_context
                    && selection.cluster_context == first.selection.cluster_context
            })
            .count();
        let (group, rest) = remaining.split_at(end);
        remaining = rest;
        let mut sources = group
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>();
        let selections = group
            .iter()
            .map(|(path, resolved)| (path.clone(), resolved.selection.clone()))
            .collect();
        let ingest = LargeCaseUseCases {
            engine,
            store,
            parser: first.parser.as_ref() as &dyn StreamingEventParser,
        };
        while !sources.is_empty() {
            cancelled(req.cancel)?;
            let start = engine
                .audit_log
                .last_entry(req.id)?
                .map_or(0, |entry| entry.seq);
            match ingest.ingest_local_batch_selected(
                req.id,
                req.root,
                &sources,
                req.copy_original,
                &selections,
                req.cancel,
            ) {
                Ok(rows) => {
                    for (path, hash) in rows {
                        result.ingested += 1;
                        progress(result.ingested, total, &path, hash.as_str());
                    }
                    break;
                }
                Err(
                    AppError::Fixed(FixedAppError::PolicyMappedSourceDecoderUnavailable)
                    | AppError::ParserUnavailable { .. },
                ) => {
                    for path in sources {
                        outcomes.push(disposition(req, &path, FileReason::PipelineUnavailable)?);
                    }
                    break;
                }
                Err(AppError::Fixed(FixedAppError::PolicyMappedSourceAlreadyIndexed)) => {
                    for path in &sources {
                        match ingest.ingest_local_batch_selected(
                            req.id,
                            req.root,
                            std::slice::from_ref(path),
                            req.copy_original,
                            &selections,
                            req.cancel,
                        ) {
                            Ok(rows) => {
                                for (path, hash) in rows {
                                    result.ingested += 1;
                                    progress(result.ingested, total, &path, hash.as_str());
                                }
                            }
                            Err(AppError::Fixed(
                                FixedAppError::PolicyMappedSourceAlreadyIndexed,
                            )) => {
                                outcomes.push(disposition(
                                    req,
                                    path,
                                    FileReason::PipelineUnavailable,
                                )?);
                                if result.details.len() < DISPLAYED_FAILURES {
                                    result.details.push(format!(
                                        "{}: these bytes already have a mapped generation in the case",
                                        escape_display(path)
                                    ));
                                }
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    break;
                }
                Err(AppError::SourceGroupExclusionLimit(_)) => {
                    let entries = engine.audit_log.entries(req.id)?;
                    let since = entries
                        .iter()
                        .position(|entry| entry.seq > start)
                        .unwrap_or(entries.len());
                    let mut finished = BTreeSet::new();
                    for entry in &entries[since..] {
                        if let Some(source) = irmind_app::RejectedSource::from_audit(entry)? {
                            finished.insert(source.source().to_owned());
                        }
                    }
                    let accepted = manifests(&entries[since..])?;
                    result.ingested += accepted.len();
                    finished.extend(accepted.into_keys());
                    let previous = sources.len();
                    sources.retain(|path| !finished.contains(path));
                    if sources.len() == previous {
                        return Err(AppError::InvalidChain(start));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn inventory(req: &FolderImport<'_>) -> Result<(BTreeSet<String>, usize), AppError> {
    if let Some(members) = req.members {
        for path in members {
            validate_local_reference(path)?;
        }
        return Ok((members.clone(), 0));
    }
    let files = req.io.input_files(req.root).map_err(|_| {
        AppError::Fixed(FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::CannotListSelectedEvidence,
        ))
    })?;
    let mut valid = BTreeSet::new();
    let mut invalid = 0;
    for file in files {
        match req.io.audit_source_name(req.root, &file) {
            Ok(name) if validate_local_reference(&name).is_ok() => {
                valid.insert(name);
            }
            _ => invalid += 1,
        }
    }
    Ok((valid, invalid))
}

fn manifests(
    entries: &[irmind_app::SignedEntry],
) -> Result<BTreeMap<String, irmind_app::SourceManifestV1>, AppError> {
    let mut result = BTreeMap::new();
    for entry in entries {
        if let Some(source) =
            irmind_app::SourceManifestV1::decode_signed(entry.kind, &entry.payload)
                .map_err(|_| AppError::InvalidChain(entry.seq))?
        {
            result.insert(source.source.clone(), source);
        }
    }
    Ok(result)
}

fn cancelled(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    Ok(())
}

fn failure_reason(reason: irmind_app::SourceFailureReason) -> Result<FileReason, AppError> {
    match reason {
        irmind_app::SourceFailureReason::Format => Ok(FileReason::InvalidFormat),
        irmind_app::SourceFailureReason::Limit => Ok(FileReason::SourceLimit),
        irmind_app::SourceFailureReason::Hash => Ok(FileReason::SourceChanged),
        irmind_app::SourceFailureReason::Cancelled => Err(AppError::Cancelled),
    }
}

fn read_identity(req: &FolderImport<'_>, path: &str) -> Result<FileIdentity, AppError> {
    cancelled(req.cancel)?;
    let Ok(mut file) = req.io.open_folder_member(req.root, Path::new(path)) else {
        return Ok(FileIdentity::Unavailable);
    };
    let size = file.metadata().map(|metadata| metadata.len()).ok();
    match fingerprint_file(&mut file, RAW_BYTES, SAMPLE_BYTES, req.cancel) {
        Ok(known) => Ok(FileIdentity::Complete(known)),
        Err(AppError::Cancelled) => Err(AppError::Cancelled),
        Err(_) => Ok(size.map_or(FileIdentity::Unavailable, FileIdentity::SizeOnly)),
    }
}

fn disposition(
    req: &FolderImport<'_>,
    path: &str,
    mut reason: FileReason,
) -> Result<IngestFileOutcome, AppError> {
    let identity = read_identity(req, path)?;
    if !matches!(identity, FileIdentity::Complete(_)) && (reason as u8) < 8 {
        reason = FileReason::Unavailable;
    }
    Ok(IngestFileOutcome::Disposition {
        path: path.into(),
        identity,
        reason,
    })
}

fn is_sha256(path: &str) -> bool {
    let name = path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".sha256") || name == "sha256sums"
}

fn companion_reason(path: &str, sample: &[u8]) -> Option<FileReason> {
    let name = path.rsplit('/').next()?.to_ascii_lowercase();
    if is_sha256(path)
        || [".sha1", ".md5"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
    {
        return Some(FileReason::ChecksumCompanion);
    }
    if [".sig", ".asc"].iter().any(|suffix| name.ends_with(suffix)) {
        return Some(FileReason::SignatureCompanion);
    }
    let text = std::str::from_utf8(sample)
        .ok()?
        .trim_start_matches('\u{feff}');
    let lines = text.lines().take(128).collect::<Vec<_>>();
    let kape = name.ends_with("_consolelog.txt")
        && lines
            .iter()
            .filter_map(|line| kape_info(line))
            .any(|message| {
                message.starts_with("KAPE version ") && message.contains(" Author: Eric Zimmerman")
            })
        && lines
            .iter()
            .filter_map(|line| kape_info(line))
            .any(|message| message.starts_with("Command line: "));

    let velo = name.starts_with("collection-")
        && extension_is(&name, "log")
        && lines.iter().any(|line| {
            velo_info(line).is_some_and(|message| message == "Starting collection of Collector")
        })
        && lines.iter().any(|line| {
            velo_info(line).is_some_and(|message| {
                message.starts_with("Will create container at ") && extension_is(message, "zip")
            })
        });
    let ez = [
        "_evtxecmd_",
        "_mftecmd_",
        "_pecmd_",
        "_lecmd_",
        "_amcacheparser_",
        "_appcompatcacheparser_",
        "_recmd_",
        "_srumecmd_",
    ]
    .iter()
    .any(|tool| name.contains(tool))
        && name.ends_with("_consolelog.txt")
        && lines
            .iter()
            .any(|line| line.contains("Author: Eric Zimmerman"))
        && lines.iter().any(|line| line.starts_with("Command line:"));
    (kape || velo || ez).then_some(FileReason::CollectorLog)
}

fn extension_is(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

fn kape_info(line: &str) -> Option<&str> {
    let (timestamp, message) = line.split_once(" | I | ")?;
    (timestamp.len() >= 19
        && timestamp.as_bytes().get(4) == Some(&b'-')
        && timestamp.as_bytes().get(10) == Some(&b' ')
        && timestamp.as_bytes().get(13) == Some(&b':'))
    .then_some(message)
}

fn velo_info(line: &str) -> Option<&str> {
    let (timestamp, message) = line.strip_prefix("[INFO] ")?.split_once(' ')?;
    (timestamp.len() >= 20
        && timestamp.as_bytes().get(10) == Some(&b'T')
        && timestamp.as_bytes().get(4) == Some(&b'-'))
    .then_some(message)
}

struct Declaration {
    companion: String,
    identity: FileFingerprint,
    digest: [u8; 32],
}

fn checksum_companion(
    req: &FolderImport<'_>,
    source: &str,
) -> Result<Option<(FileFingerprint, Vec<u8>)>, AppError> {
    cancelled(req.cancel)?;
    let Ok(file) = req.io.open_folder_member(req.root, Path::new(source)) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    if file
        .take(CHECKSUM_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > CHECKSUM_BYTES
    {
        return Ok(None);
    }
    cancelled(req.cancel)?;
    let identity = FileFingerprint {
        size: bytes.len() as u64,
        sha256: irmind_app::sha256(&bytes),
    };
    Ok(Some((identity, bytes)))
}

fn collect_declarations(
    companion: &str,
    identity: FileFingerprint,
    bytes: &[u8],
    inventory: &BTreeSet<String>,
    declarations: &mut BTreeMap<String, Option<Declaration>>,
    warnings: &mut usize,
) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        *warnings += 1;
        return;
    };
    let mut lines = text.lines().filter(|line| !line.is_empty());
    if text.lines().take(CHECKSUM_LINES + 1).count() > CHECKSUM_LINES {
        *warnings += 1;
        return;
    }
    let first = lines.next();
    let bare = lines.clone().next().is_none();
    for line in first.into_iter().chain(lines) {
        let Some((target, digest)) = checksum_line(companion, line, bare) else {
            *warnings += 1;
            continue;
        };
        if target == companion || !inventory.contains(&target) {
            *warnings += 1;
            continue;
        }
        match declarations.entry(target) {
            Entry::Vacant(slot) => {
                slot.insert(Some(Declaration {
                    companion: companion.into(),
                    identity,
                    digest,
                }));
            }
            Entry::Occupied(mut slot) => {
                if slot
                    .get()
                    .as_ref()
                    .is_some_and(|prior| prior.digest != digest)
                {
                    slot.insert(None);
                    *warnings += 1;
                }
            }
        }
    }
}

fn checksum_line(companion: &str, line: &str, allow_bare: bool) -> Option<(String, [u8; 32])> {
    let (hex, remainder) = line.split_at_checked(64)?;
    let digest = parse_digest(hex)?;
    let (parent, name) = companion.rsplit_once('/').unwrap_or(("", companion));
    let path =
        if remainder.is_empty() && allow_bare && name.to_ascii_lowercase().ends_with(".sha256") {
            name.get(..name.len().checked_sub(".sha256".len())?)?
        } else {
            remainder
                .strip_prefix("  ")
                .or_else(|| remainder.strip_prefix(" *"))?
        };
    validate_local_reference(path).ok()?;
    let target = if parent.is_empty() {
        path.into()
    } else {
        format!("{parent}/{path}")
    };
    validate_local_reference(&target).ok()?;
    Some((target, digest))
}

fn parse_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn sha256_paths_are_safe_and_conflicts_are_sticky() {
        let h = "a".repeat(64);
        for bad in [
            "../outside",
            "/etc/passwd",
            "C:/evil",
            "sub\\x",
            "./event",
            "sub//event",
        ] {
            assert!(
                checksum_line("tree/SHA256SUMS", &format!("{h}  {bad}"), false).is_none(),
                "{bad}"
            );
        }
        let inventory = BTreeSet::from(["tree/registro-ñ.jsonl".to_owned()]);
        let data = format!(
            "{h}  registro-ñ.jsonl\n{} *registro-ñ.jsonl\n{h}  registro-ñ.jsonl\n",
            "b".repeat(64)
        );
        let mut declarations = BTreeMap::new();
        let mut warnings = 0;
        collect_declarations(
            "tree/SHA256SUMS",
            FileFingerprint {
                size: 0,
                sha256: [0; 32],
            },
            data.as_bytes(),
            &inventory,
            &mut declarations,
            &mut warnings,
        );
        assert_eq!(warnings, 1);
        assert!(declarations["tree/registro-ñ.jsonl"].is_none());
        assert_eq!(
            checksum_line("tree/registro-ñ.jsonl.SHA256", &h, true)
                .unwrap()
                .0,
            "tree/registro-ñ.jsonl"
        );
    }
    #[test]
    fn collector_name_and_signature_are_both_required() {
        for (path, text) in [
            (
                "2026_ConsoleLog.txt",
                "2026-11-26 00:00:00.0000 | I | KAPE version 1.3 Author: Eric Zimmerman\n2026-11-26 00:00:00.0001 | I | Command line: fixture",
            ),
            (
                "Collection-endpoint.log",
                "[INFO] 2026-11-26T00:00:00Z Starting collection of Collector\n[INFO] 2026-11-26T00:00:00Z Will create container at Collection-endpoint.zip",
            ),
            (
                "2026_EvtxECmd_1_ConsoleLog.txt",
                "Author: Eric Zimmerman\nCommand line: fixture",
            ),
        ] {
            assert_eq!(
                companion_reason(path, text.as_bytes()),
                Some(FileReason::CollectorLog)
            );
            assert_eq!(companion_reason("generic.log", text.as_bytes()), None);
            assert_eq!(companion_reason(path, b"unrelated\n"), None);
        }
    }
}
