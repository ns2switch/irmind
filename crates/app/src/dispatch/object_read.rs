use crate::{
    AppError, AuditEventKind, AuditOrigin, AuthorizedCall, CancellationToken, CaseId, Engine,
    LargeCaseUseCases, LogParser, ObjectEntry, ObjectSourceOutput, ParserSelection, PreparedSource,
};
use futures_util::StreamExt as _;
use irmind_domain::{EvidenceHash, ParserSelectionMode, SourceManifestV1, UtcTimestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::AsyncWriteExt as _;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectReservation {
    version: u8,
    tool: String,
    args: BTreeMap<String, String>,
    reserved_bytes: u64,
}

#[derive(Deserialize)]
struct SignedListing {
    source: String,
    objects: Vec<ObjectEntry>,
    truncated: bool,
}

impl Engine<'_> {
    pub fn object_transfer_progress(&self, id: &CaseId) -> Result<Option<(u64, u64)>, AppError> {
        let guard = self
            .object_progress
            .lock()
            .map_err(|_| AppError::Storage("object progress unavailable".into()))?;
        Ok(guard
            .get(id)
            .map(|(total, seen)| (seen.load(Ordering::Relaxed), *total)))
    }

    pub(crate) async fn object_reservation_payload(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
    ) -> Result<String, AppError> {
        let id = id.clone();
        let args = call.proposal_args().clone();
        let requested = call
            .arg("max_bytes")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(AppError::RemoteTool)?;
        let uri = object_uri(call)?;
        let limit = self.policy.max_object_bytes_per_case;
        self.blocking_local(move |local| {
            local.verify_ingest_checkpoint(&id, &CancellationToken::new())?;
            let entries = local.audit_log.entries(&id)?;
            crate::large_case::read_manifest_index(&entries)?;
            let _ = require_signed_listing(&local, &id, &entries, &args, &uri, requested)?;
            let used = entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.kind,
                        AuditEventKind::Allowed | AuditEventKind::ToolDispatch
                    )
                })
                .filter_map(|entry| serde_json::from_str::<ObjectReservation>(&entry.payload).ok())
                .filter(|entry| entry.version == 1 && entry.tool == "object_read")
                .try_fold(0u64, |used, entry| used.checked_add(entry.reserved_bytes))
                .ok_or_else(|| AppError::Policy("object transfer budget exceeded".into()))?;
            if used
                .checked_add(requested)
                .is_none_or(|total| total > limit)
            {
                return Err(AppError::Policy("object transfer budget exceeded".into()));
            }
            serde_json::to_string(&ObjectReservation {
                version: 1,
                tool: "object_read".into(),
                args,
                reserved_bytes: requested,
            })
            .map_err(|_| AppError::RemoteTool)
        })
        .await
    }

    pub(crate) async fn execute_object_read(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let result = self.execute_object_read_inner(id, call, cancel).await;
        if let Err(error) = &result {
            let kind = if matches!(error, AppError::Cancelled) {
                AuditEventKind::Cancelled
            } else {
                AuditEventKind::ToolError
            };
            self.audit_local(
                id,
                AuditOrigin::System,
                kind,
                "object read did not complete",
                None,
            )
            .await?;
        }
        result
    }

    async fn execute_object_read_inner(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let listed = self.signed_object_for_read(id, call).await?;
        let store = self.large_case_store.clone().ok_or(AppError::RemoteTool)?;
        let case = id.clone();
        let spool = self
            .blocking_local(move |_| store.create_object_spool(&case, listed.size))
            .await?;
        let ObjectSourceOutput::Object { metadata, chunks } =
            self.dispatch_object_source(call, cancel).await?
        else {
            return Err(AppError::RemoteTool);
        };
        validate_metadata(call, &metadata)?;
        self.validate_against_signed_listing(id, call, &metadata)
            .await?;
        let progress = Arc::new(AtomicU64::new(0));
        self.object_progress
            .lock()
            .map_err(|_| AppError::Storage("object progress unavailable".into()))?
            .insert(id.clone(), (metadata.size, Arc::clone(&progress)));
        let mut file = tokio::fs::File::from_std(
            spool
                .as_file()
                .try_clone()
                .map_err(|_| AppError::RemoteTool)?,
        );
        let hash = spool_stream(&mut file, chunks, metadata.size, &progress, cancel).await?;
        file.sync_all().await.map_err(|_| {
            AppError::Storage("cannot sync object spool in case data directory".into())
        })?;
        drop(file);
        let copy_original = call.arg("copy_original") == Some("true");
        let manifest = SourceManifestV1 {
            source: metadata.uri.clone(),
            size: metadata.size,
            modified_unix_seconds: metadata.modified_unix_seconds,
            version: metadata.version,
            provider_checksum: metadata.provider_checksum,
            sha256: EvidenceHash::parse(&crate::hex(&hash)).map_err(|_| AppError::RemoteTool)?,
            copied: copy_original,
        };
        manifest.validate().map_err(|_| AppError::RemoteTool)?;
        if let Some(verified) = self.compare_existing_object(id, &manifest).await? {
            return Ok(verified);
        }
        self.prepare_and_sign_object(id, spool.path(), manifest, cancel)
            .await
    }

    async fn signed_object_for_read(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
    ) -> Result<ObjectEntry, AppError> {
        let id = id.clone();
        let args = call.proposal_args().clone();
        let uri = object_uri(call)?;
        let max_bytes = call
            .arg("max_bytes")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(AppError::RemoteTool)?;
        self.blocking_local(move |local| {
            let entries = local.audit_log.entries(&id)?;
            require_signed_listing(&local, &id, &entries, &args, &uri, max_bytes)
        })
        .await
    }

    async fn validate_against_signed_listing(
        &self,
        id: &CaseId,
        call: &AuthorizedCall,
        actual: &ObjectEntry,
    ) -> Result<(), AppError> {
        let listed = self.signed_object_for_read(id, call).await?;
        if listed != *actual {
            return Err(AppError::RemoteTool);
        }
        Ok(())
    }

    async fn compare_existing_object(
        &self,
        id: &CaseId,
        manifest: &SourceManifestV1,
    ) -> Result<Option<(String, String)>, AppError> {
        let id = id.clone();
        let manifest = manifest.clone();
        self.blocking_local(move |local| {
            let index = crate::large_case::read_manifest_index(&local.audit_log.entries(&id)?)?;
            let Some(existing) = index
                .sources
                .iter()
                .find(|item| item.source == manifest.source)
            else {
                return Ok(None);
            };
            let same_content = existing.source == manifest.source
                && existing.size == manifest.size
                && existing.modified_unix_seconds == manifest.modified_unix_seconds
                && existing.version == manifest.version
                && existing.provider_checksum == manifest.provider_checksum
                && existing.sha256 == manifest.sha256;
            if !same_content || (manifest.copied && !existing.copied) {
                return Err(AppError::EvidenceMismatch(existing.sha256.as_str().into()));
            }
            local.audit(
                &id,
                AuditOrigin::System,
                AuditEventKind::ToolResult,
                &format!(
                    "object source verified; sha256={}",
                    existing.sha256.as_str()
                ),
                None,
            )?;
            let summary = format!(
                "Cloud original matches the signed manifest; sha256={}",
                existing.sha256.as_str()
            );
            let screened =
                local.screen_model_result(&id, summary.as_bytes(), "object_read", None)?;
            Ok(Some((screened, existing.sha256.as_str().to_owned())))
        })
        .await
    }

    async fn prepare_and_sign_object(
        &self,
        id: &CaseId,
        spool_path: &std::path::Path,
        manifest: SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let store = self.large_case_store.clone().ok_or(AppError::RemoteTool)?;
        let catalog = self.parser_catalog.clone().ok_or(AppError::RemoteTool)?;
        let id = id.clone();
        let root = spool_path
            .parent()
            .ok_or(AppError::RemoteTool)?
            .to_path_buf();
        let relative = spool_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(AppError::RemoteTool)?
            .to_owned();
        let cancel = cancel.clone();
        self.blocking_local(move |local| {
            let (parser, selection) =
                select_object_parser(&catalog, &root, &relative, &manifest.source)?;
            let mut prepared: PreparedSource = store.prepare_local(
                &id,
                &root,
                &relative,
                manifest.copied,
                parser.as_ref() as &dyn crate::StreamingEventParser,
                &cancel,
            )?;
            if prepared.manifest.sha256 != manifest.sha256
                || prepared.manifest.size != manifest.size
            {
                return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
            }
            prepared.manifest = manifest;
            let index = crate::large_case::read_manifest_index(&local.audit_log.entries(&id)?)?;
            let mut known = index
                .artifacts
                .into_iter()
                .map(|item| (item.path.clone(), item))
                .collect();
            let large = LargeCaseUseCases {
                engine: &local,
                store: store.as_ref(),
                parser: parser.as_ref() as &dyn crate::StreamingEventParser,
            };
            let hash = large.sign_prepared_with_selection(
                &id,
                prepared,
                Some(&selection),
                &cancel,
                &mut known,
            )?;
            local.audit(
                &id,
                AuditOrigin::System,
                AuditEventKind::ToolResult,
                &format!("object converted to Parquet; sha256={}", hash.as_str()),
                None,
            )?;
            let summary = format!("Object ingested and indexed; sha256={}", hash.as_str());
            let screened =
                local.screen_model_result(&id, summary.as_bytes(), "object_read", None)?;
            Ok((screened, hash.as_str().to_owned()))
        })
        .await
    }
}

fn select_object_parser(
    catalog: &crate::modules::ParserCatalog,
    root: &std::path::Path,
    relative: &str,
    source: &str,
) -> Result<(Arc<dyn LogParser>, ParserSelection), AppError> {
    let mut sample = Vec::with_capacity(64 * 1024);
    std::fs::File::open(root.join(relative))
        .map_err(|_| AppError::RemoteTool)?
        .take(64 * 1024)
        .read_to_end(&mut sample)
        .map_err(|_| AppError::RemoteTool)?;
    let selected = match catalog.detect(source, &sample) {
        crate::modules::ParserChoice::Auto(candidate) => candidate,
        crate::modules::ParserChoice::NeedsAnalyst(candidates) => {
            return Err(AppError::ParserSelection {
                source_name: source.into(),
                candidates: candidates
                    .into_iter()
                    .map(|candidate| (candidate.id.into(), candidate.confidence.value()))
                    .collect(),
            });
        }
        crate::modules::ParserChoice::Unsupported => {
            return Err(AppError::Policy(
                "cloud object format is unsupported".into(),
            ));
        }
    };
    let parser = catalog.get(selected.id)?;
    let selection = ParserSelection {
        parser_id: selected.id.into(),
        parser_version: parser.streaming_version().into(),
        confidence: selected.confidence.value(),
        mode: ParserSelectionMode::Automatic,
        timestamp_context: None,
        format_sample_sha256: crate::sha256(&sample),
    };
    Ok((parser, selection))
}

fn require_signed_listing(
    engine: &Engine<'_>,
    id: &CaseId,
    entries: &[crate::SignedEntry],
    args: &BTreeMap<String, String>,
    uri: &str,
    max_bytes: u64,
) -> Result<ObjectEntry, AppError> {
    entries
        .iter()
        .rev()
        .filter(|entry| {
            entry.kind == AuditEventKind::ToolResult && entry.payload.ends_with("from object_list")
        })
        .filter_map(|entry| entry.evidence.as_deref())
        .take(20)
        .find_map(|hash| {
            let Ok(raw) = engine.evidence_store.get_evidence(id, hash) else {
                return None;
            };
            let Ok(listing) = serde_json::from_slice::<SignedListing>(&raw) else {
                return None;
            };
            if listing.truncated || args.get("source") != Some(&listing.source) {
                return None;
            }
            listing.objects.into_iter().find(|item| {
                item.uri == uri
                    && item.size <= max_bytes
                    && args
                        .get("version")
                        .is_none_or(|version| item.version.as_deref() == Some(version))
                    && args.get("etag").is_none_or(|etag| {
                        item.provider_checksum.as_deref() == Some(&format!("etag:{etag}"))
                    })
            })
        })
        .ok_or_else(|| AppError::Policy("list the exact object and version before reading".into()))
}

fn object_uri(call: &AuthorizedCall) -> Result<String, AppError> {
    let (scheme, container, key) = (
        call.arg("scheme").ok_or(AppError::RemoteTool)?,
        call.arg("container").ok_or(AppError::RemoteTool)?,
        call.arg("key").ok_or(AppError::RemoteTool)?,
    );
    Ok(format!("{scheme}://{container}/{key}"))
}

fn validate_metadata(call: &AuthorizedCall, item: &ObjectEntry) -> Result<(), AppError> {
    let from = UtcTimestamp::parse(call.arg("from").ok_or(AppError::RemoteTool)?)
        .map_err(|_| AppError::RemoteTool)?;
    let to = UtcTimestamp::parse(call.arg("to").ok_or(AppError::RemoteTool)?)
        .map_err(|_| AppError::RemoteTool)?;
    let modified = item.modified_unix_seconds.ok_or(AppError::RemoteTool)?;
    let limit = call
        .arg("max_bytes")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(AppError::RemoteTool)?;
    if item.uri != object_uri(call)?
        || item.key != call.arg("key").unwrap_or("")
        || item.size > limit
        || !i64::try_from(modified)
            .is_ok_and(|at| at >= from.unix_seconds() && at <= to.unix_seconds())
        || call
            .arg("version")
            .is_some_and(|version| item.version.as_deref() != Some(version))
        || call
            .arg("etag")
            .is_some_and(|etag| item.provider_checksum.as_deref() != Some(&format!("etag:{etag}")))
    {
        return Err(AppError::RemoteTool);
    }
    Ok(())
}

async fn spool_stream(
    file: &mut tokio::fs::File,
    mut chunks: crate::ObjectStream,
    expected: u64,
    progress: &AtomicU64,
    cancel: &CancellationToken,
) -> Result<[u8; 32], AppError> {
    let mut digest = Sha256::new();
    let mut seen = 0u64;
    loop {
        let next = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            next = chunks.next() => next,
        };
        let Some(chunk) = next else { break };
        let chunk = chunk?;
        seen = seen
            .checked_add(chunk.len() as u64)
            .ok_or(AppError::RemoteTool)?;
        if seen > expected {
            return Err(AppError::RemoteTool);
        }
        digest.update(&chunk);
        file.write_all(&chunk).await.map_err(|_| {
            AppError::Storage("cannot write object spool in case data directory".into())
        })?;
        progress.store(seen, Ordering::Relaxed);
    }
    if seen != expected {
        return Err(AppError::RemoteTool);
    }
    Ok(digest.finalize().into())
}
