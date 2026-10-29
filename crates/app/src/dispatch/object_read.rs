use crate::{
    AppError, AuditEventKind, AuditOrigin, AuthorizedCall, CancellationToken, CaseId, Engine,
    LargeCaseUseCases, ObjectEntry, ObjectSourceOutput, PreparedSource,
};
use futures_util::StreamExt as _;
use irmind_domain::{EvidenceHash, SourceManifestV1, UtcTimestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
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
            require_signed_listing(&local, &id, &entries, &args, &uri, requested)?;
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
        let ObjectSourceOutput::Object { metadata, chunks } =
            self.dispatch_object_source(call, cancel).await?
        else {
            return Err(AppError::RemoteTool);
        };
        validate_metadata(call, &metadata)?;
        let progress = Arc::new(AtomicU64::new(0));
        self.object_progress
            .lock()
            .map_err(|_| AppError::Storage("object progress unavailable".into()))?
            .insert(id.clone(), (metadata.size, Arc::clone(&progress)));
        let spool = tempfile::Builder::new()
            .prefix("irmind-object-")
            .tempdir()
            .map_err(|_| AppError::RemoteTool)?;
        let path = spool.path().join("download.json");
        let mut file = tokio::fs::File::create(&path)
            .await
            .map_err(|_| AppError::RemoteTool)?;
        let hash = spool_stream(&mut file, chunks, metadata.size, &progress, cancel).await?;
        file.sync_all().await.map_err(|_| AppError::RemoteTool)?;
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
        source_root: &std::path::Path,
        manifest: SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(String, String), AppError> {
        let store = self.large_case_store.clone().ok_or(AppError::RemoteTool)?;
        let parser = self.streaming_parser.clone().ok_or(AppError::RemoteTool)?;
        let id = id.clone();
        let root = source_root.to_path_buf();
        let cancel = cancel.clone();
        self.blocking_local(move |local| {
            let mut prepared: PreparedSource = store.prepare_local(
                &id,
                &root,
                "download.json",
                manifest.copied,
                parser.as_ref(),
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
                parser: parser.as_ref(),
            };
            let hash = large.sign_prepared(&id, prepared, &cancel, &mut known)?;
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

fn require_signed_listing(
    engine: &Engine<'_>,
    id: &CaseId,
    entries: &[crate::SignedEntry],
    args: &BTreeMap<String, String>,
    uri: &str,
    max_bytes: u64,
) -> Result<(), AppError> {
    let listed = entries
        .iter()
        .rev()
        .filter(|entry| {
            entry.kind == AuditEventKind::ToolResult && entry.payload.ends_with("from object_list")
        })
        .filter_map(|entry| entry.evidence.as_deref())
        .take(20)
        .any(|hash| {
            let Ok(raw) = engine.evidence_store.get_evidence(id, hash) else {
                return false;
            };
            let Ok(listing) = serde_json::from_slice::<SignedListing>(&raw) else {
                return false;
            };
            !listing.truncated
                && args.get("source") == Some(&listing.source)
                && listing.objects.iter().any(|item| {
                    item.uri == uri
                        && item.size <= max_bytes
                        && args
                            .get("version")
                            .is_none_or(|version| item.version.as_deref() == Some(version))
                        && args.get("etag").is_none_or(|etag| {
                            item.provider_checksum.as_deref() == Some(&format!("etag:{etag}"))
                        })
                })
        });
    if listed {
        Ok(())
    } else {
        Err(AppError::Policy(
            "list the exact object and version before reading".into(),
        ))
    }
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
        file.write_all(&chunk)
            .await
            .map_err(|_| AppError::RemoteTool)?;
        progress.store(seen, Ordering::Relaxed);
    }
    if seen != expected {
        return Err(AppError::RemoteTool);
    }
    Ok(digest.finalize().into())
}
