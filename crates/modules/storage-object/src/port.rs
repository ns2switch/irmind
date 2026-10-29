use super::{AppError, StorageObject};
use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use irmind_app::{
    CancellationToken, ObjectEntry, ObjectSource, ObjectSourceOutput, ObjectStream, async_trait,
};
use irmind_domain::{AuthorizedCall, EvidenceHash, SourceManifestV1, Tool, UtcTimestamp};
use object_store::{GetOptions, ObjectMeta, path::Path};
use std::time::{Duration, Instant};

const MAX_LIST: usize = 1_000;
const MAX_SCAN: usize = 10_000;
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

fn invalid_request() -> AppError {
    AppError::Policy("object storage request is invalid".into())
}

fn remote_error() -> AppError {
    AppError::Policy("object storage request failed".into())
}

fn valid_object_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 900
        && !key.contains(['?', '#', '\\', '@', '\0'])
        && !key.starts_with('/')
        && key
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
}

fn valid_object_prefix(prefix: &str) -> bool {
    valid_object_key(prefix.trim_end_matches('/')) && !prefix.ends_with("//")
}

impl StorageObject {
    fn entry(&self, meta: ObjectMeta) -> Result<ObjectEntry, AppError> {
        let key = meta.location.to_string();
        if !valid_object_key(&key) {
            return Err(invalid_request());
        }
        let uri = format!("{}://{}/{}", self.scheme, self.container, key);
        let provider_checksum = meta.e_tag.map(|tag| format!("etag:{tag}"));
        let entry = ObjectEntry {
            uri: uri.clone(),
            key,
            size: meta.size,
            modified_unix_seconds: u64::try_from(meta.last_modified.timestamp()).ok(),
            version: meta.version,
            provider_checksum: provider_checksum.clone(),
        };
        let check = SourceManifestV1 {
            source: uri,
            size: entry.size,
            modified_unix_seconds: entry.modified_unix_seconds,
            version: entry.version.clone(),
            provider_checksum,
            sha256: EvidenceHash::parse(&"0".repeat(64)).map_err(|_| invalid_request())?,
            copied: false,
        };
        check.validate().map_err(|_| invalid_request())?;
        Ok(entry)
    }

    async fn list(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        let prefix = call.arg("prefix").ok_or_else(invalid_request)?;
        let from = UtcTimestamp::parse(call.arg("from").ok_or_else(invalid_request)?)
            .map_err(|_| invalid_request())?;
        let to = UtcTimestamp::parse(call.arg("to").ok_or_else(invalid_request)?)
            .map_err(|_| invalid_request())?;
        let limit = call
            .arg("limit")
            .ok_or_else(invalid_request)?
            .parse::<usize>()
            .map_err(|_| invalid_request())?;
        if !valid_object_prefix(prefix) || limit == 0 || limit > MAX_LIST || from > to {
            return Err(invalid_request());
        }
        let prefix_path = Path::parse(prefix).map_err(|_| invalid_request())?;
        let mut listing = self.store.list(Some(&prefix_path));
        let mut objects = Vec::new();
        let mut total_bytes = 0u64;
        let deadline = Instant::now() + Duration::from_mins(1);
        let mut scanned = 0usize;
        while let Some(meta) = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            () = tokio::time::sleep_until(deadline.into()) => return Err(remote_error()),
            next = listing.try_next() => next.map_err(|_| remote_error())?,
        } {
            scanned += 1;
            if scanned > MAX_SCAN {
                return Ok(ObjectSourceOutput::Listing {
                    objects,
                    total_bytes,
                    truncated: true,
                });
            }
            if meta.last_modified.timestamp() < from.unix_seconds()
                || meta.last_modified.timestamp() > to.unix_seconds()
            {
                continue;
            }
            if objects.len() == limit {
                return Ok(ObjectSourceOutput::Listing {
                    objects,
                    total_bytes,
                    truncated: true,
                });
            }
            total_bytes = total_bytes
                .checked_add(meta.size)
                .ok_or_else(invalid_request)?;
            objects.push(self.entry(meta)?);
        }
        Ok(ObjectSourceOutput::Listing {
            objects,
            total_bytes,
            truncated: false,
        })
    }

    async fn read(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        let key = call.arg("key").ok_or_else(invalid_request)?;
        let version = call.arg("version");
        let etag = call.arg("etag");
        let max_bytes = call
            .arg("max_bytes")
            .ok_or_else(invalid_request)?
            .parse::<u64>()
            .map_err(|_| invalid_request())?;
        if !valid_object_key(key)
            || max_bytes == 0
            || max_bytes > MAX_OBJECT_BYTES
            || (version.is_none() && etag.is_none())
        {
            return Err(invalid_request());
        }
        let path = Path::parse(key).map_err(|_| invalid_request())?;
        let options = GetOptions {
            version: version.map(str::to_owned),
            if_match: etag.map(str::to_owned),
            ..GetOptions::default()
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::Cancelled),
            response = self.store.get_opts(&path, options) => response.map_err(|_| remote_error())?,
        };
        if result.meta.size > max_bytes
            || version.is_some_and(|expected| result.meta.version.as_deref() != Some(expected))
            || etag.is_some_and(|expected| result.meta.e_tag.as_deref() != Some(expected))
        {
            return Err(invalid_request());
        }
        let expected_size = result.meta.size;
        let metadata = self.entry(result.meta.clone())?;
        let chunks: ObjectStream = stream::try_unfold(
            (result.into_stream(), 0u64, cancel.clone()),
            move |(mut incoming, seen, cancel)| async move {
                let next = tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Err(AppError::Cancelled),
                    next = incoming.next() => next,
                };
                match next {
                    Some(Ok(chunk)) => {
                        let new_seen = seen
                            .checked_add(chunk.len() as u64)
                            .ok_or_else(invalid_request)?;
                        if new_seen > max_bytes || new_seen > expected_size {
                            return Err(invalid_request());
                        }
                        Ok(Some((chunk.to_vec(), (incoming, new_seen, cancel))))
                    }
                    None if seen == expected_size => Ok(None),
                    Some(Err(_)) | None => Err(remote_error()),
                }
            },
        )
        .boxed();
        Ok(ObjectSourceOutput::Object { metadata, chunks })
    }
}

#[async_trait]
impl ObjectSource for StorageObject {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        if call.arg("source") != Some(self.source_id())
            || call.arg("container") != Some(self.container.as_str())
        {
            return Err(invalid_request());
        }
        match call.tool() {
            Tool::ObjectList => self.list(call, cancel).await,
            Tool::ObjectRead => self.read(call, cancel).await,
            _ => Err(invalid_request()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_prefix_preserves_directory_boundary() {
        assert!(valid_object_prefix("AWSLogs/123/CloudTrail/"));
        assert!(valid_object_prefix("AWSLogs/123/CloudTrail"));
        assert!(!valid_object_prefix("AWSLogs/123//CloudTrail"));
        assert!(!valid_object_prefix("../AWSLogs"));
        let path = Path::parse("AWSLogs/123/CloudTrail/").ok();
        assert_eq!(
            path.map(|value| value.to_string()).as_deref(),
            Some("AWSLogs/123/CloudTrail")
        );
    }
}
