use super::{
    AppError, ArtifactMigrationRequest, BTreeMap, BTreeSet, CancellationToken, GraphRecord,
    ParquetArtifact, ParquetStore, PathBuf, SourceManifestV1, StreamingEventParser, invalid_source,
    parse_hash, storage,
};
use std::io::{Read as _, Seek as _, SeekFrom};

pub(super) struct Input {
    pub(super) manifest: SourceManifestV1,
    pub(super) root: PathBuf,
    pub(super) relative: String,
    pub(super) parser_id: String,
    pub(super) parser_version: String,
}

pub(super) fn resolve(
    store: &ParquetStore,
    request: &ArtifactMigrationRequest<'_>,
    old: &[ParquetArtifact],
    cancel: &CancellationToken,
) -> Result<Vec<Input>, AppError> {
    let mut manifests = BTreeMap::new();
    for entry in request.signed_entries {
        if let Some(source) = SourceManifestV1::decode_signed(entry.kind, &entry.payload)
            .map_err(|_| invalid_source())?
        {
            manifests.entry(source.sha256.clone()).or_insert(source);
        }
    }
    let hashes = old
        .iter()
        .flat_map(|a| a.source_hashes().iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut result = Vec::new();
    for hash in hashes {
        let source = manifests.remove(&hash).unwrap_or(SourceManifestV1 {
            source: format!("legacy/{}.json", hash.as_str()),
            size: 0,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: hash,
            copied: true,
        });
        let input = resolve_one(store, request, source, cancel)?;
        result.push(input);
    }
    result.sort_by(|a, b| a.manifest.source.cmp(&b.manifest.source));
    Ok(result)
}

fn resolve_one(
    store: &ParquetStore,
    request: &ArtifactMigrationRequest<'_>,
    mut manifest: SourceManifestV1,
    cancel: &CancellationToken,
) -> Result<Input, AppError> {
    let case = store.case_dir(request.case_id)?;
    let mut candidates = vec![(case.join("originals"), manifest.sha256.as_str().into())];
    if manifest.source.starts_with("legacy/") && manifest.size == 0 {
        candidates.push((
            store
                .root
                .parent()
                .ok_or_else(invalid_source)?
                .join("evidence"),
            manifest.sha256.as_str().into(),
        ));
    }
    if let Some(root) = request.source_root {
        candidates.push((root.to_owned(), manifest.source.clone()));
        candidates.push((root.to_owned(), manifest.sha256.as_str().into()));
    }
    let identity = request.parser.identity_for_source(&manifest.source)?;
    let expected = original_choice(request, &manifest)?;
    if identity.name != expected.0 || identity.version != expected.1 {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyArtifactMigrationParser,
        ));
    }
    for (root, relative) in candidates {
        let Ok(mut file) = ParquetStore::open_source(&root, &relative) else {
            continue;
        };
        let (hash, size) = ParquetStore::hash_reader(&mut file, cancel)?;
        if hash != parse_hash(&manifest.sha256)? || (manifest.size != 0 && manifest.size != size) {
            return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
        }
        manifest.size = size;
        file.seek(SeekFrom::Start(0)).map_err(storage)?;
        return Ok(Input {
            manifest,
            root,
            relative,
            parser_id: identity.name.into(),
            parser_version: identity.version.into(),
        });
    }
    Err(AppError::Storage("migration requires an available verified original; retain a copy or provide its source directory".into()))
}

#[derive(PartialEq)]
struct Meaning {
    record: GraphRecord,
    account: String,
    region: String,
}

pub(super) fn equivalent(
    input: &Input,
    parser: &dyn StreamingEventParser,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    use std::sync::mpsc::sync_channel;
    let (a, ar) = sync_channel(1);
    let (b, br) = sync_channel(1);
    std::thread::scope(|scope| {
        let first = scope.spawn(move || records(input, parser, false, cancel, &a));
        let second = scope.spawn(move || records(input, parser, true, cancel, &b));
        let result = compare(&ar, &br, cancel);
        drop(ar);
        drop(br);
        let left = first.join().map_err(|_| invalid_source())?;
        let right = second.join().map_err(|_| invalid_source())?;
        result?;
        let a = left?;
        let b = right?;
        if a.accepted != b.accepted || a.rejected != b.rejected || a.samples != b.samples {
            return Err(AppError::Fixed(
                irmind_app::FixedAppError::PolicyArtifactMigrationMeaning,
            ));
        }
        Ok(())
    })
}

fn compare(
    left: &std::sync::mpsc::Receiver<Meaning>,
    right: &std::sync::mpsc::Receiver<Meaning>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        match (left.recv().ok(), right.recv().ok()) {
            (None, None) => return Ok(()),
            (Some(a), Some(b)) if a == b => {}
            _ => {
                return Err(AppError::Fixed(
                    irmind_app::FixedAppError::PolicyArtifactMigrationMeaning,
                ));
            }
        }
    }
}

fn records(
    input: &Input,
    parser: &dyn StreamingEventParser,
    precise: bool,
    cancel: &CancellationToken,
    sender: &std::sync::mpsc::SyncSender<Meaning>,
) -> Result<irmind_app::ParseReport, AppError> {
    let mut file = ParquetStore::open_source(&input.root, &input.relative)?;
    let mut sample = Vec::new();
    (&mut file)
        .take(64 * 1024)
        .read_to_end(&mut sample)
        .map_err(storage)?;
    super::super::local::stream::parse_and_verify(
        super::super::local::stream::VerifiedInput {
            source: &mut file,
            sample: &sample,
            relative_path: &input.manifest.source,
            parser,
            hash: parse_hash(&input.manifest.sha256)?,
            hash_value: &input.manifest.sha256,
            size: input.manifest.size,
            cancel,
            precise_time: precise,
            decode_budget: irmind_app::source_mapping::DecodeBudget::sequential(),
        },
        &mut |row| {
            let mut value = None;
            row.inspect(|r| {
                let converted = if precise {
                    super::super::writer::RecordRow::from_partitioned(r, &input.manifest.sha256)
                } else {
                    super::super::writer::RecordRow::from_record(&r.record, &input.manifest.sha256)
                };
                value = Some(converted.map(|c| Meaning {
                    record: r.record.clone(),
                    account: c.scope_account,
                    region: c.scope_region,
                }));
            });
            sender
                .send(value.ok_or_else(invalid_source)??)
                .map_err(|_| AppError::Cancelled)
        },
    )
}

fn original_choice(
    request: &ArtifactMigrationRequest<'_>,
    manifest: &SourceManifestV1,
) -> Result<(String, String), AppError> {
    for entry in request.signed_entries {
        if entry.kind != irmind_domain::AuditEventKind::SourceManifestV2 {
            continue;
        }
        let signed = irmind_domain::SourceManifestV2::decode(&entry.payload)
            .map_err(|_| invalid_source())?;
        if signed.source.source == manifest.source && signed.source.sha256 == manifest.sha256 {
            return Ok((signed.parser_id, signed.parser_version));
        }
    }
    Ok(("parser-json".into(), "json-stream-v2".into()))
}
