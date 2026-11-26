//! Explicit analyst management of an immutable Sigma package preview.
use irmind_app::{
    AppError, CancellationToken, Engine,
    catalog::{
        CATALOG_REPOSITORY, CatalogError, CatalogReleaseMetadata, SigmaCatalogIndex,
        SigmaCatalogSource,
    },
    v10_proofs::SigmaPackageOriginV1,
};
use irmind_infra::{
    Ed25519CatalogIndexVerifier, LocalStore,
    sigma_pack::{
        CatalogSigmaInstallApproval, LocalSigmaPack, SigmaPackageBundle,
        inspect_sigma_catalog_asset, inspect_sigma_package_bundle,
        inspect_sigmahq_catalog_reference,
    },
};
use irmind_tui::SigmaPackagePreview;
use std::{collections::BTreeMap, io::Read as _, path::Path};

const LIMIT: usize = 2 * 64 * 1024 * 1024 + 8192 + 64;

pub(super) fn preview(
    store: &LocalStore,
    engine: &Engine<'_>,
    source: &str,
    update: Option<&str>,
    cancel: &CancellationToken,
) -> Result<SigmaPackagePreview, AppError> {
    let history = engine.sigma_installations()?;
    let mut inferred_source = String::new();
    let source = if source.is_empty() {
        let name = update.ok_or_else(usage)?;
        let (receipt, _) = history.get(name).ok_or_else(usage)?;
        if matches!(receipt.origin, SigmaPackageOriginV1::Local) {
            return Err(usage());
        }
        inferred_source.push_str("catalog:");
        inferred_source.push_str(name);
        &inferred_source
    } else {
        source
    };
    let (bytes, selection, package, catalog) = if let Some(name) = source.strip_prefix("catalog:") {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| AppError::Policy("Unable to start the Sigma catalog download".into()))?;
        let download = runtime.block_on(download(name, cancel))?;
        let bundle = if let Some(selection) = &download.selection {
            inspect_sigmahq_catalog_reference(
                &download.index,
                name,
                &download.bytes,
                selection,
                cancel,
            )?
        } else {
            inspect_sigma_catalog_asset(&download.index, name, &download.bytes, cancel)?
        };
        (
            download.bytes,
            download.selection,
            bundle,
            Some(download.index),
        )
    } else {
        let bytes = read_local(Path::new(source), cancel)?;
        let package = inspect_sigma_package_bundle(&bytes, cancel)?;
        (bytes, None, package, None)
    };
    let name = package.metadata.name.clone();
    if update.is_some_and(|requested| requested != name) {
        return Err(AppError::Policy(
            "The candidate package has a different name".into(),
        ));
    }
    let previous = history.get(&name);
    if update.is_none() && previous.is_some_and(|(receipt, _)| receipt.active) {
        return Err(AppError::Policy(
            "This Sigma package is active. Use /sigma update to review the change.".into(),
        ));
    }
    let detail = format_preview(
        store,
        engine,
        previous.map(|(receipt, _)| receipt),
        &package,
        catalog.as_ref(),
        cancel,
    )?;
    Ok(SigmaPackagePreview {
        detail,
        name,
        bytes,
        asset: package.asset_sha256,
        previous: previous.map(|(_, operation)| operation.hash),
        catalog,
        selection,
    })
}

fn format_preview(
    store: &LocalStore,
    engine: &Engine<'_>,
    previous: Option<&irmind_app::v10_proofs::SigmaPackageInstallationV1>,
    candidate: &SigmaPackageBundle,
    index: Option<&SigmaCatalogIndex>,
    cancel: &CancellationToken,
) -> Result<String, AppError> {
    use std::fmt::Write as _;
    let metadata = &candidate.metadata;
    let origin = index.map_or_else(
        || "local file".to_owned(),
        |release| {
            format!(
                "catalog tag {} · sequence {}",
                release.tag(),
                release.sequence()
            )
        },
    );
    let mut detail = format!(
        "Install Sigma package {} {}?\nOrigin {origin}\nLicense {}\nRules {}\nManifest SHA-256 {}\nAsset SHA-256 {}",
        metadata.name,
        metadata.version,
        metadata.license,
        candidate.pack.rules.len(),
        irmind_app::hex(&candidate.manifest_sha256),
        irmind_app::hex(&candidate.asset_sha256),
    );
    if let Some(old) = previous {
        let _ = write!(
            detail,
            "\nPreviously committed version {} · license {}",
            old.version, old.license
        );
        if old.active {
            let current = store
                .open_local_sigma_package(engine, &old.name, cancel)?
                .ok_or_else(|| AppError::Policy("Sigma package changed during preview".into()))?;
            let (added, removed, changed) = changes(&current.pack, &candidate.pack);
            let _ = write!(
                detail,
                "\nRule changes · {added} added, {removed} removed, {changed} changed"
            );
        }
    }
    Ok(detail)
}

fn changes(old: &LocalSigmaPack, candidate: &LocalSigmaPack) -> (usize, usize, usize) {
    let previous: BTreeMap<_, _> = old
        .manifest
        .0
        .iter()
        .map(|entry| (entry.rule.id.as_str(), entry.rule.sha256))
        .collect();
    let mut added = 0;
    let mut changed = 0;
    for rule in &candidate.manifest.0 {
        match previous.get(rule.rule.id.as_str()) {
            None => added += 1,
            Some(hash) if *hash != rule.rule.sha256 => changed += 1,
            Some(_) => (),
        }
    }
    let removed = previous.len() - (candidate.manifest.0.len() - added);
    (added, removed, changed)
}

pub(super) fn apply(
    store: &LocalStore,
    engine: &Engine<'_>,
    approved: &SigmaPackagePreview,
    cancel: &CancellationToken,
) -> Result<String, AppError> {
    if let Some(index) = &approved.catalog {
        store.install_catalog_sigma_package(
            engine,
            index,
            &approved.bytes,
            &CatalogSigmaInstallApproval {
                name: &approved.name,
                asset: approved.asset,
                proof: irmind_app::sha256(index.proof()),
                previous: approved.previous,
                selection: approved.selection.as_deref(),
            },
            cancel,
        )?;
    } else {
        store.install_local_sigma_package(
            engine,
            &approved.bytes,
            approved.asset,
            approved.previous,
            cancel,
        )?;
    }
    Ok(format!("Sigma package {} is active", approved.name))
}

struct CatalogDownload {
    index: SigmaCatalogIndex,
    bytes: Vec<u8>,
    selection: Option<Vec<u8>>,
}

async fn download(name: &str, cancel: &CancellationToken) -> Result<CatalogDownload, AppError> {
    use super::catalog_source::fetch_sigma_asset as fetch;
    if !irmind_app::v10_proofs::valid_sigma_package_identity(name, "0.0.0") {
        return Err(usage());
    }
    let verifier = Ed25519CatalogIndexVerifier::production()?;
    if !verifier.available() {
        return Err(CatalogError::Unavailable.into());
    }
    let metadata = fetch(
        &format!("https://api.github.com/repos/{CATALOG_REPOSITORY}/releases/latest"),
        1024 * 1024,
        cancel,
    )
    .await?;
    let release = CatalogReleaseMetadata::decode(&metadata, true)?;
    let base = format!(
        "https://github.com/{CATALOG_REPOSITORY}/releases/download/{}",
        release.tag()
    );
    let raw = fetch(&format!("{base}/sigma-index.json"), 1024 * 1024, cancel).await?;
    let signature = fetch(&format!("{base}/sigma-index.ed25519"), 64, cancel).await?;
    let index = verifier.verify_sigma(&raw, &signature, release.tag())?;
    let entry = index
        .entries()
        .iter()
        .find(|entry| entry.name == name)
        .ok_or(CatalogError::InvalidData)?;
    if !entry.supports_irmind(env!("CARGO_PKG_VERSION"))? {
        return Err(AppError::Policy(format!(
            "Sigma package requires IRMind {}",
            entry.minimum_irmind_version
        )));
    }
    let size = |value: u64| usize::try_from(value).map_err(|_| CatalogError::InvalidData);
    let (bytes, selection) = match &entry.source {
        SigmaCatalogSource::CatalogAsset { asset, bytes, .. } => (
            fetch(&format!("{base}/{asset}"), size(*bytes)?, cancel).await?,
            None,
        ),
        SigmaCatalogSource::SigmahqArchive {
            url,
            bytes,
            selection_asset,
            selection_bytes,
            ..
        } => {
            let manifest = fetch(
                &format!("{base}/{selection_asset}"),
                size(*selection_bytes)?,
                cancel,
            )
            .await?;
            if manifest.len() as u64 != *selection_bytes
                || irmind_app::sha256(&manifest) != *entry.manifest_sha256.as_bytes()
            {
                return Err(CatalogError::AssetMismatch.into());
            }
            let archive = super::catalog_source::fetch_sigmahq(url, size(*bytes)?, cancel).await?;
            (archive, Some(manifest))
        }
    };
    Ok(CatalogDownload {
        index,
        bytes,
        selection,
    })
}

fn read_local(path: &Path, cancel: &CancellationToken) -> Result<Vec<u8>, AppError> {
    let parent = path
        .parent()
        .filter(|part| !part.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file = path.file_name().ok_or_else(usage)?;
    let mut source = irmind_fs::open_regular_no_follow(parent, Path::new(file))
        .map_err(|_| AppError::Policy("Sigma package is not a readable regular file".into()))?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 16 * 1024];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let count = source
            .read(&mut chunk)
            .map_err(|_| AppError::Policy("Unable to read Sigma package".into()))?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > LIMIT {
            return Err(AppError::Policy(
                "Sigma package exceeds the byte limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn usage() -> AppError {
    AppError::Policy(
        "Use /sigma install <file|catalog:name> or /sigma update <name> [file|catalog:name]".into(),
    )
}
