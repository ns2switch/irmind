//! Inspect analyst-selected Sigma rules under a bounded transport.
#[cfg(feature = "sigma")]
mod archive;
#[cfg(feature = "sigma")]
mod bundle;
#[cfg(feature = "sigma")]
pub use archive::inspect_sigmahq_archive;
#[cfg(feature = "sigma")]
pub use bundle::{
    SigmaPackageBundle, SigmaPackageMetadata, inspect_sigma_catalog_asset,
    inspect_sigma_package_bundle, inspect_sigmahq_catalog_reference,
};
#[cfg(feature = "sigma")]
pub mod evaluation;
pub mod field_table;
#[cfg(feature = "sigma")]
mod runtime;
#[cfg(feature = "sigma")]
pub use runtime::InstalledSigmaCoverage;
#[cfg(feature = "sigma")]
pub(crate) use runtime::{SigmaMatchCheck, verify_class_plan};
#[cfg(feature = "sigma")]
mod plan;
#[cfg(feature = "sigma")]
mod storage;
use irmind_app::{
    AppError, CancellationToken,
    v10_proofs::{SigmaPackManifestV1, SigmaPackRuleV1, SigmaRuleKeyV1},
};
use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};
#[cfg(feature = "sigma")]
pub use storage::{AdmittedSigmaPack, CatalogSigmaInstallApproval};

pub(crate) fn sigma_proof_read(
    kind: u8,
    bytes: Vec<u8>,
) -> Result<irmind_app::v10_proofs::SigmaProofRead, AppError> {
    let class_labels = if kind == 2 {
        let table =
            irmind_app::v10_proofs::SigmaFieldTableV1::decode(&bytes).map_err(|_| invalid())?;
        field_table::ReviewedSigmaFieldTable::parse(&table)?
            .variants
            .iter()
            .enumerate()
            .map(|(ordinal, class)| {
                format!(
                    "#{} {} / {} / {} · {} · {}",
                    ordinal,
                    class.product.as_deref().unwrap_or("*"),
                    class.service.as_deref().unwrap_or("*"),
                    class.category.as_deref().unwrap_or("*"),
                    class.parser_id,
                    class.mapping_id,
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(irmind_app::v10_proofs::SigmaProofRead {
        bytes,
        class_labels,
    })
}

const MAX_FILES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_DIRECTORIES: usize = 4096;
const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RULE_BYTES: u64 = 64 * 1024;

pub struct SigmaRuleIdentity {
    pub id: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
}

pub struct LocalSigmaPack {
    pub manifest: SigmaPackManifestV1,
    pub rules: Vec<Vec<u8>>,
}

/// Validate the exact rule bytes before presenting an analyst's import preview.
#[cfg(feature = "sigma")]
pub fn inspect_local_sigma_pack(
    root: &Path,
    cancel: &CancellationToken,
) -> Result<LocalSigmaPack, AppError> {
    read_local_sigma_pack(root, cancel, admit_rule_identity)
}

#[cfg(feature = "sigma")]
fn validate_manifest_rule(entry: &SigmaPackRuleV1, bytes: &[u8]) -> Result<(), AppError> {
    let digest = irmind_app::sha256(bytes);
    let metadata = admit_rule_identity(bytes)?;
    let id = metadata
        .id
        .unwrap_or_else(|| format!("sha256:{}", irmind_app::hex(&digest)));
    if bytes.len() as u64 != entry.size
        || digest != entry.rule.sha256
        || id != entry.rule.id
        || metadata.author != entry.author
        || metadata.version != entry.version
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(feature = "sigma")]
fn admit_rule_identity(raw: &[u8]) -> Result<SigmaRuleIdentity, AppError> {
    use irmind_sigma::RuleValue;
    let document = irmind_sigma::admit_rule(raw).map_err(|_| {
        AppError::Policy("A Sigma rule is invalid or uses unsupported YAML syntax".into())
    })?;
    let text = |name| match document.fields().get(name) {
        None => Ok(None),
        Some(RuleValue::Text(value)) => Ok(Some(value.clone())),
        Some(_) => Err(AppError::Policy("Sigma rule metadata must be text".into())),
    };
    Ok(SigmaRuleIdentity {
        id: text("id")?,
        version: text("version")?,
        author: text("author")?,
    })
}

/// Ingest the selected directory without consulting the network. The admission
/// function validates the complete bounded YAML document and returns its provenance.
pub fn read_local_sigma_pack(
    root: &Path,
    cancel: &CancellationToken,
    mut admit: impl FnMut(&[u8]) -> Result<SigmaRuleIdentity, AppError>,
) -> Result<LocalSigmaPack, AppError> {
    check_directory(root)?;
    let files = collect_files(root, cancel)?;
    let mut manifest = Vec::new();
    let mut rules = Vec::new();
    let mut remaining = MAX_PACK_BYTES;
    for (relative, path) in files {
        check_cancel(cancel)?;
        let bytes = read_rule(root, &path, remaining)?;
        let size = bytes.len() as u64;
        remaining = remaining.checked_sub(size).ok_or_else(invalid)?;
        let metadata = admit(&bytes)?;
        let hash = irmind_app::sha256(&bytes);
        let rule = SigmaRuleKeyV1 {
            id: metadata
                .id
                .unwrap_or_else(|| format!("sha256:{}", irmind_app::hex(&hash))),
            sha256: hash,
        };
        manifest.push(SigmaPackRuleV1 {
            path: relative,
            rule,
            version: metadata.version,
            author: metadata.author,
            size,
        });
        rules.push(bytes);
    }
    let manifest = SigmaPackManifestV1(manifest);
    manifest.encode().map_err(|_| invalid())?;
    Ok(LocalSigmaPack { manifest, rules })
}

fn collect_files(
    root: &Path,
    cancel: &CancellationToken,
) -> Result<Vec<(String, PathBuf)>, AppError> {
    let mut directories = vec![(PathBuf::new(), 0)];
    let mut visited = 0;
    let mut files = Vec::new();
    let mut entries = 0;
    while let Some((subdirectory, depth)) = directories.pop() {
        check_cancel(cancel)?;
        let directory = root.join(&subdirectory);
        check_directory(&directory)?;
        for entry in fs::read_dir(directory).map_err(|_| invalid())? {
            check_cancel(cancel)?;
            let entry = entry.map_err(|_| invalid())?;
            entries += 1;
            // Include non-rule entries in the traversal budget.
            if entries > 2 * (MAX_FILES + MAX_DIRECTORIES) {
                return Err(invalid());
            }
            let relative = subdirectory.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| invalid())?;
            if is_link(&metadata) {
                return Err(invalid());
            }
            if metadata.is_dir() {
                visited += 1;
                if visited > MAX_DIRECTORIES || depth == MAX_DEPTH {
                    return Err(invalid());
                }
                directories.push((relative, depth + 1));
            } else if metadata.is_file()
                && relative
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml")
                    })
            {
                if files.len() == MAX_FILES {
                    return Err(invalid());
                }
                let normalized = relative
                    .components()
                    .map(|component| component.as_os_str().to_str().ok_or_else(invalid))
                    .collect::<Result<Vec<_>, _>>()?
                    .join("/");
                if normalized.len() > 512 {
                    return Err(invalid());
                }
                files.push((normalized, relative));
            } else if !metadata.is_file() {
                return Err(invalid());
            }
        }
    }
    files.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

fn read_rule(root: &Path, path: &Path, remaining: u64) -> Result<Vec<u8>, AppError> {
    let file = irmind_fs::open_regular_no_follow(root, path).map_err(|_| invalid())?;
    let length = file.metadata().map_err(|_| invalid())?.len();
    let max = remaining.min(MAX_RULE_BYTES);
    if length == 0
        || length > max
        || !irmind_fs::regular_file_has_single_link(&file).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(length + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 != length {
        return Err(invalid());
    }
    Ok(bytes)
}

fn check_directory(directory: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| invalid())?;
    if !metadata.is_dir() || is_link(&metadata) {
        return Err(invalid());
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    Ok(())
}

fn invalid() -> AppError {
    AppError::Storage("Sigma pack contains an unsafe input or exceeds its import limits".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
