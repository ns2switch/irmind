use super::storage;
use irmind_app::{AppError, CancellationToken};
use irmind_domain::{
    MAX_SKILL_PACKAGE_BYTES, MAX_SKILL_RESOURCE_BYTES, SkillError, SkillPackage, SkillResource,
    SkillResourcePath,
};
use std::{fs, io::Read as _, path::Path};

pub(super) fn plain_directory(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| storage())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(storage());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(storage());
        }
    }
    Ok(())
}

fn check_cancelled(cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        Ok(())
    }
}

pub(super) fn read(root: &Path, cancel: &CancellationToken) -> Result<SkillPackage, AppError> {
    check_cancelled(cancel)?;
    plain_directory(root)?;
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(root).map_err(|_| storage())?.enumerate() {
        check_cancelled(cancel)?;
        if index >= 4 {
            return Err(SkillError::LimitExceeded.into());
        }
        let entry = entry.map_err(|_| storage())?;
        let name = entry.file_name().into_string().map_err(|_| storage())?;
        if name == "SKILL.md" {
            paths.push(name);
        } else if matches!(name.as_str(), "queries" | "rules" | "references") {
            plain_directory(&entry.path())?;
            for (child_index, child) in fs::read_dir(entry.path())
                .map_err(|_| storage())?
                .enumerate()
            {
                check_cancelled(cancel)?;
                if child_index >= 16 || paths.len() >= 17 {
                    return Err(SkillError::LimitExceeded.into());
                }
                let child = child.map_err(|_| storage())?;
                let filename = child.file_name().into_string().map_err(|_| storage())?;
                paths.push(format!("{name}/{filename}"));
            }
        } else {
            return Err(SkillError::InvalidPath.into());
        }
    }
    paths.sort();
    let mut total = 0usize;
    let mut files = Vec::new();
    for path in paths {
        SkillResourcePath::parse(&path)?;
        let resource = read_file(root, &path, cancel)?;
        total = total
            .checked_add(resource.untrusted_text().len())
            .ok_or(SkillError::LimitExceeded)?;
        if total > MAX_SKILL_PACKAGE_BYTES {
            return Err(SkillError::LimitExceeded.into());
        }
        files.push(resource);
    }
    check_cancelled(cancel)?;
    SkillPackage::new(files).map_err(Into::into)
}

fn read_file(
    root: &Path,
    path: &str,
    cancel: &CancellationToken,
) -> Result<SkillResource, AppError> {
    check_cancelled(cancel)?;
    let mut file =
        irmind_fs::open_regular_no_follow(root, Path::new(path)).map_err(|_| storage())?;
    if !irmind_fs::regular_file_has_single_link(&file).map_err(|_| storage())? {
        return Err(storage());
    }
    let before = file.metadata().map_err(|_| storage())?;
    if before.len() > MAX_SKILL_RESOURCE_BYTES as u64 {
        return Err(SkillError::LimitExceeded.into());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        check_cancelled(cancel)?;
        let count = file.read(&mut buffer).map_err(|_| storage())?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > MAX_SKILL_RESOURCE_BYTES {
            return Err(SkillError::LimitExceeded.into());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| storage())?;
    if before.len() != bytes.len() as u64
        || before.len() != after.len()
        || before.modified().map_err(|_| storage())? != after.modified().map_err(|_| storage())?
        || !irmind_fs::regular_file_has_single_link(&file).map_err(|_| storage())?
    {
        return Err(storage());
    }
    SkillResource::new(path, &bytes).map_err(Into::into)
}
