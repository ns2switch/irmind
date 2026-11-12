use irmind_app::{AppError, CancellationToken, SkillPackageStore, SkillServiceError, hex, sha256};
use irmind_domain::{SkillName, SkillPackage};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

mod candidate;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

const MAX_STORED_BYTES: u64 = 384 * 1024;

pub struct FileSkillPackageStore {
    home: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Container {
    version: u32,
    name: String,
    files: Vec<(String, String)>,
}

impl Container {
    fn new(name: &SkillName, package: &SkillPackage) -> Self {
        Self {
            version: 1,
            name: name.as_str().into(),
            files: package
                .resources()
                .values()
                .map(|r| (r.path().as_str().into(), r.untrusted_text().into()))
                .collect(),
        }
    }

    fn package(self, name: &SkillName) -> Result<SkillPackage, AppError> {
        if self.version != 1 || self.name != name.as_str() || self.files.len() > 17 {
            return Err(storage());
        }
        let files = self
            .files
            .into_iter()
            .map(|(path, text)| {
                irmind_domain::SkillResource::new(&path, text.as_bytes()).map_err(AppError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        SkillPackage::new(files).map_err(Into::into)
    }
}

impl FileSkillPackageStore {
    pub fn new(home: &Path) -> Self {
        Self { home: home.into() }
    }

    fn active(&self, create: bool) -> Result<Option<PathBuf>, AppError> {
        candidate::plain_directory(&self.home)?;
        let root = self.home.join("skills");
        let active = root.join("active");
        for directory in [&root, &active] {
            match fs::symlink_metadata(directory) {
                Ok(_) => candidate::plain_directory(directory)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                    return Ok(None);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut builder = fs::DirBuilder::new();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt as _;
                        builder.mode(0o700);
                    }
                    builder.create(directory).map_err(|_| storage())?;
                }
                Err(_) => return Err(storage()),
            }
            if create {
                irmind_fs::private_dir(directory).map_err(|_| storage())?;
            }
        }
        Ok(Some(active))
    }

    fn filename(name: &SkillName) -> String {
        format!("{}.json", hex(&sha256(name.as_str().as_bytes())))
    }

    fn read_container(root: &Path, filename: &str) -> Result<Container, AppError> {
        let file =
            irmind_fs::open_regular_no_follow(root, Path::new(filename)).map_err(|_| storage())?;
        if !irmind_fs::regular_file_has_single_link(&file).map_err(|_| storage())? {
            return Err(storage());
        }
        if file.metadata().map_err(|_| storage())?.len() > MAX_STORED_BYTES {
            return Err(storage());
        }
        let mut bytes = Vec::new();
        file.take(MAX_STORED_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| storage())?;
        if bytes.len() as u64 > MAX_STORED_BYTES {
            return Err(storage());
        }
        serde_json::from_slice(&bytes).map_err(|_| storage())
    }
}

impl SkillPackageStore for FileSkillPackageStore {
    fn read_candidate(
        &self,
        directory: &Path,
        cancel: &CancellationToken,
    ) -> Result<SkillPackage, AppError> {
        candidate::read(directory, cancel)
    }

    fn names(&self) -> Result<Vec<SkillName>, AppError> {
        let Some(root) = self.active(false)? else {
            return Ok(Vec::new());
        };
        let mut names = Vec::new();
        for (index, entry) in fs::read_dir(&root).map_err(|_| storage())?.enumerate() {
            if index >= 512 {
                return Err(storage());
            }
            let entry = entry.map_err(|_| storage())?;
            let filename = entry.file_name().into_string().map_err(|_| storage())?;
            if filename.starts_with(".skill-") {
                continue;
            }
            let container = Self::read_container(&root, &filename)?;
            let name = SkillName::parse(&container.name)?;
            if filename != Self::filename(&name) {
                return Err(storage());
            }
            names.push(name);
            if names.len() > 256 {
                return Err(storage());
            }
        }
        names.sort();
        Ok(names)
    }

    fn read_active(&self, name: &SkillName) -> Result<Option<SkillPackage>, AppError> {
        let Some(root) = self.active(false)? else {
            return Ok(None);
        };
        let filename = Self::filename(name);
        match fs::symlink_metadata(root.join(&filename)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(storage()),
            Ok(_) => Self::read_container(&root, &filename)?
                .package(name)
                .map(Some),
        }
    }

    fn publish(&self, name: &SkillName, package: &SkillPackage) -> Result<(), AppError> {
        let root = self.active(true)?.ok_or_else(storage)?;
        let contents = serde_json::to_vec(&Container::new(name, package)).map_err(|_| storage())?;
        if contents.len() as u64 > MAX_STORED_BYTES {
            return Err(storage());
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".skill-")
            .tempfile_in(&root)
            .map_err(|_| storage())?;
        irmind_fs::private_file(temporary.path()).map_err(|_| storage())?;
        temporary.write_all(&contents).map_err(|_| storage())?;
        temporary.as_file().sync_all().map_err(|_| storage())?;
        let (file, path) = temporary.into_parts();
        drop(file);
        irmind_fs::durable_replace(&path, &root.join(Self::filename(name)))
            .map_err(|_| storage())?;
        irmind_fs::sync_directory(&root).map_err(|_| storage())
    }

    fn deactivate(&self, name: &SkillName) -> Result<(), AppError> {
        let Some(root) = self.active(false)? else {
            return Ok(());
        };
        match fs::remove_file(root.join(Self::filename(name))) {
            Ok(()) => irmind_fs::sync_directory(&root).map_err(|_| storage()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage()),
        }
    }

    fn clean_temporary(&self) -> Result<usize, AppError> {
        let Some(root) = self.active(false)? else {
            return Ok(0);
        };
        let mut count = 0;
        for (index, entry) in fs::read_dir(&root).map_err(|_| storage())?.enumerate() {
            if index >= 512 {
                return Err(storage());
            }
            let entry = entry.map_err(|_| storage())?;
            if entry.file_name().to_string_lossy().starts_with(".skill-") {
                fs::remove_file(entry.path()).map_err(|_| storage())?;
                count += 1;
            }
        }
        irmind_fs::sync_directory(&root).map_err(|_| storage())?;
        Ok(count)
    }
}

fn storage() -> AppError {
    SkillServiceError::Storage.into()
}
