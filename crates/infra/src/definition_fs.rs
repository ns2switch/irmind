use irmind_app::{AppError, MAX_DEFINITION_BYTES, ParserDefinitionStore, hex, sha256};
use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

pub struct FileDefinitionStore {
    root: PathBuf,
}
impl FileDefinitionStore {
    pub fn new(home: &Path) -> Self {
        Self {
            root: home.join("parsers"),
        }
    }

    fn directory(&self, name: &str) -> Result<PathBuf, AppError> {
        ensure_directory(&self.root)?;
        irmind_fs::private_dir(&self.root).map_err(|_| storage())?;
        let path = self.root.join(name);
        ensure_directory(&path)?;
        irmind_fs::private_dir(&path).map_err(|_| storage())?;
        Ok(path)
    }

    fn check_root(&self) -> Result<bool, AppError> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Ok(_) | Err(_) => Err(storage()),
        }
    }

    fn read(&self, directory: &str, name: &str) -> Result<Option<String>, AppError> {
        if !self.check_root()? {
            return Ok(None);
        }
        let root = self.root.join(directory);
        let relative = format!("{name}.toml");
        match fs::symlink_metadata(root.join(&relative)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(storage()),
            Ok(metadata) if !metadata.is_file() || metadata.len() > MAX_DEFINITION_BYTES as u64 => {
                return Err(storage());
            }
            Ok(_) => {}
        }
        let file = irmind_fs::open_regular_no_follow(&root, Path::new(&relative))
            .map_err(|_| storage())?;
        let mut bytes = Vec::new();
        file.take(MAX_DEFINITION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| storage())?;
        if bytes.len() > MAX_DEFINITION_BYTES {
            return Err(storage());
        }
        String::from_utf8(bytes).map(Some).map_err(|_| storage())
    }

    fn write(&self, directory: &str, name: &str, contents: &str) -> Result<(), AppError> {
        if contents.len() > MAX_DEFINITION_BYTES {
            return Err(storage());
        }
        let root = self.directory(directory)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".definition-")
            .tempfile_in(&root)
            .map_err(|_| storage())?;
        irmind_fs::private_file(temporary.path()).map_err(|_| storage())?;
        temporary
            .write_all(contents.as_bytes())
            .map_err(|_| storage())?;
        temporary.as_file().sync_all().map_err(|_| storage())?;
        let (file, path) = temporary.into_parts();
        drop(file);
        irmind_fs::durable_replace(&path, &root.join(format!("{name}.toml")))
            .map_err(|_| storage())?;
        irmind_fs::sync_directory(&root).map_err(|_| storage())
    }
}

impl ParserDefinitionStore for FileDefinitionStore {
    fn clean_temporary(&self) -> Result<usize, AppError> {
        let mut count = 0;
        for name in ["active", "archive"] {
            let root = self.directory(name)?;
            for entry in fs::read_dir(&root).map_err(|_| storage())?.take(4353) {
                let entry = entry.map_err(|_| storage())?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".definition-")
                {
                    fs::remove_file(entry.path()).map_err(|_| storage())?;
                    count += 1;
                }
            }
            irmind_fs::sync_directory(&root).map_err(|_| storage())?;
        }
        Ok(count)
    }
    fn read_active(&self, id: &str) -> Result<Option<String>, AppError> {
        validate_id(id)?;
        self.read("active", id)
    }
    fn write_active(&self, id: &str, contents: &str) -> Result<(), AppError> {
        validate_id(id)?;
        self.write("active", id, contents)
    }
    fn archive(&self, hash: &str, contents: &str) -> Result<(), AppError> {
        if hash != hex(&sha256(contents.as_bytes())) {
            return Err(storage());
        }
        self.write("archive", hash, contents)
    }
    fn deactivate(&self, id: &str) -> Result<(), AppError> {
        validate_id(id)?;
        let root = self.directory("active")?;
        match fs::remove_file(root.join(format!("{id}.toml"))) {
            Ok(()) => irmind_fs::sync_directory(&root).map_err(|_| storage()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage()),
        }
    }
    fn names(&self) -> Result<Vec<String>, AppError> {
        if !self.check_root()? {
            return Ok(Vec::new());
        }
        let directory = self.root.join("active");
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(storage()),
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err(storage());
            }
            Ok(_) => {}
        }
        let mut names = Vec::new();
        for (index, entry) in fs::read_dir(directory).map_err(|_| storage())?.enumerate() {
            if index >= 256 {
                return Err(storage());
            }
            let path = entry.map_err(|_| storage())?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "toml")
                && let Some(name) = path.file_stem()
            {
                names.push(name.to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    }
}

fn ensure_directory(path: &Path) -> Result<(), AppError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| storage())
        }
        Ok(_) | Err(_) => Err(storage()),
    }
}

fn validate_id(id: &str) -> Result<(), AppError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(storage());
    }
    Ok(())
}
fn storage() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::Definition(
        irmind_app::DefinitionError::Storage,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
