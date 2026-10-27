use irmind_app::{
    AdapterStorageError, AppError, ConfigurationStore, FixedAppError, PersistentConfig,
};
use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

const MAX_CONFIG_BYTES: u64 = 65_536;

pub struct TomlConfigurationStore {
    home: PathBuf,
}

impl TomlConfigurationStore {
    pub fn new(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
        }
    }

    fn path(&self) -> PathBuf {
        self.home.join("config.toml")
    }
}

fn invalid_storage() -> AppError {
    AppError::Fixed(FixedAppError::AdapterStorage(
        AdapterStorageError::LocalStorageOperationFailed,
    ))
}

impl ConfigurationStore for TomlConfigurationStore {
    fn load(&self) -> Result<PersistentConfig, AppError> {
        let path = self.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PersistentConfig::default());
            }
            Err(_) => return Err(invalid_storage()),
        };
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(invalid_storage());
        }
        irmind_fs::private_file(&path).map_err(|_| invalid_storage())?;
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .map_err(|_| invalid_storage())?
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid_storage())?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(invalid_storage());
        }
        let source = std::str::from_utf8(&bytes).map_err(|_| invalid_storage())?;
        toml::from_str(source).map_err(|_| invalid_storage())
    }

    fn save(&self, config: &PersistentConfig) -> Result<(), AppError> {
        fs::create_dir_all(&self.home).map_err(|_| invalid_storage())?;
        irmind_fs::private_dir(&self.home).map_err(|_| invalid_storage())?;
        let path = self.path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() => return Err(invalid_storage()),
            Ok(_) => irmind_fs::private_file(&path).map_err(|_| invalid_storage())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid_storage()),
        }
        let source = toml::to_string_pretty(config).map_err(|_| invalid_storage())?;
        if source.len() as u64 > MAX_CONFIG_BYTES {
            return Err(invalid_storage());
        }
        for index in 0..16 {
            let temp = self
                .home
                .join(format!("config.toml.tmp.{}.{index}", std::process::id()));
            let file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(invalid_storage()),
            };
            let result = write_and_replace(file, &temp, &path, &self.home, source.as_bytes());
            if result.is_err() {
                let _ = fs::remove_file(&temp);
            }
            return result.map_err(|_| invalid_storage());
        }
        Err(invalid_storage())
    }
}

fn write_and_replace(
    mut file: fs::File,
    temp: &Path,
    path: &Path,
    home: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    irmind_fs::private_file(temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    irmind_fs::durable_replace(temp, path)?;
    irmind_fs::sync_directory(home)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_private_and_rejects_a_corrupt_file() {
        let root = tempfile::tempdir().unwrap();
        let store = TomlConfigurationStore::new(root.path());
        assert!(store.load().unwrap().llm_module.is_none());
        store.save(&PersistentConfig::default()).unwrap();
        let path = root.path().join("config.toml");
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("config.toml.tmp.")
        }));
        assert!(store.load().unwrap() == PersistentConfig::default());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(&path, "version = [invalid]").unwrap();
        assert!(store.load().is_err());
    }
}
