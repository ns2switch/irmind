use crate::crypto::{decrypt, derive, persist};
use crate::*;

impl FileKeystore {
    pub fn open(home: &Path, passphrase: &SecretString, create: bool) -> Result<Self, AppError> {
        let path = home.join("keystore.enc");
        let lock_path = home.join("keystore.lock");
        let lock = open_private(&lock_path, true)?;
        if !lock.try_lock_exclusive().map_err(|_| failure())? {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::EncryptedKeystoreIsOpenInAnotherProcess,
            )));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(failure()),
        };
        let state = if let Some(metadata) = metadata {
            if !metadata.is_file() || metadata.len() > 1024 * 1024 {
                return Err(failure());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            open_private(&path, false)?
                .take((MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| failure())?;
            decrypt(&bytes, passphrase)?
        } else if create {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            let key = derive(passphrase, &salt, MIN_MEMORY_KIB, MIN_PASSES, 1)?;
            VaultState {
                key,
                salt,
                records: BTreeMap::new(),
            }
        } else {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                irmind_app::AdapterStorageError::EncryptedKeystoreNotFound,
            )));
        };
        let keystore = Self {
            vault: Arc::new(Vault {
                path,
                _lock: lock,
                state: Mutex::new(state),
                poisoned: AtomicBool::new(false),
                imports: Mutex::new(BTreeMap::new()),
            }),
        };
        if create && !keystore.vault.path.exists() {
            let state = keystore.vault.state.lock().map_err(|_| failure())?;
            persist(&keystore.vault, &state)?;
        }
        Ok(keystore)
    }

    pub fn change_passphrase(&self, passphrase: &SecretString) -> Result<(), AppError> {
        let mut state = self.vault.state.lock().map_err(|_| failure())?;
        if self.vault.poisoned.load(Ordering::SeqCst) {
            return Err(failure());
        }
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive(passphrase, &salt, MIN_MEMORY_KIB, MIN_PASSES, 1)?;
        let next = VaultState {
            key,
            salt,
            records: std::mem::take(&mut state.records),
        };
        match persist(&self.vault, &next) {
            Ok(()) => {
                *state = next;
                Ok(())
            }
            Err(error) => {
                if self.vault.poisoned.load(Ordering::SeqCst) {
                    *state = next;
                } else {
                    state.records = next.records;
                }
                Err(error)
            }
        }
    }

    pub(super) fn with_state<T>(
        &self,
        f: impl FnOnce(&mut VaultState) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let mut state = self.vault.state.lock().map_err(|_| failure())?;
        if self.vault.poisoned.load(Ordering::SeqCst) {
            return Err(failure());
        }
        f(&mut state)
    }
}
