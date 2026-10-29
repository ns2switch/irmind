#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use ed25519_dalek::{Signer as _, SigningKey};
use fs4::fs_std::FileExt as _;
use irmind_app::{
    AppError, KeystoreCapability, KeystoreManifest, SecretBackend, Signer, SignerBackend,
};
use irmind_domain::Actor;
use irmind_keystore_transfer::{KeyImportSession, wrap_signing_seed};
use rand::RngCore as _;
use secrecy::{ExposeSecret as _, SecretString};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"IRKS";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 61;
const MIN_MEMORY_KIB: u32 = 32 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MIN_PASSES: u32 = 3;
const MAX_PASSES: u32 = 10;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MIN_PASSPHRASE_BYTES: usize = 12;

pub const MANIFEST: KeystoreManifest = KeystoreManifest {
    id: "file",
    capabilities: &[KeystoreCapability::Signer, KeystoreCapability::Secrets],
    interactive_unlock: true,
    headless: true,
    network: false,
    config_fields: &[],
};

struct VaultState {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    records: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

struct Vault {
    path: PathBuf,
    _lock: File,
    state: Mutex<VaultState>,
    poisoned: AtomicBool,
    imports: Mutex<BTreeMap<String, KeyImportSession>>,
}

#[derive(Clone)]
pub struct FileKeystore {
    vault: Arc<Vault>,
}

struct FileSigner {
    vault: Arc<Vault>,
    actor: Actor,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for FileKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeystore").finish_non_exhaustive()
    }
}

fn failure() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
        irmind_app::AdapterStorageError::EncryptedKeystoreOperationFailed,
    ))
}

fn file_error(error: &std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::EncryptedKeystorePermissionDenied,
        ))
    } else {
        failure()
    }
}

fn open_private(path: &Path, create: bool) -> Result<File, AppError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path).map_err(|error| file_error(&error))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if file.metadata().map_err(|_| failure())?.file_attributes() & 0x400 != 0 {
            return Err(failure());
        }
    }
    irmind_fs::private_file(path).map_err(|error| file_error(&error))?;
    Ok(file)
}

fn record_name(actor: &Actor) -> String {
    format!("key:{}", actor.as_storage())
}

fn secret_name(name: &str) -> Result<String, AppError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidModuleSecretName,
        )));
    }
    Ok(format!("secret:{name}"))
}

mod backend_ports;
mod crypto;
mod file_backend;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::wildcard_imports)]
mod tests;
