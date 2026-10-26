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
    AppError::Storage("encrypted keystore operation failed".into())
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
    let file = options.open(path).map_err(|_| failure())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if file.metadata().map_err(|_| failure())?.file_attributes() & 0x400 != 0 {
            return Err(failure());
        }
    }
    irmind_fs::private_file(path).map_err(|_| failure())?;
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
        return Err(AppError::Policy("invalid module secret name".into()));
    }
    Ok(format!("secret:{name}"))
}

fn derive(
    passphrase: &SecretString,
    salt: &[u8; 16],
    memory: u32,
    passes: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
        || !(MIN_PASSES..=MAX_PASSES).contains(&passes)
        || !(1..=4).contains(&lanes)
        || passphrase.expose_secret().len() < MIN_PASSPHRASE_BYTES
    {
        return Err(AppError::Storage(
            "encrypted keystore parameters are unsafe".into(),
        ));
    }
    let params = Params::new(memory, passes, lanes, Some(32)).map_err(|_| failure())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut *key)
        .map_err(|_| failure())?;
    Ok(key)
}

fn read_u32(bytes: &[u8]) -> Result<u32, AppError> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| failure())?))
}

fn read_records(bytes: &[u8]) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, AppError> {
    if bytes.len() < 4 || bytes.len() > MAX_FILE_BYTES {
        return Err(failure());
    }
    let mut offset = 4usize;
    let count = read_u32(&bytes[..4])? as usize;
    if count > 1024 {
        return Err(failure());
    }
    let mut records = BTreeMap::new();
    for _ in 0..count {
        let length = usize::from(*bytes.get(offset).ok_or_else(failure)?);
        offset += 1;
        if length == 0 || length > 100 || offset + length + 4 > bytes.len() {
            return Err(failure());
        }
        let name = std::str::from_utf8(&bytes[offset..offset + length])
            .map_err(|_| failure())?
            .to_owned();
        offset += length;
        let data_len = read_u32(&bytes[offset..offset + 4])? as usize;
        offset += 4;
        if data_len == 0 || data_len > 4096 || offset + data_len > bytes.len() {
            return Err(failure());
        }
        let data = Zeroizing::new(bytes[offset..offset + data_len].to_vec());
        offset += data_len;
        if records.insert(name, data).is_some() {
            return Err(failure());
        }
    }
    if offset != bytes.len() {
        return Err(failure());
    }
    Ok(records)
}

fn encode_records(
    records: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(
        &u32::try_from(records.len())
            .map_err(|_| failure())?
            .to_be_bytes(),
    );
    for (name, data) in records {
        let name_len = u8::try_from(name.len()).map_err(|_| failure())?;
        let data_len = u32::try_from(data.len()).map_err(|_| failure())?;
        out.push(name_len);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data_len.to_be_bytes());
        out.extend_from_slice(data);
    }
    if out.len() > MAX_FILE_BYTES {
        return Err(failure());
    }
    Ok(out)
}

fn encrypt(state: &VaultState) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let plain = encode_records(&state.records)?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&*state.key).into());
    let ciphertext_len = plain.len().checked_add(16).ok_or_else(failure)?;
    let mut output = Zeroizing::new(Vec::with_capacity(HEADER_LEN + ciphertext_len));
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&MIN_MEMORY_KIB.to_be_bytes());
    output.extend_from_slice(&MIN_PASSES.to_be_bytes());
    output.extend_from_slice(&1u32.to_be_bytes());
    output.extend_from_slice(&state.salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(
        &u32::try_from(ciphertext_len)
            .map_err(|_| failure())?
            .to_be_bytes(),
    );
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &output,
            },
        )
        .map_err(|_| failure())?;
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn decrypt(bytes: &[u8], passphrase: &SecretString) -> Result<VaultState, AppError> {
    if bytes.len() < HEADER_LEN + 16 || bytes.len() > MAX_FILE_BYTES || &bytes[..4] != MAGIC {
        return Err(failure());
    }
    if bytes[4] != VERSION {
        return Err(AppError::Storage(
            "unknown encrypted keystore version".into(),
        ));
    }
    let memory = read_u32(&bytes[5..9])?;
    let passes = read_u32(&bytes[9..13])?;
    let lanes = read_u32(&bytes[13..17])?;
    let salt: [u8; 16] = bytes[17..33].try_into().map_err(|_| failure())?;
    let nonce: [u8; 24] = bytes[33..57].try_into().map_err(|_| failure())?;
    let length = read_u32(&bytes[57..61])? as usize;
    if length < 16 || length != bytes.len() - HEADER_LEN {
        return Err(failure());
    }
    let key = derive(passphrase, &salt, memory, passes, lanes)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &bytes[..HEADER_LEN],
                },
            )
            .map_err(|_| AppError::Storage("cannot unlock encrypted keystore".into()))?,
    );
    Ok(VaultState {
        key,
        salt,
        records: read_records(&plain)?,
    })
}

fn persist(vault: &Vault, state: &VaultState) -> Result<(), AppError> {
    let bytes = encrypt(state)?;
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let path = vault
        .path
        .with_extension(format!("tmp-{:016x}", u64::from_be_bytes(suffix)));
    let mut replace_started = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| failure())?;
        irmind_fs::private_file(&path).map_err(|_| failure())?;
        file.write_all(&bytes).map_err(|_| failure())?;
        file.sync_all().map_err(|_| failure())?;
        replace_started = true;
        irmind_fs::durable_replace(&path, &vault.path).map_err(|_| failure())?;
        irmind_fs::sync_directory(vault.path.parent().ok_or_else(failure)?)
            .map_err(|_| failure())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
        if replace_started {
            // A failed replace or directory sync leaves the commit state uncertain.
            // Block every subsequent operation until the vault is reopened.
            vault.poisoned.store(true, Ordering::SeqCst);
        }
    }
    result
}

impl FileKeystore {
    pub fn open(home: &Path, passphrase: &SecretString, create: bool) -> Result<Self, AppError> {
        let path = home.join("keystore.enc");
        let lock_path = home.join("keystore.lock");
        let lock = open_private(&lock_path, true)?;
        if !lock.try_lock_exclusive().map_err(|_| failure())? {
            return Err(AppError::Storage(
                "encrypted keystore is open in another process".into(),
            ));
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
            return Err(AppError::Storage("encrypted keystore not found".into()));
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

    fn with_state<T>(
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

impl SignerBackend for FileKeystore {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MANIFEST
    }

    fn load(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        let public_key = self.with_state(|state| {
            let bytes = state
                .records
                .get(&record_name(&actor))
                .ok_or_else(|| AppError::Signature("signing key not found".into()))?;
            let seed =
                Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| failure())?);
            let key = SigningKey::from_bytes(&seed);
            if matches!(actor, Actor::Agent(_))
                && let Some(analyst) = state.records.get(&record_name(&Actor::Analyst))
            {
                let analyst_seed = Zeroizing::new(
                    <[u8; 32]>::try_from(analyst.as_slice()).map_err(|_| failure())?,
                );
                if key.verifying_key() == SigningKey::from_bytes(&analyst_seed).verifying_key() {
                    return Err(AppError::Signature(
                        "agent and analyst keys must differ".into(),
                    ));
                }
            }
            Ok(key.verifying_key().to_bytes().to_vec())
        })?;
        Ok(Arc::new(FileSigner {
            vault: self.vault.clone(),
            actor,
            public_key,
        }))
    }

    fn create(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        self.with_state(|state| {
            let name = record_name(&actor);
            if state.records.contains_key(&name) {
                return Err(AppError::Policy("signing key already exists".into()));
            }
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            state
                .records
                .insert(name.clone(), Zeroizing::new(key.to_bytes().to_vec()));
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.remove(&name);
                }
                return Err(error);
            }
            Ok(())
        })?;
        self.load(actor)
    }

    fn public_key_for_actor(&self, actor: &Actor) -> Result<Vec<u8>, AppError> {
        self.load(actor.clone()).map(|signer| signer.public_key())
    }

    fn migration_recipient(&self, actor: &Actor) -> Result<[u8; 32], AppError> {
        self.with_state(|state| {
            if state.records.contains_key(&record_name(actor)) {
                return Err(AppError::Policy(
                    "destination signing key already exists".into(),
                ));
            }
            Ok(())
        })?;
        let session = KeyImportSession::new();
        let recipient = session.recipient();
        self.vault
            .imports
            .lock()
            .map_err(|_| failure())?
            .insert(actor.as_storage(), session);
        Ok(recipient)
    }

    fn export_wrapped(&self, actor: &Actor, recipient: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        self.with_state(|state| {
            let bytes = state.records.get(&record_name(actor)).ok_or_else(failure)?;
            let seed =
                Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| failure())?);
            wrap_signing_seed(actor, &seed, recipient)
        })
    }

    fn import_wrapped(&self, actor: Actor, packet: &[u8]) -> Result<(), AppError> {
        let session = self
            .vault
            .imports
            .lock()
            .map_err(|_| failure())?
            .remove(&actor.as_storage())
            .ok_or_else(failure)?;
        let seed = session.unwrap(&actor, packet)?;
        self.with_state(|state| {
            let name = record_name(&actor);
            if state.records.contains_key(&name) {
                return Err(AppError::Policy(
                    "destination signing key already exists".into(),
                ));
            }
            if matches!(actor, Actor::Agent(_))
                && let Some(analyst) = state.records.get(&record_name(&Actor::Analyst))
            {
                let analyst_seed = Zeroizing::new(
                    <[u8; 32]>::try_from(analyst.as_slice()).map_err(|_| failure())?,
                );
                if SigningKey::from_bytes(&seed).verifying_key()
                    == SigningKey::from_bytes(&analyst_seed).verifying_key()
                {
                    return Err(AppError::Signature(
                        "agent and analyst keys must differ".into(),
                    ));
                }
            }
            state
                .records
                .insert(name.clone(), Zeroizing::new(seed.to_vec()));
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.remove(&name);
                }
                return Err(error);
            }
            Ok(())
        })
    }
}

impl Signer for FileSigner {
    fn actor(&self) -> Actor {
        self.actor.clone()
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        let state = self.vault.state.lock().map_err(|_| failure())?;
        if self.vault.poisoned.load(Ordering::SeqCst) {
            return Err(failure());
        }
        let bytes = state
            .records
            .get(&record_name(&self.actor))
            .ok_or_else(failure)?;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| failure())?);
        Ok(SigningKey::from_bytes(&seed)
            .sign(message)
            .to_bytes()
            .to_vec())
    }
}

impl SecretBackend for FileKeystore {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MANIFEST
    }
    fn get(&self, name: &str) -> Result<SecretString, AppError> {
        let name = secret_name(name)?;
        self.with_state(|state| {
            let bytes = state.records.get(&name).ok_or(AppError::SecretMissing)?;
            let scratch = Zeroizing::new(bytes.to_vec());
            let value = std::str::from_utf8(&scratch)
                .map_err(|_| failure())?
                .to_owned();
            Ok(SecretString::from(value))
        })
    }
    fn put(&self, name: &str, secret: &SecretString) -> Result<(), AppError> {
        let name = secret_name(name)?;
        if secret.expose_secret().is_empty() || secret.expose_secret().len() > 4096 {
            return Err(AppError::Policy("invalid module secret length".into()));
        }
        self.with_state(|state| {
            let old = state.records.insert(
                name.clone(),
                Zeroizing::new(secret.expose_secret().as_bytes().to_vec()),
            );
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.remove(&name);
                    if let Some(old) = old {
                        state.records.insert(name, old);
                    }
                }
                return Err(error);
            }
            Ok(())
        })
    }
    fn delete(&self, name: &str) -> Result<(), AppError> {
        let name = secret_name(name)?;
        self.with_state(|state| {
            let old = state.records.remove(&name).ok_or(AppError::SecretMissing)?;
            if let Err(error) = persist(&self.vault, state) {
                if !self.vault.poisoned.load(Ordering::SeqCst) {
                    state.records.insert(name, old);
                }
                return Err(error);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{FileKeystore, SecretBackend, SignerBackend};
    use ed25519_dalek::{Signature, VerifyingKey};
    use irmind_domain::Actor;
    use secrecy::{ExposeSecret as _, SecretString};
    use std::fs;

    fn phrase() -> SecretString {
        SecretString::from("a synthetic test passphrase".to_owned())
    }

    #[test]
    fn encrypted_vault_round_trip_and_signature() {
        let home = tempfile::tempdir().unwrap();
        let vault = FileKeystore::open(home.path(), &phrase(), true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(home.path().join("keystore.enc"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        irmind_testkit::signer_backend_contract(&vault).unwrap();
        irmind_testkit::secret_backend_contract(&vault).unwrap();
        let signer = vault.load(Actor::Analyst).unwrap();
        let public: [u8; 32] = signer.public_key().try_into().unwrap();
        let signature: [u8; 64] = signer.sign(b"synthetic case").unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify_strict(b"synthetic case", &Signature::from_bytes(&signature))
            .unwrap();
        vault
            .put(
                "SYNTHETIC_API_KEY",
                &SecretString::from("top-secret".to_owned()),
            )
            .unwrap();
        assert!(!format!("{vault:?}").contains("top-secret"));
        drop(signer);
        drop(vault);
        let reopened = FileKeystore::open(home.path(), &phrase(), false).unwrap();
        assert_eq!(
            reopened.public_key_for_actor(&Actor::Analyst).unwrap(),
            public
        );
        assert_eq!(
            reopened.get("SYNTHETIC_API_KEY").unwrap().expose_secret(),
            "top-secret"
        );
        assert!(reopened.get("MISSING_KEY").is_err());
        reopened.delete("SYNTHETIC_API_KEY").unwrap();
        assert!(reopened.get("SYNTHETIC_API_KEY").is_err());
    }

    #[test]
    fn wrong_phrase_and_tampering_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            FileKeystore::open(home.path(), &SecretString::from("short".to_owned()), true).is_err()
        );
        drop(FileKeystore::open(home.path(), &phrase(), true).unwrap());
        let wrong = SecretString::from("wrong passphrase".to_owned());
        assert!(FileKeystore::open(home.path(), &wrong, false).is_err());
        let path = home.path().join("keystore.enc");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_store_refuses_a_symbolic_link() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("keystore.enc")).unwrap();
        assert!(FileKeystore::open(home.path(), &phrase(), true).is_err());
    }

    #[test]
    fn unsafe_parameters_and_unknown_version_fail_before_kdf() {
        let home = tempfile::tempdir().unwrap();
        drop(FileKeystore::open(home.path(), &phrase(), true).unwrap());
        let path = home.path().join("keystore.enc");
        let original = fs::read(&path).unwrap();
        let mut weak = original.clone();
        weak[5..9].copy_from_slice(&1024u32.to_be_bytes());
        fs::write(&path, weak).unwrap();
        assert!(
            FileKeystore::open(home.path(), &phrase(), false)
                .unwrap_err()
                .to_string()
                .contains("unsafe")
        );
        let mut future = original;
        future[4] = 255;
        fs::write(&path, future).unwrap();
        assert!(
            FileKeystore::open(home.path(), &phrase(), false)
                .unwrap_err()
                .to_string()
                .contains("version")
        );
    }

    #[test]
    fn changing_phrase_reencrypts_without_changing_identity() {
        let home = tempfile::tempdir().unwrap();
        let vault = FileKeystore::open(home.path(), &phrase(), true).unwrap();
        let original = vault.create(Actor::Analyst).unwrap().public_key();
        let replacement = SecretString::from("new synthetic passphrase".to_owned());
        vault.change_passphrase(&replacement).unwrap();
        drop(vault);
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_err());
        let unlocked = FileKeystore::open(
            home.path(),
            &SecretString::from("new synthetic passphrase".to_owned()),
            false,
        )
        .unwrap();
        assert_eq!(
            unlocked.public_key_for_actor(&Actor::Analyst).unwrap(),
            original
        );
    }

    #[test]
    fn second_session_cannot_unlock_the_same_store_concurrently() {
        let home = tempfile::tempdir().unwrap();
        let first = FileKeystore::open(home.path(), &phrase(), true).unwrap();
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_err());
        drop(first);
        assert!(FileKeystore::open(home.path(), &phrase(), false).is_ok());
    }

    #[test]
    fn signing_identity_moves_in_encrypted_one_use_packet() {
        let source_home = tempfile::tempdir().unwrap();
        let target_home = tempfile::tempdir().unwrap();
        let source = FileKeystore::open(source_home.path(), &phrase(), true).unwrap();
        let target = FileKeystore::open(target_home.path(), &phrase(), true).unwrap();
        let original = source.create(Actor::Analyst).unwrap().public_key();
        let recipient = target.migration_recipient(&Actor::Analyst).unwrap();
        let packet = source.export_wrapped(&Actor::Analyst, &recipient).unwrap();
        assert!(!packet.windows(32).any(|part| part == original.as_slice()));
        target.import_wrapped(Actor::Analyst, &packet).unwrap();
        assert_eq!(target.load(Actor::Analyst).unwrap().public_key(), original);
        let agent = Actor::parse_storage("agent:synthetic").unwrap();
        let agent_public = source.create(agent.clone()).unwrap().public_key();
        let agent_recipient = target.migration_recipient(&agent).unwrap();
        let agent_packet = source.export_wrapped(&agent, &agent_recipient).unwrap();
        target.import_wrapped(agent.clone(), &agent_packet).unwrap();
        assert_eq!(target.load(agent).unwrap().public_key(), agent_public);
        assert_ne!(agent_public, original);
        assert!(target.import_wrapped(Actor::Analyst, &packet).is_err());
        assert!(target.migration_recipient(&Actor::Analyst).is_err());
    }
}
