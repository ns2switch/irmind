#![forbid(unsafe_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, KeystoreCapability, KeystoreManifest, SecretBackend, Signer, SignerBackend,
};
use irmind_domain::Actor;
use irmind_keystore_transfer::{KeyImportSession, wrap_signing_seed};
use secrecy::SecretString;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

pub const MANIFEST: KeystoreManifest = KeystoreManifest {
    id: "os",
    capabilities: &[KeystoreCapability::Signer, KeystoreCapability::Secrets],
    interactive_unlock: false,
    headless: false,
    network: false,
    config_fields: &[],
};

pub struct OsKeystore {
    entries: Mutex<BTreeMap<(String, String), Arc<keyring::Entry>>>,
    imports: Mutex<BTreeMap<String, KeyImportSession>>,
}

impl OsKeystore {
    pub fn probe() -> Result<Self, AppError> {
        let backend = Self {
            entries: Mutex::new(BTreeMap::new()),
            imports: Mutex::new(BTreeMap::new()),
        };
        let entry = backend.entry("irmind", "local-analyst")?;
        match entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(backend),
            Err(_) => Err(unavailable()),
        }
    }

    fn entry(&self, service: &str, name: &str) -> Result<Arc<keyring::Entry>, AppError> {
        let key = (service.to_owned(), name.to_owned());
        let mut entries = self.entries.lock().map_err(|_| unavailable())?;
        if let Some(entry) = entries.get(&key) {
            return Ok(Arc::clone(entry));
        }
        let entry = Arc::new(keyring::Entry::new(service, name).map_err(|_| unavailable())?);
        entries.insert(key, Arc::clone(&entry));
        Ok(entry)
    }

    fn load_key(&self, actor: &Actor) -> Result<SigningKey, AppError> {
        let entry = self.entry("irmind", &account(actor))?;
        let key = signing_key_from_entry(&entry)?;
        if matches!(actor, Actor::Agent(_))
            && let Ok(analyst) = self.load_key(&Actor::Analyst)
            && key.verifying_key() == analyst.verifying_key()
        {
            return Err(AppError::Signature(
                "agent and analyst keys must differ".into(),
            ));
        }
        Ok(key)
    }
}

struct OsSigner {
    entry: Arc<keyring::Entry>,
    actor: Actor,
    public_key: Vec<u8>,
}

fn signing_key_from_entry(entry: &keyring::Entry) -> Result<SigningKey, AppError> {
    let value = Zeroizing::new(entry.get_password().map_err(|_| unavailable())?);
    let bytes = Zeroizing::new(hex::decode(value.as_bytes()).map_err(|_| unavailable())?);
    let seed = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| unavailable())?);
    Ok(SigningKey::from_bytes(&seed))
}

fn unavailable() -> AppError {
    AppError::Storage("system keyring unavailable".into())
}

fn account(actor: &Actor) -> String {
    match actor {
        Actor::Analyst => "local-analyst".into(),
        Actor::Agent(id) => format!("local-agent-{}", id.as_str()),
    }
}

impl SignerBackend for OsKeystore {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MANIFEST
    }

    fn load(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        let public_key = self.load_key(&actor)?.verifying_key().to_bytes().to_vec();
        Ok(Arc::new(OsSigner {
            entry: self.entry("irmind", &account(&actor))?,
            actor,
            public_key,
        }))
    }

    fn create(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError> {
        let entry = self.entry("irmind", &account(&actor))?;
        match entry.get_password() {
            Ok(_) => return Err(AppError::Policy("signing key already exists".into())),
            Err(keyring::Error::NoEntry) => {}
            Err(_) => return Err(unavailable()),
        }
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let encoded = Zeroizing::new(hex::encode(key.to_bytes()));
        entry.set_password(&encoded).map_err(|_| unavailable())?;
        let loaded = self.load_key(&actor)?;
        if loaded.verifying_key() != key.verifying_key() {
            return Err(AppError::Signature(
                "signing key changed during creation".into(),
            ));
        }
        Ok(Arc::new(OsSigner {
            entry,
            actor,
            public_key: key.verifying_key().to_bytes().to_vec(),
        }))
    }

    fn public_key_for_actor(&self, actor: &Actor) -> Result<Vec<u8>, AppError> {
        Ok(self.load_key(actor)?.verifying_key().to_bytes().to_vec())
    }

    fn migration_recipient(&self, actor: &Actor) -> Result<[u8; 32], AppError> {
        let entry = self.entry("irmind", &account(actor))?;
        if !matches!(entry.get_password(), Err(keyring::Error::NoEntry)) {
            return Err(AppError::Policy(
                "destination signing key already exists or is unavailable".into(),
            ));
        }
        let session = KeyImportSession::new();
        let recipient = session.recipient();
        self.imports
            .lock()
            .map_err(|_| unavailable())?
            .insert(actor.as_storage(), session);
        Ok(recipient)
    }

    fn export_wrapped(&self, actor: &Actor, recipient: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        let seed = Zeroizing::new(self.load_key(actor)?.to_bytes());
        wrap_signing_seed(actor, &seed, recipient)
    }

    fn import_wrapped(&self, actor: Actor, packet: &[u8]) -> Result<(), AppError> {
        let session = self
            .imports
            .lock()
            .map_err(|_| unavailable())?
            .remove(&actor.as_storage())
            .ok_or_else(unavailable)?;
        let seed = session.unwrap(&actor, packet)?;
        if matches!(actor, Actor::Agent(_))
            && let Ok(analyst) = self.load_key(&Actor::Analyst)
            && SigningKey::from_bytes(&seed).verifying_key() == analyst.verifying_key()
        {
            return Err(AppError::Signature(
                "agent and analyst keys must differ".into(),
            ));
        }
        let entry = self.entry("irmind", &account(&actor))?;
        if !matches!(entry.get_password(), Err(keyring::Error::NoEntry)) {
            return Err(AppError::Policy(
                "destination signing key already exists or is unavailable".into(),
            ));
        }
        let encoded = Zeroizing::new(hex::encode(*seed));
        entry.set_password(&encoded).map_err(|_| unavailable())?;
        if self.load_key(&actor)?.verifying_key() != SigningKey::from_bytes(&seed).verifying_key() {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl Signer for OsSigner {
    fn actor(&self) -> Actor {
        self.actor.clone()
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        let key = signing_key_from_entry(&self.entry)?;
        if key.verifying_key().to_bytes().as_slice() != self.public_key {
            return Err(AppError::Signature(
                "OS signing key changed during session".into(),
            ));
        }
        Ok(key.sign(message).to_bytes().to_vec())
    }
}

impl SecretBackend for OsKeystore {
    fn manifest(&self) -> &'static KeystoreManifest {
        &MANIFEST
    }
    fn get(&self, name: &str) -> Result<SecretString, AppError> {
        let entry = self.entry("irmind-module", name)?;
        let value = entry.get_password().map_err(|error| match error {
            keyring::Error::NoEntry => AppError::SecretMissing,
            _ => unavailable(),
        })?;
        if value.is_empty() {
            return Err(AppError::Storage("module secret is empty".into()));
        }
        Ok(SecretString::from(value))
    }
    fn put(&self, name: &str, secret: &SecretString) -> Result<(), AppError> {
        use secrecy::ExposeSecret as _;
        if secret.expose_secret().is_empty() {
            return Err(AppError::Policy("empty module secret".into()));
        }
        self.entry("irmind-module", name)?
            .set_password(secret.expose_secret())
            .map_err(|_| unavailable())
    }
    fn delete(&self, name: &str) -> Result<(), AppError> {
        self.entry("irmind-module", name)?
            .delete_credential()
            .map_err(|_| unavailable())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::OsKeystore;
    use ed25519_dalek::SigningKey;
    use irmind_app::SignerBackend;
    use irmind_domain::Actor;
    use irmind_mod_keystore_file::FileKeystore;
    use secrecy::SecretString;

    #[test]
    fn os_backend_passes_shared_contracts_with_mock_keyring() {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let backend = OsKeystore::probe().unwrap();
        irmind_testkit::signer_backend_contract(&backend).unwrap();
        irmind_testkit::secret_backend_contract(&backend).unwrap();
    }

    #[test]
    fn signing_key_moves_from_file_to_mock_os_keyring_without_changing_public_key() {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let home = tempfile::tempdir().unwrap();
        let file = FileKeystore::open(
            home.path(),
            &SecretString::from("synthetic transfer phrase".to_owned()),
            true,
        )
        .unwrap();
        let original = file.create(Actor::Analyst).unwrap().public_key();
        let os = OsKeystore::probe().unwrap();
        let recipient = os.migration_recipient(&Actor::Analyst).unwrap();
        let packet = file.export_wrapped(&Actor::Analyst, &recipient).unwrap();
        os.import_wrapped(Actor::Analyst, &packet).unwrap();
        assert_eq!(os.public_key_for_actor(&Actor::Analyst).unwrap(), original);
    }

    #[test]
    fn signer_refuses_a_keyring_entry_replaced_mid_session() {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let os = OsKeystore::probe().unwrap();
        let signer = os.create(Actor::Analyst).unwrap();
        let replacement = SigningKey::from_bytes(&[77u8; 32]);
        os.entry("irmind", "local-analyst")
            .unwrap()
            .set_password(&hex::encode(replacement.to_bytes()))
            .unwrap();
        assert!(signer.sign(b"synthetic case").is_err());
    }
}
