use crate::{AppError, Signer};
use irmind_domain::Actor;
use secrecy::SecretString;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystoreCapability {
    Signer,
    Secrets,
}

#[derive(Clone, Copy, Debug)]
pub struct KeystoreManifest {
    pub id: &'static str,
    pub capabilities: &'static [KeystoreCapability],
    pub interactive_unlock: bool,
    pub headless: bool,
    pub network: bool,
    pub config_fields: &'static [&'static str],
}

/// A backend owns the private key. Callers receive only a signing capability.
///
/// ```compile_fail
/// use irmind_app::SignerBackend;
/// use irmind_domain::Actor;
/// fn leak(backend: &dyn SignerBackend) {
///     let signer = backend.load(Actor::Analyst).unwrap();
///     let _private = signer.private_key();
/// }
/// ```
pub trait SignerBackend: Send + Sync {
    fn manifest(&self) -> &'static KeystoreManifest;
    fn load(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError>;
    fn create(&self, actor: Actor) -> Result<Arc<dyn Signer>, AppError>;
    fn public_key_for_actor(&self, actor: &Actor) -> Result<Vec<u8>, AppError>;
    /// Starts a one-use encrypted import. The private signing key stays inside a backend.
    fn migration_recipient(&self, actor: &Actor) -> Result<[u8; 32], AppError>;
    fn export_wrapped(&self, actor: &Actor, recipient: &[u8; 32]) -> Result<Vec<u8>, AppError>;
    fn import_wrapped(&self, actor: Actor, packet: &[u8]) -> Result<(), AppError>;
}

/// A missing credential is an error. It never becomes an empty value.
pub trait SecretBackend: Send + Sync {
    fn manifest(&self) -> &'static KeystoreManifest;
    fn get(&self, name: &str) -> Result<SecretString, AppError>;
    fn put(&self, name: &str, secret: &SecretString) -> Result<(), AppError>;
    fn delete(&self, name: &str) -> Result<(), AppError>;
}
