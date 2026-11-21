use anyhow::{Context as _, Result, anyhow};
use irmind_app::{
    AdapterStorageError, AppError, FixedAppError, SecretBackend, Signer, SignerBackend, hex, sha256,
};
use irmind_domain::Actor;
#[cfg(feature = "keystore-file")]
use secrecy::SecretString;
use serde::Deserialize;
#[cfg(feature = "keystore-file")]
use std::io::Read;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "keystore-file")]
use irmind_mod_keystore_file::FileKeystore;
#[derive(Debug)]
pub(super) struct SetupCancelled;

impl std::fmt::Display for SetupCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("keystore setup cancelled by analyst")
    }
}

impl std::error::Error for SetupCancelled {}
#[cfg(feature = "keystore-file")]
type FilePorts = (
    Arc<dyn SignerBackend>,
    Arc<dyn SecretBackend>,
    Arc<FileKeystore>,
);
type BackendPair = (Arc<dyn SignerBackend>, Arc<dyn SecretBackend>);
#[cfg(feature = "keystore-os")]
use irmind_mod_keystore_os::OsKeystore;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    signer: String,
    secrets: String,
    analyst_key_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    keystore: Selection,
}

pub(super) struct ActiveKeystore {
    pub signer_backend: Arc<dyn SignerBackend>,
    pub secret_backend: Arc<dyn SecretBackend>,
    pub signer: Arc<dyn Signer>,
    pub new_analyst_key: bool,
    pub signer_id: String,
    pub secrets_id: String,
    #[cfg(feature = "keystore-file")]
    pub file_backend: Option<Arc<FileKeystore>>,
}

fn config_path(home: &Path) -> PathBuf {
    home.join("keystore.toml")
}

fn read_config(home: &Path) -> Result<Option<Selection>> {
    let path = config_path(home);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect keystore configuration"),
    };
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(anyhow!("invalid keystore configuration file"));
    }
    irmind_fs::private_file(&path).context("restrict keystore configuration")?;
    let source = fs::read_to_string(&path).context("read keystore configuration")?;
    let parsed: Configuration = toml::from_str(&source)
        .map_err(|_| anyhow!("keystore.toml has invalid syntax or unknown fields"))?;
    if !matches!(parsed.keystore.signer.as_str(), "os" | "file")
        || !matches!(parsed.keystore.secrets.as_str(), "os" | "file")
    {
        return Err(anyhow!("unknown configured keystore backend"));
    }
    Ok(Some(parsed.keystore))
}

fn write_config(home: &Path, selection: &Selection) -> Result<()> {
    let path = config_path(home);
    let fingerprint = selection
        .analyst_key_fingerprint
        .as_deref()
        .ok_or_else(|| anyhow!("analyst fingerprint missing"))?;
    let source = format!(
        "[keystore]\nsigner = \"{}\"\nsecrets = \"{}\"\nanalyst_key_fingerprint = \"{fingerprint}\"\n",
        selection.signer, selection.secrets,
    );
    for index in 0..16 {
        let temporary = home.join(format!("keystore.toml.tmp.{}.{index}", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(anyhow!("cannot create private keystore configuration")),
        };
        let result = (|| {
            irmind_fs::private_file(&temporary)?;
            file.write_all(source.as_bytes())?;
            file.sync_all()?;
            irmind_fs::durable_replace(&temporary, &path)?;
            irmind_fs::sync_directory(home)?;
            Ok::<(), anyhow::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        return result;
    }
    Err(anyhow!("cannot reserve keystore configuration path"))
}

#[cfg(feature = "keystore-file")]
fn read_passphrase(fd: Option<u32>) -> Result<SecretString> {
    let value = match fd {
        None => rpassword::prompt_password("Keystore passphrase (input hidden): ")
            .context("read passphrase from terminal")?,
        Some(descriptor) => {
            #[cfg(unix)]
            let input = fs::File::open(format!("/dev/fd/{descriptor}"))
                .context("open passphrase descriptor")?;
            #[cfg(windows)]
            let input: Box<dyn Read> = if descriptor == 0 {
                Box::new(std::io::stdin())
            } else {
                return Err(anyhow!("Windows supports --passphrase-fd 0 only"));
            };
            let mut text = String::new();
            input
                .take(4097)
                .read_to_string(&mut text)
                .context("read passphrase descriptor")?;
            if text.len() > 4096 {
                return Err(anyhow!("passphrase descriptor exceeds 4096 bytes"));
            }
            while text.ends_with(['\r', '\n']) {
                text.pop();
            }
            text
        }
    };
    if value.is_empty() {
        return Err(anyhow!("empty keystore passphrase"));
    }
    Ok(SecretString::from(value))
}

fn os_backend() -> Result<(Arc<dyn SignerBackend>, Arc<dyn SecretBackend>)> {
    #[cfg(feature = "keystore-os")]
    {
        let backend = Arc::new(OsKeystore::probe()?);
        Ok((backend.clone(), backend))
    }
    #[cfg(not(feature = "keystore-os"))]
    {
        Err(AppError::Fixed(FixedAppError::AdapterStorage(
            AdapterStorageError::SystemKeyringUnavailable,
        ))
        .into())
    }
}

#[cfg(feature = "keystore-file")]
fn file_backend(
    home: &Path,
    fd: Option<u32>,
    passphrase: Option<&SecretString>,
    create: bool,
) -> Result<FilePorts> {
    let cli_passphrase;
    let passphrase = if let Some(value) = passphrase {
        value
    } else {
        cli_passphrase = read_passphrase(fd)?;
        &cli_passphrase
    };
    let backend = Arc::new(FileKeystore::open(home, passphrase, create)?);
    Ok((backend.clone(), backend.clone(), backend))
}

fn select_backends(
    selection: &Selection,
    file: Option<&BackendPair>,
    os: Option<&BackendPair>,
) -> Result<BackendPair> {
    let signer = match selection.signer.as_str() {
        "file" => Arc::clone(&file.ok_or_else(|| anyhow!("file backend unavailable"))?.0),
        "os" => Arc::clone(&os.ok_or_else(|| anyhow!("OS backend unavailable"))?.0),
        _ => return Err(anyhow!("unknown signer backend")),
    };
    let secrets = match selection.secrets.as_str() {
        "file" => Arc::clone(&file.ok_or_else(|| anyhow!("file backend unavailable"))?.1),
        "os" => Arc::clone(&os.ok_or_else(|| anyhow!("OS backend unavailable"))?.1),
        _ => return Err(anyhow!("unknown secrets backend")),
    };
    Ok((signer, secrets))
}

fn activate(
    home: &Path,
    selection: &Selection,
    fd: Option<u32>,
    allow_create: bool,
    has_cases: bool,
    passphrase: Option<&SecretString>,
) -> Result<ActiveKeystore> {
    #[cfg(not(feature = "keystore-file"))]
    let _ = (home, fd);
    #[cfg(feature = "keystore-file")]
    let (file, file_admin) = if selection.signer == "file" || selection.secrets == "file" {
        let (signer, secrets, admin) = file_backend(
            home,
            fd,
            passphrase,
            allow_create
                && selection.analyst_key_fingerprint.is_none()
                && !home.join("keystore.enc").exists(),
        )?;
        (Some((signer, secrets)), Some(admin))
    } else {
        (None, None)
    };
    #[cfg(not(feature = "keystore-file"))]
    let file: Option<(Arc<dyn SignerBackend>, Arc<dyn SecretBackend>)> = {
        if selection.signer == "file" || selection.secrets == "file" {
            return Err(anyhow!("encrypted file backend was not compiled"));
        }
        None
    };
    let os = if selection.signer == "os" || selection.secrets == "os" {
        Some(os_backend()?)
    } else {
        None
    };
    let (signer_backend, secret_backend) = select_backends(selection, file.as_ref(), os.as_ref())?;
    let loaded = signer_backend.load(Actor::Analyst);
    let new_analyst_key = loaded.is_err();
    let signer = match loaded {
        Ok(signer) => signer,
        Err(_) if selection.analyst_key_fingerprint.is_some() => {
            return Err(AppError::Fixed(FixedAppError::ConfiguredAnalystSignerUnavailable).into());
        }
        Err(_) if allow_create && !has_cases => signer_backend.create(Actor::Analyst)?,
        Err(error) => return Err(error.into()),
    };
    let fingerprint = hex(&sha256(&signer.public_key()));
    if let Some(expected) = &selection.analyst_key_fingerprint
        && expected != &fingerprint
    {
        return Err(anyhow!(
            "configured signer fingerprint differs from the existing analyst key"
        ));
    }
    Ok(ActiveKeystore {
        signer_backend,
        secret_backend,
        signer,
        new_analyst_key,
        signer_id: selection.signer.clone(),
        secrets_id: selection.secrets.clone(),
        #[cfg(feature = "keystore-file")]
        file_backend: file_admin,
    })
}

pub(super) fn load_or_configure(
    home: &Path,
    fd: Option<u32>,
    interactive: bool,
    has_cases: bool,
) -> Result<ActiveKeystore> {
    let configured = read_config(home)?;
    if interactive {
        return interactive_setup(home, configured.as_ref(), has_cases);
    }
    let selection = configured.ok_or_else(|| {
        anyhow!("keystore backend is not configured; run irmind interactively first")
    })?;
    activate(home, &selection, fd, false, has_cases, None)
}

fn interactive_setup(
    home: &Path,
    configured: Option<&Selection>,
    has_cases: bool,
) -> Result<ActiveKeystore> {
    let configured_choice = configured.map(|selection| irmind_tui::KeystoreChoice {
        signer: if selection.signer == "os" {
            "os"
        } else {
            "file"
        },
        secrets: if selection.secrets == "os" {
            "os"
        } else {
            "file"
        },
    });
    let wizard = irmind_tui::KeystoreWizard::new(
        configured_choice,
        os_backend().is_ok(),
        cfg!(feature = "keystore-file"),
        home.join("keystore.enc").exists(),
    );
    let active = irmind_tui::run_keystore_wizard(wizard, |choice, passphrase| {
        let mut selection = Selection {
            signer: choice.signer.into(),
            secrets: choice.secrets.into(),
            analyst_key_fingerprint: configured
                .and_then(|value| value.analyst_key_fingerprint.clone()),
        };
        match activate(home, &selection, None, true, has_cases, passphrase) {
            Ok(active) => {
                let fingerprint = hex(&sha256(&active.signer.public_key()));
                selection.analyst_key_fingerprint = Some(fingerprint.clone());
                write_config(home, &selection).map_err(|error| setup_error(home, &error))?;
                Ok((fingerprint, active))
            }
            Err(error) => Err(setup_error(home, &error)),
        }
    })?;
    active.ok_or_else(|| anyhow!(SetupCancelled))
}

fn setup_error(home: &Path, error: &anyhow::Error) -> String {
    let detail = format!("{error:#}");
    tracing::error!(target: "irmind::operations", stage = "keystore", causes = %detail, "startup operation failed");
    match error.downcast_ref::<AppError>() {
        Some(AppError::Fixed(FixedAppError::ConfiguredAnalystSignerUnavailable)) =>
            "The configured analyst signing key is missing from this backend. Restore the key or use an explicit migration. IRMind kept the existing key identity.".into(),
        Some(AppError::Fixed(FixedAppError::AdapterStorage(storage))) => match storage {
            AdapterStorageError::EncryptedKeystorePermissionDenied => format!(
                "The vault at {} cannot be accessed with your user permissions. Check ownership and access, then retry.",
                home.join("keystore.enc").display()
            ),
            AdapterStorageError::CannotUnlockEncryptedKeystore => format!(
                "The passphrase is incorrect or the vault at {} is damaged. Retry and restore a known-good vault if the problem persists. Details: {}",
                home.join("keystore.enc").display(),
                home.join("diagnostics.log").display()
            ),
            AdapterStorageError::EncryptedKeystoreOperationFailed => format!(
                "The vault operation failed. Check directory access and free disk space, then retry. Diagnostics: {}",
                home.join("diagnostics.log").display()
            ),
            AdapterStorageError::EncryptedKeystoreIsOpenInAnotherProcess =>
                "The encrypted file is already open in another IRMind process. Close that session, then retry.".into(),
            AdapterStorageError::EncryptedKeystoreNotFound => format!(
                "The configured vault at {} is missing. Restore it or select another backend.",
                home.join("keystore.enc").display()
            ),
            AdapterStorageError::UnknownEncryptedKeystoreVersion =>
                "The vault format is newer than this IRMind build. Upgrade IRMind.".into(),
            AdapterStorageError::EncryptedKeystoreParametersAreUnsafe =>
                "The vault uses weak or invalid encryption parameters. Restore a valid vault.".into(),
            AdapterStorageError::SystemKeyringUnavailable =>
                "The OS keyring is unavailable in this session. Choose the encrypted file backend for SSH.".into(),
            _ => setup_fallback(home),
        },
        _ if error.chain().filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .any(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied) => format!(
                "The data directory {} cannot be accessed with your user permissions. Check ownership and access, then retry.",
                home.display()
            ),
        _ => setup_fallback(home),
    }
}

fn setup_fallback(home: &Path) -> String {
    format!(
        "Keystore setup failed. Retry or choose another backend. Diagnostics: {}",
        home.join("diagnostics.log").display()
    )
}

pub(super) fn select_migrated_backend(
    home: &Path,
    capability: &str,
    target: &str,
    fingerprint: &str,
) -> Result<()> {
    let mut selection = read_config(home)?.ok_or_else(|| anyhow!("keystore is not configured"))?;
    if selection.analyst_key_fingerprint.as_deref() != Some(fingerprint) {
        return Err(anyhow!("analyst fingerprint changed during migration"));
    }
    match capability {
        "signer" => selection.signer = target.into(),
        "secrets" => selection.secrets = target.into(),
        _ => return Err(anyhow!("invalid keystore capability")),
    }
    write_config(home, &selection)
}

#[cfg(all(test, feature = "keystore-file"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn setup_guidance_depends_on_error_types_not_messages() {
        let home = Path::new("synthetic");
        let wrong_text = "cannot unlock encrypted keystore; keyring unavailable";
        let raw = anyhow!(wrong_text);
        assert!(setup_error(home, &raw).starts_with("Keystore setup failed."));
        let missing = anyhow::Error::new(AppError::Fixed(FixedAppError::AdapterStorage(
            AdapterStorageError::EncryptedKeystoreNotFound,
        )))
        .context(wrong_text);
        assert!(setup_error(home, &missing).contains("configured vault"));
        let denied = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "synthetic error text",
        ))
        .context(wrong_text);
        assert!(setup_error(home, &denied).starts_with("The data directory"));
    }

    #[test]
    fn configured_fingerprint_never_creates_a_missing_vault() {
        let home = tempfile::tempdir().unwrap();
        let passphrase = SecretString::from("synthetic test passphrase".to_owned());
        let selection = Selection {
            signer: "file".into(),
            secrets: "file".into(),
            analyst_key_fingerprint: Some("00".repeat(32)),
        };
        let error = activate(
            home.path(),
            &selection,
            None,
            true,
            false,
            Some(&passphrase),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error.downcast_ref::<AppError>(),
            Some(AppError::Fixed(FixedAppError::AdapterStorage(
                AdapterStorageError::EncryptedKeystoreNotFound
            )))
        ));
        assert!(!home.path().join("keystore.enc").exists());
    }

    #[test]
    fn configured_fingerprint_never_creates_a_replacement_key() {
        let home = tempfile::tempdir().unwrap();
        let passphrase = SecretString::from("synthetic test passphrase".to_owned());
        let empty_vault = FileKeystore::open(home.path(), &passphrase, true).unwrap();
        drop(empty_vault);
        let selection = Selection {
            signer: "file".into(),
            secrets: "file".into(),
            analyst_key_fingerprint: Some("00".repeat(32)),
        };
        let error = activate(
            home.path(),
            &selection,
            None,
            true,
            false,
            Some(&passphrase),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error.downcast_ref::<AppError>(),
            Some(AppError::Fixed(
                FixedAppError::ConfiguredAnalystSignerUnavailable
            ))
        ));
        let reopened = FileKeystore::open(home.path(), &passphrase, false).unwrap();
        assert!(reopened.load(Actor::Analyst).is_err());
    }
}
