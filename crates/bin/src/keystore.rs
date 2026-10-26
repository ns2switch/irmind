use anyhow::{Context as _, Result, anyhow};
use irmind_app::{SecretBackend, Signer, SignerBackend, hex, sha256};
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
    let parsed: Configuration = toml::from_str(&source).context("parse keystore configuration")?;
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
        Err(anyhow!("OS keyring backend was not compiled"))
    }
}

#[cfg(feature = "keystore-file")]
fn file_backend(home: &Path, fd: Option<u32>, create: bool) -> Result<FilePorts> {
    let backend = Arc::new(FileKeystore::open(home, &read_passphrase(fd)?, create)?);
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
) -> Result<ActiveKeystore> {
    #[cfg(not(feature = "keystore-file"))]
    let _ = (home, fd);
    #[cfg(feature = "keystore-file")]
    let (file, file_admin) = if selection.signer == "file" || selection.secrets == "file" {
        let (signer, secrets, admin) = file_backend(
            home,
            fd,
            allow_create && !home.join("keystore.enc").exists(),
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
    if let Some(selection) = &configured {
        match activate(home, selection, fd, false, has_cases) {
            Ok(active) => return Ok(active),
            Err(error) if !interactive => return Err(error),
            Err(error) => {
                let reason = format!(
                    "Configured backend unavailable: {error}. Select explicitly to change it."
                );
                let choice = irmind_tui::choose_keystore(
                    &reason,
                    os_backend().is_ok(),
                    cfg!(feature = "keystore-file"),
                )?
                .ok_or_else(|| anyhow!("keystore setup cancelled"))?;
                let mut revised = Selection {
                    signer: choice.signer.into(),
                    secrets: choice.secrets.into(),
                    analyst_key_fingerprint: selection.analyst_key_fingerprint.clone(),
                };
                let active = activate(home, &revised, fd, true, has_cases)?;
                revised.analyst_key_fingerprint = Some(hex(&sha256(&active.signer.public_key())));
                write_config(home, &revised)?;
                return Ok(active);
            }
        }
    }
    if !interactive {
        return Err(anyhow!(
            "keystore backend is not configured; run irmind interactively first"
        ));
    }
    let choice = irmind_tui::choose_keystore(
        "Select signer and secret backends. No backend is chosen automatically.",
        os_backend().is_ok(),
        cfg!(feature = "keystore-file"),
    )?
    .ok_or_else(|| anyhow!("keystore setup cancelled"))?;
    let mut selection = Selection {
        signer: choice.signer.into(),
        secrets: choice.secrets.into(),
        analyst_key_fingerprint: None,
    };
    let active = activate(home, &selection, fd, true, has_cases)?;
    selection.analyst_key_fingerprint = Some(hex(&sha256(&active.signer.public_key())));
    write_config(home, &selection)?;
    Ok(active)
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
