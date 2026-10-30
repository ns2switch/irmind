use anyhow::{Result, anyhow};
use irmind_domain::CaseId;
use std::{fs, io::Write as _, path::Path};

const NAME: &str = "last-case";

pub(super) fn load(home: &Path) -> Result<Option<CaseId>> {
    let path = home.join(NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(anyhow!("cannot inspect recent case reference")),
    };
    if !metadata.is_file() || metadata.len() > 64 {
        return Err(anyhow!("recent case reference is invalid"));
    }
    irmind_fs::private_file(&path)
        .map_err(|_| anyhow!("recent case reference is not a private regular file"))?;
    let text =
        fs::read_to_string(&path).map_err(|_| anyhow!("cannot read recent case reference"))?;
    CaseId::parse(text.trim())
        .map(Some)
        .map_err(|_| anyhow!("recent case reference contains an invalid case ID"))
}

pub(super) fn save(home: &Path, id: &CaseId) -> Result<()> {
    let destination = home.join(NAME);
    for index in 0..16 {
        let temporary = home.join(format!("{NAME}.tmp.{}.{index}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(anyhow!("cannot create recent case reference")),
        };
        let result = (|| -> Result<()> {
            irmind_fs::private_file(&temporary)?;
            writeln!(file, "{}", id.as_str())?;
            file.sync_all()?;
            irmind_fs::durable_replace(&temporary, &destination)?;
            irmind_fs::sync_directory(home)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        return result.map_err(|_| anyhow!("cannot save recent case reference"));
    }
    Err(anyhow!("cannot reserve recent case reference"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{load, save};
    use irmind_domain::CaseId;

    #[test]
    fn recent_case_reference_is_private_and_replaces_atomically() {
        let root = tempfile::tempdir().unwrap();
        let first = CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap();
        let second = CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap();
        assert_eq!(load(root.path()).unwrap(), None);
        save(root.path(), &first).unwrap();
        assert_eq!(load(root.path()).unwrap(), Some(first));
        save(root.path(), &second).unwrap();
        assert_eq!(load(root.path()).unwrap(), Some(second));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(root.path().join("last-case"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        #[cfg(windows)]
        irmind_fs::private_file(&root.path().join("last-case")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recent_case_reference_does_not_follow_a_symlink() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("target"),
            "00000000-0000-0000-0000-000000000001",
        )
        .unwrap();
        symlink(root.path().join("target"), root.path().join("last-case")).unwrap();
        assert!(load(root.path()).is_err());
    }
}
