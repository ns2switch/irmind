use std::fs;
use std::path::Path;

pub(crate) fn private_dir(path: &Path) -> std::io::Result<()> {
    refuse_link(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        crate::windows_security::private_windows(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported ACL platform",
        ))
    }
}

pub fn private_file(path: &Path) -> std::io::Result<()> {
    refuse_link(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        crate::windows_security::private_windows(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported ACL platform",
        ))
    }
}

fn refuse_link(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private data path is a symbolic link",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private data path is a reparse point",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn private_paths_are_restricted() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("private");
        fs::create_dir(&dir).unwrap();
        private_dir(&dir).unwrap();
        let file = dir.join("case.json");
        fs::write(&file, b"synthetic").unwrap();
        private_file(&file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        #[cfg(windows)]
        {
            for path in [&dir, &file] {
                crate::windows_security::verify_private(path).unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_paths_refuse_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::write(&target, b"synthetic").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(private_file(&link).is_err());
    }
}
