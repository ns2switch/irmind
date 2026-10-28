#![deny(unsafe_code)]

mod private_fs;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_security;

pub use private_fs::{private_dir, private_file};

use std::{
    fs, io,
    path::{Component, Path},
};

/// Opens a regular file below an analyst-selected root without following
/// symlinks in the selected path. A second content hash detects concurrent
/// replacement by another process with the same user privileges.
pub fn open_regular_no_follow(root: &Path, relative: &Path) -> io::Result<fs::File> {
    let root_meta = fs::symlink_metadata(root)?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid source root",
        ));
    }
    let mut path = root.to_path_buf();
    let mut count = 0usize;
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid source path",
            ));
        };
        if part.to_string_lossy().contains([':', '\\']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid source path",
            ));
        }
        path.push(part);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink source rejected",
            ));
        }
        count += 1;
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty source path",
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
        let opened = options.open(&path)?;
        if opened.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reparse point rejected",
            ));
        }
        if !opened.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source is not a file",
            ));
        }
        return Ok(opened);
    }
    #[cfg(not(windows))]
    {
        let opened = options.open(path)?;
        if !opened.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source is not a file",
            ));
        }
        Ok(opened)
    }
}

/// Flushes a parent directory after an atomic rename where the platform permits it.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        // MoveFileExW uses MOVEFILE_WRITE_THROUGH; Windows has no directory fsync here.
        let _ = path;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(path)?.sync_all()
    }
}

/// Moves a new file into place without replacing an existing destination.
pub fn durable_rename(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows_security::durable_rename(source, destination)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(source, destination)
    }
}

/// Atomically replaces a file in its private directory.
pub fn durable_replace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows_security::durable_replace(source, destination)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(source, destination)
    }
}
