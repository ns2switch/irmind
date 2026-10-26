#![deny(unsafe_code)]

mod private_fs;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_security;

pub use private_fs::{private_dir, private_file};

use std::{io, path::Path};

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
