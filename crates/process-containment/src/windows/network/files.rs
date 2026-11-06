#![cfg(windows)]
use crate::witness_protocol::{MAX_MESSAGE, denied};
use std::{
    fs,
    io::{self, Read as _},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};
pub(super) fn read(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > MAX_MESSAGE as u64
    {
        return Err(denied());
    }
    let mut bytes = Vec::new();
    file.take(MAX_MESSAGE as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(denied());
    }
    Ok(bytes)
}
#[cfg(feature = "launcher")]
pub(super) fn write(
    path: &Path,
    bytes: &[u8],
    identity: &super::super::process::Identity,
) -> io::Result<()> {
    use std::io::Write as _;
    if bytes.len() > MAX_MESSAGE {
        return Err(denied());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    crate::filesystem::private_windows(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    identity.grant_read(path)
}
