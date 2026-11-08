#![forbid(unsafe_code)]
//! Build-time mapping identity. No environment values or absolute paths enter the output.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub fn emit_native_mapping_manifest(production_features: &[&str]) -> io::Result<()> {
    let module = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(invalid)?);
    let root = module.ancestors().nth(3).ok_or_else(invalid)?;
    let features = production_features
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect();
    let output = manifest(root, &module, features)?;
    let target = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(invalid)?);
    fs::write(target.join("native-mapping-manifest.bin"), output)
}

fn manifest(root: &Path, module: &Path, mut features: Vec<String>) -> io::Result<Vec<u8>> {
    let mut files = Vec::new();
    for directory in [
        module.to_path_buf(),
        root.join("crates/app"),
        root.join("crates/domain"),
        root.join("crates/build-manifest"),
    ] {
        files.push(directory.join("Cargo.toml"));
        if directory.join("build.rs").exists() {
            files.push(directory.join("build.rs"));
        }
        collect(&directory.join("src"), &mut files)?;
    }
    files.push(root.join("Cargo.toml"));
    files.push(root.join("Cargo.lock"));
    let mut files = files
        .into_iter()
        .map(|file| {
            let relative = file.strip_prefix(root).map_err(|_| invalid())?;
            let logical = relative
                .components()
                .map(|c| c.as_os_str().to_str().ok_or_else(invalid))
                .collect::<io::Result<Vec<_>>>()?
                .join("/");
            Ok((logical, file))
        })
        .collect::<io::Result<Vec<_>>>()?;
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    files.dedup_by(|a, b| a.0 == b.0);
    features.sort();
    features.dedup();
    let mut bytes = b"irmind-native-mapping-build-v1\0".to_vec();
    bytes.extend_from_slice(&(features.len() as u64).to_be_bytes());
    for feature in features {
        put(&mut bytes, feature.as_bytes());
    }
    bytes.extend_from_slice(&(files.len() as u64).to_be_bytes());
    for (relative, file) in files {
        put(&mut bytes, relative.as_bytes());
        bytes.extend_from_slice(&hash_file(&file)?);
        println!("cargo:rerun-if-changed={}", file.display());
    }
    if bytes.len() > 64 * 1024 {
        return Err(invalid());
    }
    Ok(bytes)
}
fn collect(root: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    println!("cargo:rerun-if-changed={}", root.display());
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            return Err(invalid());
        }
        if kind.is_dir() {
            collect(&path, files)?;
        } else if kind.is_file() {
            files.push(path);
        }
    }
    Ok(())
}
fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid());
    }
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buffer[..count]);
    }
}
fn put(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}
fn invalid() -> io::Error {
    io::Error::other("cannot construct the canonical native mapping build manifest")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
