#![forbid(unsafe_code)]
//! Build-time mapping identity. No environment values or absolute paths enter the output.
use sha2::{Digest, Sha256};

const INPUT_DIRECTORY: &str = "IRMIND_NATIVE_MAPPING_MANIFEST_DIR";
const REQUIRE_V2: &str = "IRMIND_NATIVE_MAPPING_REQUIRE_V2";
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub fn emit_native_mapping_manifest(production_features: &[&str]) -> io::Result<()> {
    emit_native_mapping_manifest_with_sources(production_features, &[])
}

/// Include shared mapping implementation crates in the same canonical build identity.
pub fn emit_native_mapping_manifest_with_sources(
    production_features: &[&str],
    shared_sources: &[&str],
) -> io::Result<()> {
    let module = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(invalid)?);
    let root = module.ancestors().nth(3).ok_or_else(invalid)?;
    let name = std::env::var("CARGO_PKG_NAME").map_err(|_| invalid())?;
    if name.starts_with("irmind-mod-mapping-") {
        println!("cargo:rerun-if-env-changed={INPUT_DIRECTORY}");
        println!("cargo:rerun-if-env-changed={REQUIRE_V2}");
        if let Some(directory) = std::env::var_os(INPUT_DIRECTORY) {
            return install_prepared(&name, Path::new(&directory));
        }
        if std::env::var_os(REQUIRE_V2).is_some() {
            return Err(io::Error::other(
                "release build requires prepared V2 native mapping inputs",
            ));
        }
    }
    let features = production_features
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect();
    let output = manifest_with_sources(root, &module, features, shared_sources)?;
    let target = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(invalid)?);
    fs::write(target.join("native-mapping-manifest.bin"), output)
}

fn install_prepared(name: &str, directory: &Path) -> io::Result<()> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid());
    }
    let path = directory.join(format!("{name}.bin"));
    println!("cargo:rerun-if-changed={}", path.display());
    let mut input = fs::File::open(&path)?.take(64 * 1024 + 1);
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 || !bytes.starts_with(b"irmind-native-mapping-build-v2\0") {
        return Err(invalid());
    }
    let target = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(invalid)?);
    fs::write(target.join("native-mapping-manifest.bin"), bytes)
}

#[cfg(test)]
fn manifest(root: &Path, module: &Path, features: Vec<String>) -> io::Result<Vec<u8>> {
    manifest_with_sources(root, module, features, &[])
}

fn manifest_with_sources(
    root: &Path,
    module: &Path,
    mut features: Vec<String>,
    shared_sources: &[&str],
) -> io::Result<Vec<u8>> {
    let files = source_files(root, module, shared_sources)?;
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
fn source_files(root: &Path, module: &Path, shared_sources: &[&str]) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut directories = vec![
        module.to_path_buf(),
        root.join("crates/app"),
        root.join("crates/mapping-contracts"),
        root.join("crates/domain"),
        root.join("crates/build-manifest"),
    ];
    for relative in shared_sources {
        let path = Path::new(relative);
        if path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(invalid());
        }
        directories.push(root.join(path));
    }
    for directory in directories {
        files.push(directory.join("Cargo.toml"));
        if directory.join("build.rs").exists() {
            files.push(directory.join("build.rs"));
        }
        collect(&directory.join("src"), &mut files)?;
    }
    files.push(root.join("Cargo.toml"));
    files.push(root.join("Cargo.lock"));
    Ok(files)
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
