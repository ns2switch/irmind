#![forbid(unsafe_code)]
//! Development-only package validation with the same reader/compiler as `IRMind`.
use anyhow::{Result, anyhow};
use irmind_app::{CancellationToken, SkillCompiler as _, SkillPackageStore as _};
use irmind_infra::{FileSkillPackageStore, TomlSkillCompiler};
use std::path::PathBuf;

fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("usage: validate_skill <skill-directory>"))?;
    let store = FileSkillPackageStore::new(&path);
    let package = store.read_candidate(&path, &CancellationToken::new())?;
    let compiled = TomlSkillCompiler.compile(package)?;
    println!(
        "{} {} {}",
        compiled.metadata().name().as_str(),
        compiled.metadata().version().as_str(),
        irmind_app::hex(compiled.package().hash().as_bytes())
    );
    Ok(())
}
