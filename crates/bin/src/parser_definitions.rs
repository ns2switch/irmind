use anyhow::{Result, anyhow};
use std::{io::Read as _, path::Path};

pub(super) fn clean_temporaries(engine: &irmind_app::Engine<'_>, home: &Path) {
    match engine.clean_definition_temporary(&irmind_infra::FileDefinitionStore::new(home)) {
        Ok(removed) if removed > 0 => {
            tracing::info!(target: "irmind::operations", removed, "removed orphan parser definition temporary files");
        }
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(target: "irmind::operations", "parser definition storage is unavailable; inspect /parsers");
        }
    }
}

#[cfg(feature = "parser-declarative")]
pub(super) fn register(
    mut registry: irmind_app::modules::ModuleRegistry,
    definitions: &irmind_app::ApprovedDefinitions,
    home: &Path,
) -> Result<irmind_app::modules::ModuleRegistry> {
    let (active, _) = definitions.load_active(
        &irmind_infra::FileDefinitionStore::new(home),
        &irmind_mod_parser_declarative::DeclarativeCompiler,
    );
    registry.register(
        Box::new(irmind_mod_parser_declarative::DeclarativeModule::new(
            active,
        )?),
        &irmind_app::modules::ModuleConfig::new(),
    )?;
    Ok(registry)
}

pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if limit == 0 || limit > 1024 * 1024 {
        return Err(anyhow!("parser input byte limit is invalid"));
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("parser input has no file name"))?;
    let file = irmind_fs::open_regular_no_follow(parent, Path::new(name))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(anyhow!(
            "parser input exceeds the preview byte limit; select a small sample"
        ));
    }
    Ok(bytes)
}
