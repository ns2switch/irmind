use super::super::Confirmation;
use super::CaseRuntime;
use anyhow::{Result, bail};
use std::path::PathBuf;

pub(super) fn source_root(prompt: &str) -> Result<Option<PathBuf>> {
    if prompt == "/migrate --v2" {
        return Ok(None);
    }
    let Some(root) = prompt
        .strip_prefix("/migrate --v2 ")
        .filter(|s| !s.trim().is_empty())
    else {
        bail!("use /migrate --v2 [original-source-root]");
    };
    Ok(Some(PathBuf::from(root.trim())))
}
impl CaseRuntime<'_, '_, '_> {
    pub(super) fn migrate_v2_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt != "/migrate --v2" && !prompt.starts_with("/migrate --v2 ") {
            return Ok(false);
        }
        let root = source_root(prompt)?;
        if let Some(Confirmation::Migration(approved, _)) = self.state.confirmed_action.take()
            && approved == prompt
        {
            let workflow = self.workflow();
            let id = self.id;
            self.start_task("Verify sources and migrate artifacts to V2",move |cancel| {
                workflow.migrate_artifacts_v2(id,root.as_deref(),&cancel)
                    .map(|count|format!("Migrated {count} Parquet artifacts to V2; historical artifacts retained"))
            });
        } else {
            let summary = String::from(
                "Migrate this open case to Parquet V2?\nOriginals and every existing artifact are verified first.\nTimestamp precision can improve; historical signatures remain intact.\nNew artifacts and their replacement record are signed atomically.\n1. Cancel  2. Migrate (↑/↓, Enter, or number then Enter)",
            );
            self.state.confirmation_option = 0;
            self.state.confirmation = Some(Confirmation::Migration(prompt.into(), summary));
        }
        Ok(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_v2_migration_selects_a_source_directory() {
        assert!(matches!(source_root("/migrate --v2"), Ok(None)));
        assert_eq!(
            source_root("/migrate --v2 synthetic originals")
                .ok()
                .flatten(),
            Some(PathBuf::from("synthetic originals"))
        );
        assert!(source_root("/migrate --v2 ").is_err());
        assert!(source_root("/migrate").is_err());
    }
}
