use super::{ConfigurationStore, Engine, Result, anyhow, configuration};
use irmind_app::{ContentGuard, modules::ModuleManifest};
use std::path::Path;

fn configuration_file_present(home: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(home.join("config.toml")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(anyhow!("cannot inspect config.toml; no case was opened")),
    }
}

pub(super) fn reconcile_configuration(
    engine: &Engine<'_>,
    store: &dyn ConfigurationStore,
    manifests: &[&ModuleManifest],
    home: &Path,
    interactive: bool,
    guard: &dyn ContentGuard,
) -> Result<bool> {
    let present = configuration_file_present(home)?;
    let inspection = engine.inspect_configuration(store, manifests, present)?;
    let irmind_app::ConfigurationInspection::Review(review) = inspection else {
        return Ok(true);
    };
    if !interactive {
        return Err(anyhow!(
            "config.toml differs from the signed version; run irmind without a subcommand to review or restore it"
        ));
    }
    match irmind_tui::resolve_configuration_review(&review, guard)? {
        irmind_tui::ConfigurationRecoveryChoice::Restore => {
            engine.restore_approved_configuration(store, manifests, present)?;
        }
        irmind_tui::ConfigurationRecoveryChoice::Accept => {
            engine.accept_current_configuration(store, manifests, present, true)?;
        }
        irmind_tui::ConfigurationRecoveryChoice::Quit => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decide_overrides(
    engine: &Engine<'_>,
    store: &dyn ConfigurationStore,
    manifests: &[&ModuleManifest],
    overrides: &[configuration::EgressOverride],
    interactive: bool,
    guard: &dyn ContentGuard,
) -> Result<bool> {
    if overrides.is_empty() {
        return Ok(true);
    }
    let accepted = if interactive {
        let rows = overrides
            .iter()
            .map(|item| irmind_tui::OverrideReviewEntry {
                field: item.field.clone(),
                saved: item.saved.clone(),
                effective: item.effective.clone(),
            })
            .collect::<Vec<_>>();
        irmind_tui::resolve_override_review(&rows, guard)?
    } else {
        true
    };
    if accepted {
        let changes = overrides
            .iter()
            .map(|item| {
                item.change.clone().ok_or_else(|| {
                    anyhow!("invalid session override; reject it in the TUI or correct the value")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        engine.record_session_overrides(store, manifests, &changes)?;
    }
    Ok(accepted)
}
