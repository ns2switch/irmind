use super::{ConfigurationStore, Engine, Result, anyhow};
use irmind_app::{
    ConfigChange,
    modules::{ConfigField, ModuleManifest, ModulePort},
};

// Exact former schema, used only to review and retire approved settings. It is
// never passed to a running module or exposed in the settings editor.
static HISTORICAL: ModuleManifest = ModuleManifest {
    id: "parser-syslog",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[
        ConfigField {
            name: "LEGACY_YEAR",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "LEGACY_UTC_OFFSET_MINUTES",
            required: false,
            secret: false,
        },
    ],
};

pub(super) fn review_manifests<'a>(manifests: &[&'a ModuleManifest]) -> Vec<&'a ModuleManifest> {
    manifests
        .iter()
        .map(|manifest| {
            if manifest.id == HISTORICAL.id {
                &HISTORICAL
            } else {
                *manifest
            }
        })
        .collect()
}

pub(super) fn remove_after_confirmation(
    engine: &Engine<'_>,
    store: &dyn ConfigurationStore,
    manifests: &[&ModuleManifest],
    interactive: bool,
) -> Result<bool> {
    let saved = store.load()?;
    let Some(settings) = saved.modules.get(HISTORICAL.id) else {
        return Ok(true);
    };
    let fields = HISTORICAL
        .config
        .iter()
        .filter(|field| settings.values.contains_key(field.name))
        .map(|field| field.name)
        .collect::<Vec<_>>();
    if fields.is_empty() {
        return Ok(true);
    }
    if !interactive {
        return Err(anyhow!(
            "retired RFC 3164 settings require review; run irmind without a subcommand to remove them and choose time settings for each ingestion"
        ));
    }
    if !irmind_tui::confirm_retired_parser_time_settings()? {
        return Ok(false);
    }
    for field in fields {
        engine.apply_configuration_change(
            store,
            manifests,
            ConfigChange::SetValue {
                module: HISTORICAL.id.into(),
                field: field.into(),
                value: String::new(),
            },
            true,
        )?;
    }
    Ok(true)
}
