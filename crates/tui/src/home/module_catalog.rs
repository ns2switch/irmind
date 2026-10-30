use crate::{ModuleKind, ModuleStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DisplayStatus {
    Active,
    Disabled,
    Missing,
    NotCompiled,
}

impl DisplayStatus {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Missing => "missing configuration",
            Self::NotCompiled => "not compiled",
        }
    }
}

pub(super) fn status(module: &ModuleStatus) -> DisplayStatus {
    if !module.compiled {
        DisplayStatus::NotCompiled
    } else if module.selected && !module.enabled {
        DisplayStatus::Missing
    } else if module.selected || module.kind == ModuleKind::Local && module.enabled {
        DisplayStatus::Active
    } else {
        DisplayStatus::Disabled
    }
}

pub(super) fn label(id: &str) -> &'static str {
    match id {
        "llm-openai-compatible" => "OpenAI-compatible / Ollama",
        "llm-anthropic" => "Anthropic",
        "llm-deepseek" => "DeepSeek",
        "llm-openrouter" => "OpenRouter",
        "siem-splunk" => "Splunk",
        "edr-crowdstrike" => "CrowdStrike",
        "edr-sentinelone" => "SentinelOne",
        "cloud-aws" => "AWS CloudTrail",
        "ti-misp" => "MISP",
        "ti-virustotal" => "VirusTotal",
        "storage-s3" => "Amazon S3",
        "storage-gcs" => "Google Cloud Storage",
        "storage-azure" => "Azure Blob Storage",
        "keystore-os" => "System keychain",
        "keystore-file" => "Encrypted file",
        "parser-json" => "JSON parser",
        _ => "Other module",
    }
}

pub(super) fn group(id: &str) -> &'static str {
    if id.starts_with("llm-") {
        "AI model"
    } else if id.starts_with("siem-") {
        "SIEM"
    } else if id.starts_with("edr-") {
        "EDR"
    } else if id.starts_with("cloud-") {
        "Cloud"
    } else if id.starts_with("ti-") {
        "Threat intel"
    } else if id.starts_with("storage-") {
        "Storage"
    } else if id.starts_with("keystore-") {
        "Keystore"
    } else {
        "Local"
    }
}

fn group_rank(group: &str) -> usize {
    [
        "AI model",
        "SIEM",
        "EDR",
        "Cloud",
        "Threat intel",
        "Storage",
        "Keystore",
        "Local",
    ]
    .iter()
    .position(|value| *value == group)
    .unwrap_or(8)
}

pub(super) fn ordered(modules: &[ModuleStatus]) -> Vec<(usize, &ModuleStatus)> {
    let mut rows = modules.iter().enumerate().collect::<Vec<_>>();
    rows.sort_by_key(|(_, module)| (group_rank(group(&module.id)), label(&module.id), &module.id));
    rows
}

pub(super) fn selected_row(modules: &[ModuleStatus], selected: usize) -> usize {
    let mut position = 0;
    let mut last_group = "";
    for (index, module) in ordered(modules) {
        let current_group = group(&module.id);
        if current_group != last_group {
            position += 1;
            last_group = current_group;
        }
        if index == selected {
            return position;
        }
        position += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{DisplayStatus, group, label};

    #[test]
    fn module_catalog_has_readable_names_and_expected_groups() {
        assert_eq!(label("storage-gcs"), "Google Cloud Storage");
        assert_eq!(group("storage-gcs"), "Storage");
        assert_eq!(group("llm-anthropic"), "AI model");
        assert_eq!(DisplayStatus::Missing.label(), "missing configuration");
    }
}
