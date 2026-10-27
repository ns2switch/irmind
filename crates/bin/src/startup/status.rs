use super::{
    BTreeMap, Cli, ModuleRegistry, ModuleStatus, PersistentConfig, RootWorkspaceIo, configuration,
};
use irmind_app::modules::ModulePort;
use irmind_tui::{ModuleKind, ModuleParameter, ModuleSelectionSource};

struct StatusBuilder<'a> {
    registry: &'a ModuleRegistry,
    issues: &'a BTreeMap<&'static str, String>,
    keystore: &'a RootWorkspaceIo,
    saved: &'a PersistentConfig,
    out: Vec<ModuleStatus>,
}

pub(super) fn module_statuses(
    cli: &Cli,
    registry: &ModuleRegistry,
    issues: &BTreeMap<&'static str, String>,
    keystore: &RootWorkspaceIo,
    saved: &PersistentConfig,
) -> Vec<ModuleStatus> {
    let mut builder = StatusBuilder {
        registry,
        issues,
        keystore,
        saved,
        out: vec![ModuleStatus {
            id: "parser-json".into(),
            compiled: true,
            enabled: true,
            configuration: "valid; built-in parser".into(),
            kind: ModuleKind::Local,
            selected: false,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: Vec::new(),
            credentials: Vec::new(),
        }],
    };
    for (id, compiled) in [
        ("keystore-os", cfg!(feature = "keystore-os")),
        ("keystore-file", cfg!(feature = "keystore-file")),
    ] {
        let backend = id.strip_prefix("keystore-").unwrap_or(id);
        let signer = keystore.signer_id == backend;
        let secrets = keystore.secrets_id == backend;
        builder.out.push(ModuleStatus {
            id: id.into(),
            compiled,
            enabled: signer || secrets,
            configuration: format!("signer={signer}, secrets={secrets}"),
            kind: ModuleKind::Keystore,
            selected: signer || secrets,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: Vec::new(),
            credentials: Vec::new(),
        });
    }
    append_product_statuses(cli, &mut builder);
    builder.out
}

fn append_product_statuses(cli: &Cli, builder: &mut StatusBuilder<'_>) {
    append_llm_statuses(cli, builder);
    builder.push(
        "siem-splunk",
        cfg!(feature = "siem-splunk"),
        cli.enable_splunk,
    );
    builder.push("cloud-aws", cfg!(feature = "cloud-aws"), cli.enable_aws);
    builder.push(
        "edr-crowdstrike",
        cfg!(feature = "edr-crowdstrike"),
        cli.enable_crowdstrike,
    );
    builder.push(
        "edr-sentinelone",
        cfg!(feature = "edr-sentinelone"),
        cli.enable_sentinelone,
    );
    builder.push("ti-misp", cfg!(feature = "ti-misp"), cli.enable_misp);
    builder.push(
        "ti-virustotal",
        cfg!(feature = "ti-virustotal"),
        cli.enable_virustotal,
    );
}

fn append_llm_statuses(cli: &Cli, builder: &mut StatusBuilder<'_>) {
    for (id, compiled) in [
        ("llm-openai-compatible", true),
        ("llm-anthropic", cfg!(feature = "llm-anthropic")),
        ("llm-deepseek", cfg!(feature = "llm-deepseek")),
        ("llm-openrouter", cfg!(feature = "llm-openrouter")),
    ] {
        builder.push(id, compiled, cli.llm_module.as_deref() == Some(id));
    }
}

impl StatusBuilder<'_> {
    fn push(&mut self, id: &'static str, compiled: bool, requested: bool) {
        let enabled = self.registry.manifest(id).is_some();
        let configuration = if let Some(issue) = self.issues.get(id) {
            issue.clone()
        } else if enabled {
            "valid".into()
        } else if !compiled {
            "not compiled".into()
        } else if requested {
            "invalid configuration; check required settings and keystore".into()
        } else {
            "disabled".into()
        };
        let manifest = self
            .keystore
            .manifests
            .iter()
            .copied()
            .find(|item| item.id == id);
        let parameters = manifest.map_or_else(Vec::new, |item| {
            item.config
                .iter()
                .filter(|field| !field.secret)
                .map(|field| ModuleParameter {
                    name: field.name.into(),
                    value: configuration::effective_value(
                        id,
                        field.name,
                        self.saved,
                        self.keystore.allow_environment,
                    )
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
                    required: field.required,
                    overridden: (self.keystore.allow_environment
                        && std::env::var_os(field.name).is_some())
                        || self.keystore.module_overrides.contains(id)
                        || (id.starts_with("llm-")
                            && self.keystore.module_overrides.contains("llm")),
                })
                .collect()
        });
        let credentials = manifest.map_or_else(Vec::new, |item| {
            item.config
                .iter()
                .filter(|field| field.secret)
                .map(|field| field.name.into())
                .collect()
        });
        self.out.push(ModuleStatus {
            id: id.into(),
            compiled,
            enabled,
            configuration,
            kind: if manifest.is_some_and(|item| item.ports.contains(&ModulePort::Llm))
                || id.starts_with("llm-")
            {
                ModuleKind::Llm
            } else {
                ModuleKind::Connector
            },
            selected: requested,
            selection_source: if self.keystore.module_overrides.contains(id)
                || (id.starts_with("llm-") && self.keystore.module_overrides.contains("llm"))
            {
                ModuleSelectionSource::Override
            } else {
                ModuleSelectionSource::Persistent
            },
            parameters,
            credentials,
        });
    }
}
