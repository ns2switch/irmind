use super::{BTreeMap, Cli, ModuleRegistry, ModuleStatus, RootWorkspaceIo};

pub(super) fn module_statuses(
    cli: &Cli,
    registry: &ModuleRegistry,
    issues: &BTreeMap<&'static str, String>,
    keystore: &RootWorkspaceIo,
) -> Vec<ModuleStatus> {
    let mut out = vec![ModuleStatus {
        id: "parser-json".into(),
        compiled: true,
        enabled: true,
        configuration: "valid; built-in parser".into(),
    }];
    for (id, compiled) in [
        ("keystore-os", cfg!(feature = "keystore-os")),
        ("keystore-file", cfg!(feature = "keystore-file")),
    ] {
        let backend = id.strip_prefix("keystore-").unwrap_or(id);
        let signer = keystore.signer_id == backend;
        let secrets = keystore.secrets_id == backend;
        out.push(ModuleStatus {
            id: id.into(),
            compiled,
            enabled: signer || secrets,
            configuration: format!("signer={signer}, secrets={secrets}"),
        });
    }
    append_product_statuses(cli, registry, issues, &mut out);
    out
}

fn append_product_statuses(
    cli: &Cli,
    registry: &ModuleRegistry,
    issues: &BTreeMap<&'static str, String>,
    out: &mut Vec<ModuleStatus>,
) {
    append_llm_statuses(cli, registry, issues, out);
    push_status(
        "siem-splunk",
        cfg!(feature = "siem-splunk"),
        cli.enable_splunk,
        registry,
        issues,
        out,
    );
    push_status(
        "cloud-aws",
        cfg!(feature = "cloud-aws"),
        cli.enable_aws,
        registry,
        issues,
        out,
    );
    push_status(
        "edr-crowdstrike",
        cfg!(feature = "edr-crowdstrike"),
        cli.enable_crowdstrike,
        registry,
        issues,
        out,
    );
    push_status(
        "edr-sentinelone",
        cfg!(feature = "edr-sentinelone"),
        cli.enable_sentinelone,
        registry,
        issues,
        out,
    );
    push_status(
        "ti-misp",
        cfg!(feature = "ti-misp"),
        cli.enable_misp,
        registry,
        issues,
        out,
    );
    push_status(
        "ti-virustotal",
        cfg!(feature = "ti-virustotal"),
        cli.enable_virustotal,
        registry,
        issues,
        out,
    );
}

fn append_llm_statuses(
    cli: &Cli,
    registry: &ModuleRegistry,
    issues: &BTreeMap<&'static str, String>,
    out: &mut Vec<ModuleStatus>,
) {
    push_status(
        "llm-openai-compatible",
        true,
        cli.llm_module.as_deref() == Some("llm-openai-compatible"),
        registry,
        issues,
        out,
    );
    push_status(
        "llm-anthropic",
        cfg!(feature = "llm-anthropic"),
        cli.llm_module.as_deref() == Some("llm-anthropic"),
        registry,
        issues,
        out,
    );
    push_status(
        "llm-deepseek",
        cfg!(feature = "llm-deepseek"),
        cli.llm_module.as_deref() == Some("llm-deepseek"),
        registry,
        issues,
        out,
    );
    push_status(
        "llm-openrouter",
        cfg!(feature = "llm-openrouter"),
        cli.llm_module.as_deref() == Some("llm-openrouter"),
        registry,
        issues,
        out,
    );
}

fn push_status(
    id: &'static str,
    compiled: bool,
    requested: bool,
    registry: &ModuleRegistry,
    issues: &BTreeMap<&'static str, String>,
    out: &mut Vec<ModuleStatus>,
) {
    let enabled = registry.manifest(id).is_some();
    let configuration = if let Some(issue) = issues.get(id) {
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
    out.push(ModuleStatus {
        id: id.into(),
        compiled,
        enabled,
        configuration,
    });
}
