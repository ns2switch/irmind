use crate::cli::terminal_safe_path;
use anyhow::{Context, Result, anyhow};
use irmind_domain::{CaseScope, PolicyRules, Tool};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u8,
    max_tool_calls_per_case: usize,
    max_model_result_bytes: usize,
    max_model_tokens_per_case: u64,
    denied_tools: Vec<String>,
    #[serde(default)]
    scope: Option<ScopePolicyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePolicyFile {
    sources: Vec<String>,
    #[serde(default)]
    accounts: Vec<String>,
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    from: String,
    to: String,
}

impl ScopePolicyFile {
    fn parse(self) -> Result<CaseScope> {
        let encoded = format!(
            "v2;sources={};accounts={};projects={};hosts={};from={};to={}",
            self.sources.join(","),
            self.accounts.join(","),
            self.projects.join(","),
            self.hosts.join(","),
            self.from,
            self.to
        );
        match CaseScope::parse(&encoded) {
            Ok(scope @ CaseScope::Remote { .. }) => Ok(scope),
            _ => Err(anyhow!("invalid policy scope")),
        }
    }
}

pub(crate) fn load_policy(path: &Path) -> Result<(PolicyRules, String)> {
    let raw =
        std::fs::read(path).with_context(|| format!("read policy {}", terminal_safe_path(path)))?;
    let source = std::str::from_utf8(&raw).context("policy must be UTF-8")?;
    let file: PolicyFile = toml::from_str(source).context("parse policy TOML")?;
    if file.version != 1 {
        return Err(anyhow!("unsupported policy version"));
    }
    let denied_tools = file
        .denied_tools
        .iter()
        .map(|name| Tool::parse(name).map_err(|_| anyhow!("unknown policy tool: {name}")))
        .collect::<Result<Vec<_>>>()?;
    let policy = PolicyRules {
        denied_tools,
        scope: file.scope.map(ScopePolicyFile::parse).transpose()?,
        max_tool_calls_per_case: file.max_tool_calls_per_case,
        max_model_result_bytes: file.max_model_result_bytes,
        max_model_tokens_per_case: file.max_model_tokens_per_case,
    };
    policy
        .validate()
        .map_err(|_| anyhow!("invalid policy limits or scope"))?;
    let fingerprint = irmind_app::hex(&irmind_app::sha256(&raw));
    Ok((policy, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_scope_covers_accounts_projects_hosts_and_window() -> Result<()> {
        let raw = r#"
version = 1
max_tool_calls_per_case = 100
max_model_result_bytes = 10000
max_model_tokens_per_case = 200000
denied_tools = []

[scope]
sources = ["source-a"]
accounts = ["account-a"]
projects = ["project-a"]
hosts = ["host-a"]
from = "2026-10-23T00:00:00Z"
to = "2026-10-23T23:59:59Z"
"#;
        let file: PolicyFile = toml::from_str(raw)?;
        let scope = file
            .scope
            .ok_or_else(|| anyhow!("scope missing"))?
            .parse()?;
        assert!(matches!(scope, CaseScope::Remote { .. }));
        Ok(())
    }
}
