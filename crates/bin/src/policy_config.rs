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
    #[serde(default = "default_model_rounds_per_turn")]
    max_model_rounds_per_turn: usize,
    max_model_result_bytes: usize,
    max_model_tokens_per_case: u64,
    #[serde(default = "default_object_read_bytes")]
    max_object_read_bytes: u64,
    #[serde(default = "default_object_case_bytes")]
    max_object_bytes_per_case: u64,
    #[serde(default = "default_object_approval_bytes")]
    object_transfer_approval_bytes: u64,
    denied_tools: Vec<String>,
    #[serde(default)]
    scope: Option<ScopePolicyFile>,
}

fn default_object_read_bytes() -> u64 {
    PolicyRules::default().max_object_read_bytes
}
fn default_model_rounds_per_turn() -> usize {
    PolicyRules::default().max_model_rounds_per_turn
}
fn default_object_case_bytes() -> u64 {
    PolicyRules::default().max_object_bytes_per_case
}
fn default_object_approval_bytes() -> u64 {
    PolicyRules::default().object_transfer_approval_bytes
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
    #[serde(default)]
    objects: Vec<String>,
    from: String,
    to: String,
}

impl ScopePolicyFile {
    fn parse(self) -> Result<CaseScope> {
        let encoded = format!(
            "v{};sources={};accounts={};projects={};hosts={};{}from={};to={}",
            if self.objects.is_empty() { 2 } else { 3 },
            self.sources.join(","),
            self.accounts.join(","),
            self.projects.join(","),
            self.hosts.join(","),
            if self.objects.is_empty() {
                String::new()
            } else {
                format!("objects={};", self.objects.join(","))
            },
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
        max_model_rounds_per_turn: file.max_model_rounds_per_turn,
        max_model_result_bytes: file.max_model_result_bytes,
        max_model_tokens_per_case: file.max_model_tokens_per_case,
        max_object_read_bytes: file.max_object_read_bytes,
        max_object_bytes_per_case: file.max_object_bytes_per_case,
        object_transfer_approval_bytes: file.object_transfer_approval_bytes,
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
    fn model_round_limit_defaults_to_25_and_rejects_values_above_100() {
        assert_eq!(default_model_rounds_per_turn(), 25);
        let mut rules = PolicyRules {
            max_model_rounds_per_turn: 100,
            ..PolicyRules::default()
        };
        assert!(rules.validate().is_ok());
        rules.max_model_rounds_per_turn = 101;
        assert!(rules.validate().is_err());
    }

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
objects = ["s3://audit-bucket/AWSLogs/123/"]
from = "2026-10-23T00:00:00Z"
to = "2026-10-23T23:59:59Z"
"#;
        let file: PolicyFile = toml::from_str(raw)?;
        let scope = file
            .scope
            .ok_or_else(|| anyhow!("scope missing"))?
            .parse()?;
        assert!(matches!(scope, CaseScope::Remote { .. }));
        assert!(scope.allows_object(
            "source-a",
            "s3://audit-bucket/AWSLogs/123/a.json",
            "2026-10-23T12:00:00Z",
            "2026-10-23T13:00:00Z"
        ));
        Ok(())
    }
}
