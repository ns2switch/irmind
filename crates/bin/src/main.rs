#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use irmind_app::{Engine, FindingKind, ModelPricing, Repository, modules::ModuleRegistry};
use irmind_domain::{Actor, CaseId, ExecutionMode, PolicyRules, Severity, Tool};
use irmind_infra::{LocalSigner, LocalStore, verify_export};
#[cfg(feature = "cloud-aws")]
use irmind_mod_cloud_aws::AwsCloudTrail;
#[cfg(feature = "edr-crowdstrike")]
use irmind_mod_edr_crowdstrike::CrowdStrike;
#[cfg(feature = "edr-sentinelone")]
use irmind_mod_edr_sentinelone::SentinelOne;
#[cfg(feature = "llm-anthropic")]
use irmind_mod_llm_anthropic::Anthropic;
#[cfg(feature = "llm-deepseek")]
use irmind_mod_llm_deepseek::DeepSeek;
use irmind_mod_llm_openai_compatible::{MODULE_ID as DEFAULT_LLM_MODULE, OpenAiCompatible};
#[cfg(feature = "llm-openrouter")]
use irmind_mod_llm_openrouter::OpenRouter;
use irmind_mod_parser_json::JsonParser;
#[cfg(feature = "siem-splunk")]
use irmind_mod_siem_splunk::Splunk;
#[cfg(feature = "ti-misp")]
use irmind_mod_ti_misp::Misp;
#[cfg(feature = "ti-virustotal")]
use irmind_mod_ti_virustotal::VirusTotal;
use irmind_security::MandatoryGuard;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

mod tui;

#[derive(Parser)]
#[command(version, about = "IRMind: local, signed incident investigation")]
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    #[arg(long, env = "IRMIND_HOME")]
    home: Option<PathBuf>,
    #[arg(long, env = "IRMIND_POLICY")]
    policy: Option<PathBuf>,
    #[arg(long, env = "IRMIND_LLM_MODULE")]
    llm_module: Option<String>,
    #[arg(long)]
    enable_virustotal: bool,
    #[arg(long)]
    enable_splunk: bool,
    #[arg(long)]
    enable_misp: bool,
    #[arg(long)]
    enable_aws: bool,
    #[arg(long)]
    enable_crowdstrike: bool,
    #[arg(long)]
    enable_sentinelone: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u8,
    max_tool_calls_per_case: usize,
    max_model_result_bytes: usize,
    max_model_tokens_per_case: u64,
    denied_tools: Vec<String>,
}

fn load_policy(path: &std::path::Path) -> Result<(PolicyRules, String)> {
    let raw = std::fs::read(path).with_context(|| format!("read policy {}", path.display()))?;
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
        max_tool_calls_per_case: file.max_tool_calls_per_case,
        max_model_result_bytes: file.max_model_result_bytes,
        max_model_tokens_per_case: file.max_model_tokens_per_case,
    };
    policy
        .validate()
        .map_err(|_| anyhow!("invalid policy limits"))?;
    let fingerprint = irmind_app::hex(&irmind_app::sha256(&raw));
    Ok((policy, fingerprint))
}

fn load_pricing() -> Result<Option<ModelPricing>> {
    let input = std::env::var("IRMIND_INPUT_MICROUSD_PER_MILLION").ok();
    let output = std::env::var("IRMIND_OUTPUT_MICROUSD_PER_MILLION").ok();
    match (input, output) {
        (None, None) => Ok(None),
        (Some(input), Some(output)) => {
            let input_microusd_per_million = input.parse::<u64>().context("invalid input price")?;
            let output_microusd_per_million =
                output.parse::<u64>().context("invalid output price")?;
            if input_microusd_per_million > 1_000_000_000_000
                || output_microusd_per_million > 1_000_000_000_000
            {
                return Err(anyhow!("model price exceeds configured maximum"));
            }
            Ok(Some(ModelPricing {
                input_microusd_per_million,
                output_microusd_per_million,
            }))
        }
        _ => Err(anyhow!("both input and output model prices must be set")),
    }
}

#[derive(Subcommand)]
enum Command {
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    Ingest {
        case_id: String,
        path: PathBuf,
    },
    Ask {
        case_id: String,
        alert: String,
    },
    Approvals {
        case_id: String,
    },
    Approve {
        case_id: String,
        request_id: String,
    },
    Deny {
        case_id: String,
        request_id: String,
        reason: String,
    },
    EditApproval {
        case_id: String,
        request_id: String,
        args_json: String,
    },
    AddFinding {
        case_id: String,
        kind: String,
        value: String,
        evidence_hash: String,
    },
    ConfirmFinding {
        case_id: String,
        finding_id: String,
    },
    DismissFinding {
        case_id: String,
        finding_id: String,
        reason: String,
    },
    Findings {
        case_id: String,
    },
    Report {
        case_id: String,
    },
    Evidence {
        case_id: String,
        hash: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Verify {
        case_id: String,
    },
    Seal {
        case_id: String,
    },
    Graph {
        case_id: String,
    },
    GraphRebuild {
        case_id: String,
    },
    VerifyGraph {
        case_id: String,
    },
    Timeline {
        case_id: String,
    },
    Entity {
        case_id: String,
        kind: String,
        value: String,
    },
    Neighbors {
        case_id: String,
        kind: String,
        value: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    EntityTimeline {
        case_id: String,
        kind: String,
        value: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    GraphPath {
        case_id: String,
        from_kind: String,
        from_value: String,
        to_kind: String,
        to_value: String,
    },
    TextSearch {
        case_id: String,
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    RawRecords {
        case_id: String,
        hash: String,
        index: usize,
    },
    Export {
        case_id: String,
        path: PathBuf,
    },
    VerifyExport {
        path: PathBuf,
    },
    Tui {
        case_id: String,
    },
}

#[derive(Subcommand)]
enum CaseCommand {
    New {
        title: String,
        #[arg(long)]
        scope: String,
        #[arg(long, default_value = "medium")]
        severity: String,
    },
    List,
    Show {
        case_id: String,
    },
    Scope {
        case_id: String,
        scope: String,
    },
}

fn parse_id(value: &str) -> Result<CaseId> {
    CaseId::parse(value).map_err(|_| anyhow!("invalid case id"))
}

fn parse_approval_args(value: &str) -> Result<BTreeMap<String, String>> {
    serde_json::from_str(value).context("approval arguments must be a JSON object of strings")
}

fn input_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    while let Some((path, depth)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "symlink ingestion is not allowed: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            if depth >= 16 {
                return Err(anyhow!("ingest directory exceeds depth 16"));
            }
            let mut children = std::fs::read_dir(&path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            children.sort();
            pending.extend(children.into_iter().rev().map(|child| (child, depth + 1)));
        } else if metadata.is_file() {
            if metadata.len() > 50_000_000 {
                return Err(anyhow!("evidence exceeds 50 MB: {}", path.display()));
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow!("ingest size overflow"))?;
            if total_bytes > 1_000_000_000 {
                return Err(anyhow!("ingest directory exceeds 1 GB"));
            }
            files.push(path);
            if files.len() > 1_000 {
                return Err(anyhow!("ingest directory exceeds 1000 files"));
            }
        } else {
            return Err(anyhow!("unsupported ingest file: {}", path.display()));
        }
    }
    Ok(files)
}

fn read_evidence(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(50_000_001)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() > 50_000_000 {
        return Err(anyhow!("evidence exceeds 50 MB: {}", path.display()));
    }
    Ok(bytes)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::VerifyExport { path } = &cli.command {
        let (public_key, entries) = verify_export(path)?;
        println!("verified {entries} audit entries; public key {public_key}");
        return Ok(());
    }
    let home = cli.home.unwrap_or_else(|| PathBuf::from(".irmind"));
    let store = LocalStore::open(&home)?;
    let signer = LocalSigner::load_or_create(Actor::Analyst)
        .context("load analyst signing key from system keyring")?;
    let guard = MandatoryGuard::new()?;
    let mut registry = ModuleRegistry::new();
    registry.register(Box::new(JsonParser))?;
    if matches!(&cli.command, Command::Ask { .. } | Command::Tui { .. }) {
        match cli
            .llm_module
            .as_deref()
            .ok_or_else(|| anyhow!("select an approved LLM explicitly with --llm-module"))?
        {
            DEFAULT_LLM_MODULE => registry.register(Box::new(OpenAiCompatible::from_env()?))?,
            #[cfg(feature = "llm-anthropic")]
            irmind_mod_llm_anthropic::MODULE_ID => {
                registry.register(Box::new(Anthropic::from_env()?))?;
            }
            #[cfg(feature = "llm-deepseek")]
            irmind_mod_llm_deepseek::MODULE_ID => {
                registry.register(Box::new(DeepSeek::from_env()?))?;
            }
            #[cfg(feature = "llm-openrouter")]
            irmind_mod_llm_openrouter::MODULE_ID => {
                registry.register(Box::new(OpenRouter::from_env()?))?;
            }
            _ => return Err(anyhow!("LLM module is not compiled into this binary")),
        }
    }
    #[cfg(feature = "siem-splunk")]
    if cli.enable_splunk {
        registry.register(Box::new(Splunk::from_env()?))?;
    }
    #[cfg(not(feature = "siem-splunk"))]
    if cli.enable_splunk {
        return Err(anyhow!(
            "this binary was built without the siem-splunk feature"
        ));
    }
    #[cfg(feature = "ti-misp")]
    if cli.enable_misp {
        registry.register(Box::new(Misp::from_env()?))?;
    }
    #[cfg(not(feature = "ti-misp"))]
    if cli.enable_misp {
        return Err(anyhow!("this binary was built without the ti-misp feature"));
    }
    #[cfg(feature = "cloud-aws")]
    if cli.enable_aws {
        registry.register(Box::new(AwsCloudTrail::from_env()?))?;
    }
    #[cfg(not(feature = "cloud-aws"))]
    if cli.enable_aws {
        return Err(anyhow!(
            "this binary was built without the cloud-aws feature"
        ));
    }
    #[cfg(feature = "edr-crowdstrike")]
    if cli.enable_crowdstrike {
        registry.register(Box::new(CrowdStrike::from_env()?))?;
    }
    #[cfg(not(feature = "edr-crowdstrike"))]
    if cli.enable_crowdstrike {
        return Err(anyhow!(
            "this binary was built without the edr-crowdstrike feature"
        ));
    }
    #[cfg(feature = "edr-sentinelone")]
    if cli.enable_sentinelone {
        registry.register(Box::new(SentinelOne::from_env()?))?;
    }
    #[cfg(not(feature = "edr-sentinelone"))]
    if cli.enable_sentinelone {
        return Err(anyhow!(
            "this binary was built without the edr-sentinelone feature"
        ));
    }
    #[cfg(feature = "ti-virustotal")]
    if cli.enable_virustotal {
        registry.register(Box::new(VirusTotal::from_env()?))?;
    }
    #[cfg(not(feature = "ti-virustotal"))]
    if cli.enable_virustotal {
        return Err(anyhow!(
            "this binary was built without the ti-virustotal feature"
        ));
    }
    let mut engine = registry.bind(Engine::new(
        &store,
        &signer,
        &guard,
        registry.parser()?,
        ExecutionMode::Attended,
    )?)?;
    if let Some(path) = &cli.policy {
        let (policy, fingerprint) = load_policy(path)?;
        engine = engine.with_policy(policy, fingerprint)?;
    }
    if let Some(pricing) = load_pricing()? {
        engine = engine.with_pricing(pricing);
    }
    match cli.command {
        Command::Case { command } => match command {
            CaseCommand::New {
                title,
                scope,
                severity,
            } => {
                let severity = Severity::parse(&severity)
                    .map_err(|_| anyhow!("severity must be low, medium, high or critical"))?;
                let case = engine.create_case_with_severity(&title, severity, &scope)?;
                println!("{}", case.id.as_str());
            }
            CaseCommand::List => {
                for case in store.list_cases()? {
                    println!(
                        "{}\t{}\t{}",
                        case.id.as_str(),
                        if case.sealed { "sealed" } else { "open" },
                        irmind_app::ContentGuard::screen(&guard, &case.title)?.text
                    );
                }
            }
            CaseCommand::Show { case_id } => {
                let case = store.get_case(&parse_id(&case_id)?)?;
                println!(
                    "{}\nTitle: {}\nSeverity: {}\nScope: {}\nSealed: {}",
                    case.id.as_str(),
                    irmind_app::ContentGuard::screen(&guard, &case.title)?.text,
                    case.severity.as_str(),
                    irmind_app::ContentGuard::screen(&guard, &case.scope)?.text,
                    case.sealed
                );
            }
            CaseCommand::Scope { case_id, scope } => {
                engine.change_scope(&parse_id(&case_id)?, &scope)?;
                println!("case scope updated and signed");
            }
        },
        Command::Ingest { case_id, path } => {
            let id = parse_id(&case_id)?;
            engine.verify(&id)?;
            if store.get_case(&id)?.sealed {
                return Err(anyhow!("case is sealed"));
            }
            let files = input_files(&path)?;
            let mut indexed: HashSet<String> = store
                .entries(&id)?
                .into_iter()
                .filter(|entry| entry.kind == "GraphIndexed")
                .filter_map(|entry| entry.evidence)
                .collect();
            for file in files {
                let bytes = read_evidence(&file)?;
                let hash = irmind_app::hex(&irmind_app::sha256(&bytes));
                if indexed.contains(&hash) {
                    println!("skipped {hash} {}", file.display());
                    continue;
                }
                let ingested = engine.ingest(&id, &bytes, &file.display().to_string())?;
                indexed.insert(ingested.clone());
                println!("{ingested} {}", file.display());
            }
        }
        Command::Ask { case_id, alert } => {
            let model =
                registry.llm(cli.llm_module.as_deref().ok_or_else(|| {
                    anyhow!("select an approved LLM explicitly with --llm-module")
                })?)?;
            println!(
                "{}",
                engine.investigate(&parse_id(&case_id)?, &alert, model)?
            );
        }
        Command::Approvals { case_id } => {
            for request in engine.pending_approvals(&parse_id(&case_id)?)? {
                println!(
                    "{} {:?} {} {:?}",
                    request.id,
                    request.mode,
                    request.tool.as_str(),
                    request.args
                );
            }
        }
        Command::Approve {
            case_id,
            request_id,
        } => {
            println!("{}", engine.approve(&parse_id(&case_id)?, &request_id)?);
        }
        Command::Deny {
            case_id,
            request_id,
            reason,
        } => {
            println!(
                "{}",
                engine.deny(&parse_id(&case_id)?, &request_id, &reason)?
            );
        }
        Command::EditApproval {
            case_id,
            request_id,
            args_json,
        } => {
            let args = parse_approval_args(&args_json)?;
            println!(
                "{}",
                engine.edit_approval(&parse_id(&case_id)?, &request_id, args)?
            );
        }
        Command::AddFinding {
            case_id,
            kind,
            value,
            evidence_hash,
        } => println!(
            "{}",
            engine.add_finding(
                &parse_id(&case_id)?,
                FindingKind::parse(&kind)?,
                &value,
                &evidence_hash
            )?
        ),
        Command::ConfirmFinding {
            case_id,
            finding_id,
        } => {
            engine.confirm_finding(&parse_id(&case_id)?, &finding_id)?;
            println!("finding confirmed");
        }
        Command::DismissFinding {
            case_id,
            finding_id,
            reason,
        } => {
            engine.dismiss_finding(&parse_id(&case_id)?, &finding_id, &reason)?;
            println!("finding dismissed");
        }
        Command::Findings { case_id } => {
            for finding in engine.findings(&parse_id(&case_id)?)? {
                println!(
                    "{} {:?} {} {} [{}]",
                    finding.id,
                    finding.kind,
                    if finding.confirmed {
                        "confirmed"
                    } else if finding.dismissed {
                        "dismissed"
                    } else {
                        "proposed"
                    },
                    irmind_app::ContentGuard::screen(&guard, &finding.value)?.text,
                    finding.evidence_hash
                );
            }
        }
        Command::Report { case_id } => {
            println!("{}", engine.report(&parse_id(&case_id)?)?);
        }
        Command::Evidence {
            case_id,
            hash,
            output,
        } => {
            let bytes = store.get_evidence(&parse_id(&case_id)?, &hash)?;
            if let Some(path) = output {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                let mut file = options
                    .open(&path)
                    .with_context(|| format!("open {}", path.display()))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            } else {
                println!(
                    "{}",
                    irmind_app::ContentGuard::screen(&guard, &String::from_utf8_lossy(&bytes))?
                        .text
                );
            }
        }
        Command::Verify { case_id } => println!(
            "verified {} audit entries",
            engine.verify(&parse_id(&case_id)?)?
        ),
        Command::Seal { case_id } => {
            engine.seal(&parse_id(&case_id)?)?;
            println!("case sealed");
        }
        Command::Graph { case_id } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let summary = store.graph_summary(&id)?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &summary)?.text
            );
        }
        Command::GraphRebuild { case_id } => println!(
            "rebuilt {} graph records",
            engine.rebuild_graph(&parse_id(&case_id)?)?
        ),
        Command::VerifyGraph { case_id } => println!(
            "verified {} graph records",
            engine.verify_graph(&parse_id(&case_id)?)?
        ),
        Command::Timeline { case_id } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            for event in store.timeline(&id, 100)? {
                let line = format!(
                    "{} {} [{}#{}]",
                    event.at, event.event, event.evidence_hash, event.record_index
                );
                println!("{}", irmind_app::ContentGuard::screen(&guard, &line)?.text);
            }
        }
        Command::Entity {
            case_id,
            kind,
            value,
        } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let result = store.entity_lookup(&id, &kind, &value)?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &result)?.text
            );
        }
        Command::Neighbors {
            case_id,
            kind,
            value,
            limit,
        } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let result = store.neighbors(&id, &kind, &value, limit)?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &result)?.text
            );
        }
        Command::EntityTimeline {
            case_id,
            kind,
            value,
            limit,
        } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let result = store.entity_timeline(&id, &kind, &value, limit)?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &result)?.text
            );
        }
        Command::GraphPath {
            case_id,
            from_kind,
            from_value,
            to_kind,
            to_value,
        } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let result = store.graph_path(&id, (&from_kind, &from_value), (&to_kind, &to_value))?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &result)?.text
            );
        }
        Command::TextSearch {
            case_id,
            query,
            limit,
        } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let result = store.text_search(&id, &query, limit)?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &result)?.text
            );
        }
        Command::RawRecords {
            case_id,
            hash,
            index,
        } => {
            let id = parse_id(&case_id)?;
            let _case_lock = store.lock_case(&id)?;
            let result = store.raw_record(&id, &hash, index)?;
            println!(
                "{}",
                irmind_app::ContentGuard::screen(&guard, &result)?.text
            );
        }
        Command::Export { case_id, path } => {
            let id = parse_id(&case_id)?;
            engine.verify(&id)?;
            let public_key = store.export_case(&id, &path)?;
            println!("exported case; public key {public_key}");
        }
        Command::VerifyExport { .. } => {
            return Err(anyhow!(
                "verify-export must be handled before opening storage"
            ));
        }
        Command::Tui { case_id } => {
            tui::run(
                &engine,
                &store,
                &guard,
                registry.llm(cli.llm_module.as_deref().ok_or_else(|| {
                    anyhow!("select an approved LLM explicitly with --llm-module")
                })?)?,
                &parse_id(&case_id)?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod input_tests {
    use super::*;

    #[test]
    fn walks_ingest_directory_in_stable_order() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("b.json"), b"{}").unwrap();
        std::fs::write(root.path().join("a.json"), b"{}").unwrap();
        std::fs::write(root.path().join("nested/c.json"), b"{}").unwrap();
        let files = input_files(root.path()).unwrap();
        let names = files
            .iter()
            .map(|path| path.strip_prefix(root.path()).unwrap().to_path_buf())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                PathBuf::from("a.json"),
                PathBuf::from("b.json"),
                PathBuf::from("nested/c.json")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_inside_ingest_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("real.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("real.json", root.path().join("link.json")).unwrap();
        assert!(input_files(root.path()).is_err());
    }
}
