use super::{
    Arc, AuditLog, BTreeMap, CancellationToken, CaseId, Context, Engine, EvidenceGraph,
    EvidenceStore, FindingKind, HashSet, LocalStore, MandatoryGuard, ModuleRegistry, ModuleStatus,
    OpenOptions, Parser, Path, PathBuf, Read, Repository, Result, RootWorkspaceIo, Severity,
    Subcommand, Write, anyhow,
};

#[derive(Parser)]
#[command(version, about = "IRMind: local, signed incident investigation")]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct Cli {
    #[arg(long, env = "IRMIND_HOME")]
    pub(super) home: Option<PathBuf>,
    #[arg(long, env = "IRMIND_POLICY")]
    pub(super) policy: Option<PathBuf>,
    #[arg(long, env = "IRMIND_LLM_MODULE")]
    pub(super) llm_module: Option<String>,
    #[arg(long)]
    pub(super) passphrase_fd: Option<u32>,
    #[arg(long)]
    pub(super) enable_virustotal: bool,
    #[arg(long)]
    pub(super) enable_splunk: bool,
    #[arg(long)]
    pub(super) enable_misp: bool,
    #[arg(long)]
    pub(super) enable_aws: bool,
    #[arg(long)]
    pub(super) enable_crowdstrike: bool,
    #[arg(long)]
    pub(super) enable_sentinelone: bool,
    #[command(subcommand)]
    pub(super) command: Option<Command>,
}

#[derive(Subcommand)]
pub(super) enum Command {
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
        #[arg(long)]
        expected_key: Option<String>,
    },
    Tui {
        case_id: String,
    },
}

#[derive(Subcommand)]
pub(super) enum CaseCommand {
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

// Path::display() emits terminal controls from attacker-controlled file names.
#[allow(clippy::unnecessary_debug_formatting)]
pub(super) fn terminal_safe_path(path: &Path) -> String {
    format!("{path:?}")
}

pub(super) fn input_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    while let Some((path, depth)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect {}", terminal_safe_path(&path)))?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "symlink ingestion is not allowed: {}",
                terminal_safe_path(&path)
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
                return Err(anyhow!(
                    "evidence exceeds 50 MB: {}",
                    terminal_safe_path(&path)
                ));
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
            return Err(anyhow!(
                "unsupported ingest file: {}",
                terminal_safe_path(&path)
            ));
        }
    }
    Ok(files)
}

pub(super) fn read_evidence(path: &Path) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(anyhow!("ingest input is not a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(anyhow!("ingest input is a reparse point"));
        }
    }
    let mut bytes = Vec::new();
    file.take(50_000_001)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", terminal_safe_path(path)))?;
    if bytes.len() > 50_000_000 {
        return Err(anyhow!(
            "evidence exceeds 50 MB: {}",
            terminal_safe_path(path)
        ));
    }
    Ok(bytes)
}

pub(super) fn audit_source_name(root: &Path, file: &Path) -> Result<String> {
    let relative = if root.is_dir() {
        file.strip_prefix(root)
            .context("ingest path escaped its root")?
    } else {
        file.file_name()
            .map(Path::new)
            .ok_or_else(|| anyhow!("ingest file has no name"))?
    };
    let mut parts = Vec::new();
    for part in relative.components() {
        match part {
            std::path::Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| anyhow!("non-UTF-8 ingest path"))?;
                if value.contains(['/', '\\', ':']) || value == "." || value == ".." {
                    return Err(anyhow!("invalid ingest path component"));
                }
                parts.push(value);
            }
            _ => return Err(anyhow!("ingest path must be relative")),
        }
    }
    if parts.is_empty() {
        return Err(anyhow!("ingest path has no file name"));
    }
    Ok(parts.join("/"))
}

pub(super) fn write_private_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", terminal_safe_path(path)))?;
    irmind_fs::private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) struct AutomationContext<'a, 'ports> {
    pub(super) engine: &'a Engine<'ports>,
    pub(super) store: &'a Arc<LocalStore>,
    pub(super) guard: &'a Arc<MandatoryGuard>,
    pub(super) registry: &'a ModuleRegistry,
    pub(super) llm_module: Option<&'a str>,
    pub(super) selected_model: Option<&'a dyn irmind_app::LlmPort>,
    pub(super) workspace_io: &'a RootWorkspaceIo,
    pub(super) module_statuses: &'a [ModuleStatus],
    pub(super) cancel: &'a CancellationToken,
    pub(super) new_analyst_key: bool,
}

impl AutomationContext<'_, '_> {
    pub(super) fn run(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            guard,
            registry,
            llm_module,
            selected_model,
            workspace_io,
            module_statuses,
            cancel,
            new_analyst_key,
        } = self;
        match command {
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
                            irmind_app::ContentGuard::screen(guard.as_ref(), &case.title)?.text
                        );
                    }
                }
                CaseCommand::Show { case_id } => {
                    let case = store.get_case(&parse_id(&case_id)?)?;
                    println!(
                        "{}\nTitle: {}\nSeverity: {}\nScope: {}\nSealed: {}",
                        case.id.as_str(),
                        irmind_app::ContentGuard::screen(guard.as_ref(), &case.title)?.text,
                        case.severity.as_str(),
                        irmind_app::ContentGuard::screen(guard.as_ref(), &case.scope)?.text,
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
                engine.verify_cancelable(&id, cancel)?;
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
                    if cancel.is_cancelled() {
                        return Err(anyhow!("ingest cancelled"));
                    }
                    let bytes = read_evidence(&file)?;
                    let hash = irmind_app::hex(&irmind_app::sha256(&bytes));
                    if indexed.contains(&hash) {
                        println!("skipped {hash} {}", terminal_safe_path(&file));
                        continue;
                    }
                    let ingested = engine.ingest_cancelable(
                        &id,
                        &bytes,
                        &audit_source_name(&path, &file)?,
                        cancel,
                    )?;
                    indexed.insert(ingested.clone());
                    println!("{ingested} {}", terminal_safe_path(&file));
                }
            }
            Command::Ask { case_id, alert } => {
                let model = registry.llm(llm_module.ok_or_else(|| {
                    anyhow!("select an approved LLM explicitly with --llm-module")
                })?)?;
                println!(
                    "{}",
                    engine.investigate_with_cancel(&parse_id(&case_id)?, &alert, model, cancel)?
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
                        irmind_app::ContentGuard::screen(guard.as_ref(), &finding.value)?.text,
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
                    write_private_output(&path, &bytes)?;
                } else {
                    println!(
                        "{}",
                        irmind_app::ContentGuard::screen(
                            guard.as_ref(),
                            &String::from_utf8_lossy(&bytes)
                        )?
                        .text
                    );
                }
            }
            Command::Verify { case_id } => println!(
                "verified {} audit entries",
                engine.verify_cancelable(&parse_id(&case_id)?, cancel)?
            ),
            Command::Seal { case_id } => {
                let id = parse_id(&case_id)?;
                engine.seal(&id)?;
                let seal = store
                    .case_seal(&id)?
                    .ok_or_else(|| anyhow!("case seal missing"))?;
                println!(
                    "case sealed; analyst key fingerprint {}",
                    seal.analyst_key_fingerprint
                );
            }
            Command::Graph { case_id } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let summary = store.graph_summary(&id)?;
                println!(
                    "{}",
                    irmind_app::ContentGuard::screen(guard.as_ref(), &summary)?.text
                );
            }
            Command::GraphRebuild { case_id } => println!(
                "rebuilt {} graph records",
                engine.rebuild_graph_cancelable(&parse_id(&case_id)?, cancel)?
            ),
            Command::VerifyGraph { case_id } => println!(
                "verified {} graph records",
                engine.verify_graph_cancelable(&parse_id(&case_id)?, cancel)?
            ),
            Command::Timeline { case_id } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                for event in store.timeline(&id, 100)? {
                    let line = format!(
                        "{} {} [{}#{}]",
                        event.at, event.event, event.evidence_hash, event.record_index
                    );
                    println!(
                        "{}",
                        irmind_app::ContentGuard::screen(guard.as_ref(), &line)?.text
                    );
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
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
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
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
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
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
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
                let result =
                    store.graph_path(&id, (&from_kind, &from_value), (&to_kind, &to_value))?;
                println!(
                    "{}",
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
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
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
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
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
                );
            }
            Command::Export { case_id, path } => {
                let id = parse_id(&case_id)?;
                let fingerprint =
                    irmind_app::export_case(engine, store.as_ref(), &id, &path, cancel)?;
                println!("exported case; analyst key fingerprint {fingerprint}");
            }
            Command::VerifyExport { .. } => {
                return Err(anyhow!(
                    "verify-export must be handled before opening storage"
                ));
            }
            Command::Tui { case_id } => {
                return irmind_tui::run_workspace(
                    engine,
                    selected_model,
                    workspace_io,
                    module_statuses,
                    cancel,
                    Some(&parse_id(&case_id)?),
                    new_analyst_key,
                );
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod input_tests {
    use super::*;

    #[test]
    fn no_arguments_selects_the_workspace_without_an_llm() {
        let cli = Cli::try_parse_from(["irmind"]).unwrap();
        assert!(cli.command.is_none());
        assert!(cli.llm_module.is_none());
    }

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
        assert_eq!(
            audit_source_name(root.path(), &files[2]).unwrap(),
            "nested/c.json"
        );
        assert_eq!(audit_source_name(&files[0], &files[0]).unwrap(), "a.json");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_inside_ingest_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("real.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("real.json", root.path().join("link.json")).unwrap();
        assert!(input_files(root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn evidence_reader_refuses_a_swapped_symlink() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target.json");
        std::fs::write(&target, b"{}").unwrap();
        let link = root.path().join("swapped.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(super::read_evidence(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ingest_errors_escape_control_characters_in_file_names() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target.json");
        std::fs::write(&target, b"synthetic").unwrap();
        let malicious = root.path().join("bad\u{1b}[31m.txt");
        std::os::unix::fs::symlink(&target, &malicious).unwrap();
        let error = input_files(root.path()).unwrap_err().to_string();
        assert!(!error.contains('\u{1b}'));
        assert!(error.contains("\\u{1b}"));
    }
}
