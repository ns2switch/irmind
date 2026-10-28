use super::{
    Arc, AuditLog, BTreeMap, CancellationToken, CaseId, Context, Engine, EvidenceGraph,
    EvidenceStore, FindingKind, JsonParser, LargeCaseUseCases, LocalStore, MandatoryGuard,
    ModuleRegistry, ModuleStatus, OpenOptions, Parser, Path, PathBuf, Read, Repository, Result,
    RootWorkspaceIo, Severity, Subcommand, Write, anyhow,
};

#[derive(Parser, Clone)]
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

#[derive(Subcommand, Clone)]
pub(super) enum Command {
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    Ingest {
        case_id: String,
        path: PathBuf,
        #[arg(long)]
        copy_original: bool,
    },
    Migrate {
        case_id: String,
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
        #[arg(long)]
        source_root: Option<PathBuf>,
        #[arg(long)]
        sample: Option<usize>,
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
        #[arg(long)]
        source_root: Option<PathBuf>,
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
        #[arg(long)]
        include_originals: bool,
        #[arg(long)]
        source_root: Option<PathBuf>,
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

#[derive(Subcommand, Clone)]
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

pub(super) fn input_files_large(root: &Path) -> Result<Vec<PathBuf>> {
    enumerate_input_files(root, 500_000_000_000, 500_000_000_000, 1_000_000)
}

fn enumerate_input_files(
    root: &Path,
    max_file: u64,
    max_total: u64,
    max_files: usize,
) -> Result<Vec<PathBuf>> {
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
            if metadata.len() > max_file {
                return Err(anyhow!(
                    "evidence exceeds configured size limit: {}",
                    terminal_safe_path(&path)
                ));
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow!("ingest size overflow"))?;
            if total_bytes > max_total {
                return Err(anyhow!("ingest directory exceeds configured size limit"));
            }
            files.push(path);
            if files.len() > max_files {
                return Err(anyhow!(
                    "ingest directory exceeds configured file count limit"
                ));
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
    pub(super) overrides_active: bool,
    pub(super) mouse_capture: bool,
}

mod automation;
mod automation_graph;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
