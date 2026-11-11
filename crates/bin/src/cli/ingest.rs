use super::{
    AutomationContext, CaseId, Command, Engine, LargeCaseUseCases, Repository, Result,
    RootWorkspaceIo, anyhow, audit_source_name, input_files_large, parse_id, terminal_safe_path,
};
use irmind_app::{
    AuditLog, LargeCaseStore, ParserTimeContext, StreamingEventParser,
    modules::{ParserCatalog, ParserSelectionRequest, ResolvedParserSelection},
};
use irmind_tui::WorkspaceIo;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy)]
struct PlanExecution<'a> {
    id: &'a CaseId,
    source_root: &'a Path,
    plan: &'a [(String, ResolvedParserSelection)],
    copy_original: bool,
    engine: &'a Engine<'a>,
    store: &'a dyn LargeCaseStore,
    cancel: &'a irmind_app::CancellationToken,
    catalog: &'a ParserCatalog,
}

impl AutomationContext<'_, '_> {
    pub(super) fn handle_ingest(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            registry,
            workspace_io,
            cancel,
            ..
        } = self;
        match command {
            Command::Ingest {
                case_id,
                path,
                copy_original,
                parser,
                year,
                utc_offset,
                no_year_rollover,
            } => {
                let id = parse_id(&case_id)?;
                let time_context = irmind_app::command_time_context(
                    year.as_deref(),
                    utc_offset.as_deref(),
                    !no_year_rollover,
                )?;
                engine.verify_cancelable(&id, cancel)?;
                if store.get_case(&id)?.sealed {
                    return Err(anyhow!("case is sealed"));
                }
                let files = input_files_large(&path)?;
                let indexed = indexed_sources(store.as_ref(), &id)?;
                let source_root = if path.is_dir() {
                    path.as_path()
                } else {
                    path.parent()
                        .ok_or_else(|| anyhow!("source has no parent"))?
                };
                let catalog = workspace_io
                    .parser_catalog()
                    .cloned()
                    .unwrap_or_else(|| registry.parser_catalog());
                for file in &files {
                    let source = audit_source_name(&path, file)?;
                    if let Some(existing) = indexed.get(&source) {
                        store
                            .as_ref()
                            .verify_local_source(source_root, existing, cancel)?;
                        println!("skipped {}", terminal_safe_path(file));
                    }
                }
                let plan = plan_ingest(IngestPlanInput {
                    files: &files,
                    path: &path,
                    indexed: &indexed,
                    io: workspace_io,
                    catalog: &catalog,
                    engine,
                    id: &id,
                    parser: parser.as_deref(),
                    time_context,
                })?;
                perform_ingest_plan(PlanExecution {
                    id: &id,
                    source_root,
                    plan: &plan,
                    copy_original,
                    engine,
                    store: store.as_ref(),
                    cancel,
                    catalog: &catalog,
                })?;
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }
}

fn perform_ingest_plan(args: PlanExecution<'_>) -> Result<()> {
    let PlanExecution {
        id,
        source_root,
        plan,
        copy_original,
        engine,
        store,
        cancel,
        catalog,
    } = args;
    let start_seq = engine
        .audit_log
        .last_entry(id)?
        .map_or(0, |entry| entry.seq);
    let mut cursor = 0;
    while cursor < plan.len() {
        let first = &plan[cursor].1.selection;
        let parser_id = &first.parser_id;
        let end = plan[cursor..]
            .iter()
            .take_while(|(_, choice)| {
                choice.selection.parser_id == *parser_id
                    && choice.selection.parser_version == first.parser_version
                    && choice.selection.timestamp_context == first.timestamp_context
            })
            .count()
            + cursor;
        let parser = plan[cursor].1.parser.clone();
        let large = LargeCaseUseCases {
            engine,
            store,
            parser: parser.as_ref() as &dyn StreamingEventParser,
        };
        let sources = plan[cursor..end]
            .iter()
            .map(|(source, _)| source.clone())
            .collect::<Vec<_>>();
        let choices = plan[cursor..end]
            .iter()
            .map(|(source, choice)| (source.clone(), choice.selection.clone()))
            .collect::<BTreeMap<_, _>>();
        for (source, hash) in large
            .ingest_local_batch_selected(id, source_root, &sources, copy_original, &choices, cancel)
            .map_err(|error| engine.annotate_parser_time_error(id, error, catalog, cancel, false))?
        {
            println!(
                "{} {}",
                hash.as_str(),
                terminal_safe_path(&source_root.join(source))
            );
        }
        cursor = end;
    }
    report_rejected_sources(engine, id, start_seq)?;
    Ok(())
}

fn report_rejected_sources(engine: &Engine<'_>, id: &CaseId, start_seq: u64) -> Result<()> {
    let mut count = 0;
    for entry in engine
        .audit_log
        .entries(id)?
        .iter()
        .filter(|entry| entry.seq > start_seq)
    {
        if let Some(rejected) = irmind_app::RejectedSource::from_audit(entry)? {
            let safe = engine.guard.screen(rejected.source())?.text;
            eprintln!(
                "rejected {}: {}",
                terminal_safe_path(Path::new(&safe)),
                rejected.reason().description()
            );
            count += 1;
        }
    }
    if count > 0 {
        eprintln!("{count} sources rejected; their reasons are recorded in the signed audit log");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IngestPlanInput<'a> {
    files: &'a [PathBuf],
    path: &'a Path,
    indexed: &'a BTreeMap<String, irmind_domain::SourceManifestV1>,
    io: &'a RootWorkspaceIo,
    catalog: &'a ParserCatalog,
    engine: &'a Engine<'a>,
    id: &'a CaseId,
    parser: Option<&'a str>,
    time_context: Option<ParserTimeContext>,
}

fn plan_ingest(input: IngestPlanInput<'_>) -> Result<Vec<(String, ResolvedParserSelection)>> {
    let mut plan = Vec::new();
    for file in input.files {
        let source = audit_source_name(input.path, file)?;
        if input.indexed.contains_key(&source) {
            continue;
        }
        let sample = input.io.read_format_sample(file)?;
        let selected = input.catalog.select_source(ParserSelectionRequest {
            source: &source,
            sample: &sample,
            parser_override: input.parser,
            forced: input.parser.is_some(),
            time_context: input.time_context,
        });
        match selected {
            Ok(selection) => plan.push((source, selection)),
            Err(error @ irmind_app::AppError::ParserUnavailable { .. }) => {
                input
                    .engine
                    .record_parser_selection_required(input.id, "unsupported")?;
                return Err(error.into());
            }
            Err(error @ irmind_app::AppError::ParserTimeContextRequired { .. }) => {
                input
                    .engine
                    .record_parser_selection_required(input.id, "missing-time-context")?;
                return Err(error.into());
            }
            Err(error @ irmind_app::AppError::ParserSelection { .. }) => {
                let reason = if matches!(
                    input.catalog.detect(&source, &sample),
                    irmind_app::modules::ParserChoice::Unsupported
                ) {
                    "unsupported"
                } else {
                    "ambiguous"
                };
                input
                    .engine
                    .record_parser_selection_required(input.id, reason)?;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        }
    }
    plan.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(plan)
}

fn indexed_sources(
    store: &dyn AuditLog,
    id: &CaseId,
) -> Result<BTreeMap<String, irmind_domain::SourceManifestV1>> {
    store
        .entries(id)?
        .into_iter()
        .filter_map(|entry| {
            match irmind_domain::SourceManifestV1::decode_signed(entry.kind, &entry.payload) {
                Ok(Some(source)) => Some(Ok((source.source.clone(), source))),
                Ok(None) => None,
                Err(_) => Some(Err(anyhow!(
                    "invalid signed source manifest at entry {}",
                    entry.seq
                ))),
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser as _;
    #[test]
    fn automation_and_tui_commands_share_the_same_typed_negative_offset() {
        let cli = crate::cli::Cli::try_parse_from([
            "irmind",
            "ingest",
            "00000000-0000-0000-0000-000000000001",
            "synthetic.log",
            "--year",
            "2026",
            "--utc-offset",
            "-03:30",
            "--no-year-rollover",
        ])
        .unwrap();
        let args = match cli.command {
            Some(Command::Ingest {
                year,
                utc_offset,
                no_year_rollover,
                ..
            }) => Some((year, utc_offset, no_year_rollover)),
            _ => None,
        }
        .unwrap();
        let (year, utc_offset, no_year_rollover) = args;
        let parsed = irmind_app::command_time_context(
            year.as_deref(),
            utc_offset.as_deref(),
            !no_year_rollover,
        )
        .unwrap();
        let tui = irmind_app::IngestOptions::parse(
            "--year 2026 --utc-offset -03:30 --no-year-rollover synthetic.log",
        )
        .unwrap();
        assert_eq!(parsed, tui.time_context);
    }
}
