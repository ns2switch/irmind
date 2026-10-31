use super::{
    AutomationContext, CaseId, Command, Engine, LargeCaseUseCases, Repository, Result,
    RootWorkspaceIo, anyhow, audit_source_name, input_files_large, parse_id, terminal_safe_path,
};
use irmind_app::{
    AuditLog, LargeCaseStore, ParserSelection, ParserSelectionMode, StreamingEventParser,
    modules::{ParserCatalog, ParserChoice},
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
    plan: &'a [(String, ParserSelection)],
    copy_original: bool,
    engine: &'a Engine<'a>,
    store: &'a dyn LargeCaseStore,
    catalog: &'a ParserCatalog,
    cancel: &'a irmind_app::CancellationToken,
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
            } => {
                let id = parse_id(&case_id)?;
                engine.verify_cancelable(&id, cancel)?;
                if store.get_case(&id)?.sealed {
                    return Err(anyhow!("case is sealed"));
                }
                let files = input_files_large(&path)?;
                let indexed: std::collections::BTreeMap<String, irmind_domain::SourceManifestV1> =
                    store
                        .entries(&id)?
                        .into_iter()
                        .filter_map(|entry| {
                            match irmind_domain::SourceManifestV1::decode_signed(
                                entry.kind,
                                &entry.payload,
                            ) {
                                Ok(Some(source)) => Some(Ok((source.source.clone(), source))),
                                Ok(None) => None,
                                Err(_) => Some(Err(anyhow!(
                                    "invalid signed source manifest at entry {}",
                                    entry.seq
                                ))),
                            }
                        })
                        .collect::<Result<_, _>>()?;
                let source_root = if path.is_dir() {
                    path.as_path()
                } else {
                    path.parent()
                        .ok_or_else(|| anyhow!("source has no parent"))?
                };
                let catalog = registry.parser_catalog();
                for file in &files {
                    let source = audit_source_name(&path, file)?;
                    if let Some(existing) = indexed.get(&source) {
                        store
                            .as_ref()
                            .verify_local_source(source_root, existing, cancel)?;
                        println!("skipped {}", terminal_safe_path(file));
                    }
                }
                let plan =
                    plan_ingest(&files, &path, &indexed, workspace_io, &catalog, engine, &id)?;
                perform_ingest_plan(PlanExecution {
                    id: &id,
                    source_root,
                    plan: &plan,
                    copy_original,
                    engine,
                    store: store.as_ref(),
                    catalog: &catalog,
                    cancel,
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
        catalog,
        cancel,
    } = args;
    let mut cursor = 0;
    let mut last_parser = None;
    while cursor < plan.len() {
        let parser_id = &plan[cursor].1.parser_id;
        let end = plan[cursor..]
            .iter()
            .take(4)
            .take_while(|(_, choice)| choice.parser_id == *parser_id)
            .count()
            + cursor;
        let parser = catalog.get(parser_id)?;
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
            .cloned()
            .collect::<BTreeMap<_, _>>();
        for (source, hash) in large.ingest_local_batch_selected(
            id,
            source_root,
            &sources,
            copy_original,
            &choices,
            cancel,
        )? {
            println!(
                "{} {}",
                hash.as_str(),
                terminal_safe_path(&source_root.join(source))
            );
        }
        last_parser = Some(parser);
        cursor = end;
    }
    if let Some(parser) = last_parser {
        let large = LargeCaseUseCases {
            engine,
            store,
            parser: parser.as_ref() as &dyn StreamingEventParser,
        };
        let bundles = large.compact_case(id, cancel)?;
        println!("created {bundles} signed Parquet bundles");
    }
    Ok(())
}

fn plan_ingest(
    files: &[PathBuf],
    path: &Path,
    indexed: &BTreeMap<String, irmind_domain::SourceManifestV1>,
    io: &RootWorkspaceIo,
    catalog: &ParserCatalog,
    engine: &Engine<'_>,
    id: &CaseId,
) -> Result<Vec<(String, ParserSelection)>> {
    let mut plan = Vec::new();
    for file in files {
        let source = audit_source_name(path, file)?;
        if indexed.contains_key(&source) {
            continue;
        }
        let sample = io.read_format_sample(file)?;
        match catalog.detect(&source, &sample) {
            ParserChoice::Auto(candidate) => {
                let parser = catalog.get(candidate.id)?;
                plan.push((
                    source,
                    ParserSelection {
                        parser_id: candidate.id.into(),
                        parser_version: parser.streaming_version().into(),
                        confidence: candidate.confidence.value(),
                        mode: ParserSelectionMode::Automatic,
                        timestamp_context: None,
                        format_sample_sha256: irmind_app::sha256(&sample),
                    },
                ));
            }
            ParserChoice::NeedsAnalyst(candidates) => {
                let reason = if candidates
                    .first()
                    .is_some_and(|first| first.confidence.is_high())
                {
                    "ambiguous"
                } else {
                    "low-confidence"
                };
                engine.record_parser_selection_required(id, reason)?;
                return Err(anyhow!("parser selection requires an analyst in the TUI"));
            }
            ParserChoice::Unsupported => {
                engine.record_parser_selection_required(id, "unsupported")?;
                return Err(anyhow!("no compiled parser recognizes this source"));
            }
        }
    }
    plan.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(plan)
}
