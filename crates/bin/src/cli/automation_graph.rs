use super::{
    AuditLog, AutomationContext, Command, EvidenceGraph, EvidenceStore, Repository, Result, anyhow,
    parse_id, write_private_output,
};
use irmind_app::{LargeCaseUseCases, SourceCheckMode};
use irmind_mod_parser_json::JsonParser;
use std::path::Path;

impl AutomationContext<'_, '_> {
    pub(super) fn handle_custody(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            guard,
            ..
        } = self;
        match command {
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
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    pub(super) fn handle_verify(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            cancel,
            ..
        } = self;
        let Command::Verify {
            case_id,
            source_root,
            sample,
        } = command
        else {
            return Err(anyhow!("invalid command dispatch"));
        };
        let id = parse_id(&case_id)?;
        let entries = engine.verify_cancelable(&id, cancel)?;
        let has_sources = store
            .entries(&id)?
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV1);
        if has_sources {
            let root = source_root.ok_or_else(|| {
                anyhow!("source root required to verify originals; use --source-root")
            })?;
            let parser = JsonParser;
            let large = LargeCaseUseCases {
                engine,
                store: store.as_ref(),
                parser: &parser,
            };
            let mode = sample.map_or(SourceCheckMode::Full, SourceCheckMode::Sample);
            let report = large.verify_sources(&id, &root, mode, cancel)?;
            println!(
                "verified {entries} audit entries; checked {} of {} original sources; {} unchanged; {} missing or changed",
                report.checked,
                report.total,
                report.checked - report.missing_or_changed.len(),
                report.missing_or_changed.len()
            );
            if !report.missing_or_changed.is_empty() {
                return Err(anyhow!(
                    "one or more original sources are missing or changed"
                ));
            }
        } else if source_root.is_some() || sample.is_some() {
            return Err(anyhow!("case has no source manifests to sample"));
        } else {
            println!("verified {entries} audit entries");
        }
        Ok(false)
    }

    pub(super) fn handle_graph_summary(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            guard,
            cancel,
            ..
        } = self;
        match command {
            Command::Graph { case_id } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let summary = store.graph_summary(&id)?;
                println!(
                    "{}",
                    irmind_app::ContentGuard::screen(guard.as_ref(), &summary)?.text
                );
            }
            Command::GraphRebuild { case_id } => {
                let id = parse_id(&case_id)?;
                let parser = JsonParser;
                let large = LargeCaseUseCases {
                    engine,
                    store: store.as_ref(),
                    parser: &parser,
                };
                let converted = large.migrate_legacy(&id, cancel)?;
                let bundles = if engine.repo.get_case(&id)?.sealed {
                    0
                } else {
                    large.compact_case(&id, cancel)?
                };
                println!(
                    "converted {converted} copied sources to signed Parquet; created {bundles} bundles"
                );
            }
            Command::VerifyGraph {
                case_id,
                source_root,
            } => {
                let id = parse_id(&case_id)?;
                let (has_sources, has_artifacts) = parquet_status(store.as_ref(), &id)?;
                if has_sources || has_artifacts {
                    let root = source_root.as_deref().or_else(|| {
                        (!has_sources).then_some(Path::new("."))
                    }).ok_or_else(|| anyhow!(
                        "source root required to rebuild and verify Parquet; use --source-root"
                    ))?;
                    let parser = JsonParser;
                    let large = LargeCaseUseCases {
                        engine,
                        store: store.as_ref(),
                        parser: &parser,
                    };
                    let count = large.verify_parquet_rebuild(&id, root, cancel)?;
                    println!("rebuilt and compared {count} Parquet sources");
                } else {
                    return Err(anyhow!(
                        "no signed Parquet artifacts; migrate copied evidence first"
                    ));
                }
            }
            Command::Timeline { case_id, filter } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                for event in store.timeline_filtered(&id, &filter.parse()?, 100)? {
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
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    pub(super) fn handle_graph_entities(self, command: Command) -> Result<bool> {
        let Self { store, guard, .. } = self;
        match command {
            Command::Entity {
                case_id,
                kind,
                value,
                filter,
            } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let result = store.entity_lookup_filtered(&id, &filter.parse()?, &kind, &value)?;
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
                filter,
            } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let result =
                    store.neighbors_filtered(&id, &filter.parse()?, &kind, &value, limit)?;
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
                filter,
            } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let result =
                    store.entity_timeline_filtered(&id, &filter.parse()?, &kind, &value, limit)?;
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
                filter,
            } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let result = store.graph_path_filtered(
                    &id,
                    &filter.parse()?,
                    (&from_kind, &from_value),
                    (&to_kind, &to_value),
                )?;
                println!(
                    "{}",
                    irmind_app::ContentGuard::screen(guard.as_ref(), &result)?.text
                );
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    pub(super) fn handle_graph_search(self, command: Command) -> Result<bool> {
        let Self { store, guard, .. } = self;
        match command {
            Command::TextSearch {
                case_id,
                query,
                limit,
                filter,
            } => {
                let id = parse_id(&case_id)?;
                let _case_lock = store.lock_case(&id)?;
                let result = store.text_search_filtered(&id, &filter.parse()?, &query, limit)?;
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
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }

    pub(super) fn handle_export_and_tui(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            selected_model,
            workspace_io,
            module_statuses,
            cancel,
            new_analyst_key,
            overrides_active,
            mouse_capture,
            ..
        } = self;
        match command {
            Command::Export {
                case_id,
                path,
                include_originals,
                source_root,
            } => {
                let id = parse_id(&case_id)?;
                let (has_sources, has_artifacts) = parquet_status(store.as_ref(), &id)?;
                let has_new_custody = has_sources || has_artifacts;
                let fingerprint = if include_originals || has_new_custody {
                    irmind_app::export_case_v4(
                        engine,
                        store.as_ref(),
                        &id,
                        &path,
                        source_root.as_deref(),
                        include_originals,
                        cancel,
                    )?
                } else {
                    if source_root.is_some() {
                        return Err(anyhow!("--source-root requires --include-originals"));
                    }
                    irmind_app::export_case(engine, store.as_ref(), &id, &path, cancel)?
                };
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
                    irmind_tui::WorkspaceLaunch {
                        initial_case: Some(&parse_id(&case_id)?),
                        resume_last_case: irmind_tui::ResumeMode::Disabled,
                        new_analyst_key,
                        overrides_active,
                        mouse_capture,
                        theme: None,
                    },
                )
                .map(|outcome| outcome == irmind_tui::WorkspaceOutcome::Restart);
            }
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }
}

fn parquet_status(
    store: &irmind_infra::LocalStore,
    id: &irmind_app::CaseId,
) -> Result<(bool, bool)> {
    let entries = store.entries(id)?;
    let has_sources = entries
        .iter()
        .any(|entry| entry.kind == irmind_domain::AuditEventKind::SourceManifestV1);
    let mut has_artifacts = entries
        .iter()
        .any(|entry| entry.kind == irmind_domain::AuditEventKind::ParquetArtifactV1);
    for operation in store.operations(id)? {
        has_artifacts |= irmind_domain::SealedParquetMigrationV1::decode(&operation.operation)
            .map_err(|_| anyhow!("invalid sealed Parquet operation"))?
            .is_some();
    }
    Ok((has_sources, has_artifacts))
}
