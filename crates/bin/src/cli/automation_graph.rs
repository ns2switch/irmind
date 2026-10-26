use super::{
    AutomationContext, Command, EvidenceGraph, EvidenceStore, Repository, Result, anyhow, parse_id,
    write_private_output,
};

impl AutomationContext<'_, '_> {
    pub(super) fn handle_custody(self, command: Command) -> Result<bool> {
        let Self {
            engine,
            store,
            guard,
            cancel,
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
            _ => return Err(anyhow!("invalid command dispatch")),
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
            ..
        } = self;
        match command {
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
            _ => return Err(anyhow!("invalid command dispatch")),
        }
        Ok(false)
    }
}
